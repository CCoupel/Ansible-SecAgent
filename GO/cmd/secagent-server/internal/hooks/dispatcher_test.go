// SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
// SPDX-License-Identifier: AGPL-3.0-or-later

package hooks

// Tests du Dispatcher hooks — routage d'événements vers les actions configurées.
//
// Référence : DOC/server/HOOKS_SPEC.md §1, §2, §10
// Brief     : _work/handoff/teamlead-to-test-writer-20260522-154000.md
//
// API réelle implémentée dans dispatcher.go :
//
//   ActionLogger interface {
//     CreateActionLog(ctx context.Context, entry actionlog.Entry) error
//   }
//
//   NewDispatcher(store ActionLogger, bufSize int) *Dispatcher
//   (d *Dispatcher) SetConfig(cfg *HooksConfig)
//   (d *Dispatcher) Dispatch(event, hostname, status, enrolledAt string)
//   (d *Dispatcher) Start(ctx context.Context)
//
// Les tests utilisent mockLogger (spec du brief) et des actions "file"
// (observables via le filesystem) pour vérifier le routage sans réseau.

import (
	"context"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"secagent-server/cmd/secagent-server/internal/actionlog"
)

// ========================================================================
// mockLogger — implémente ActionLogger (spec brief)
// ========================================================================

type mockLogger struct {
	mu      sync.Mutex
	entries []actionlog.Entry
}

func (m *mockLogger) Append(e actionlog.Entry) error {
	m.mu.Lock()
	m.entries = append(m.entries, e)
	m.mu.Unlock()
	return nil
}

// waitEntries attend que n entrées soient disponibles (timeout fatal).
func (m *mockLogger) waitEntries(t *testing.T, n int, timeout time.Duration) []actionlog.Entry {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		m.mu.Lock()
		count := len(m.entries)
		m.mu.Unlock()
		if count >= n {
			m.mu.Lock()
			result := make([]actionlog.Entry, len(m.entries))
			copy(result, m.entries)
			m.mu.Unlock()
			return result
		}
		if time.Now().After(deadline) {
			t.Fatalf("timeout: waited %s for %d log(s), got %d", timeout, n, count)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (m *mockLogger) entryCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.entries)
}

// ========================================================================
// helpers
// ========================================================================

// waitFile attend que le fichier path existe (timeout fatal).
func waitFile(t *testing.T, path string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		if _, err := os.Stat(path); err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timeout: file %s not created within %s", path, timeout)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// fileHookConfig retourne un HooksConfig minimal : event → action file(path, content).
func fileHookConfig(event, path, content string) *HooksConfig {
	return &HooksConfig{
		Hooks: []HookDef{
			{
				Event: event,
				Actions: []ActionDef{
					{Type: "file", Path: path, Append: content},
				},
			},
		},
	}
}

// ========================================================================
// TestDispatcher_routes_to_correct_hook
// host.new → seules les actions host.new exécutées (pas host.up)
// ========================================================================

func TestDispatcher_routes_to_correct_hook(t *testing.T) {
	dir := t.TempDir()
	fileNew := filepath.Join(dir, "host.new.log")
	fileUp := filepath.Join(dir, "host.up.log")

	cfg := &HooksConfig{
		Hooks: []HookDef{
			{Event: "host.new", Actions: []ActionDef{{Type: "file", Path: fileNew, Append: "new\n"}}},
			{Event: "host.up", Actions: []ActionDef{{Type: "file", Path: fileUp, Append: "up\n"}}},
		},
	}

	logger := &mockLogger{}
	d := NewDispatcher(logger, 10)
	d.SetConfig(cfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d.Start(ctx)

	// Dispatch uniquement host.new
	d.Dispatch("host.new", "my-server", "disconnected", "2026-05-22T14:30:00Z")

	// fileNew doit être créé
	waitFile(t, fileNew, 3*time.Second)

	// fileUp ne doit PAS exister (host.up non dispatché)
	time.Sleep(200 * time.Millisecond)
	if _, err := os.Stat(fileUp); err == nil {
		t.Error("host.up file should not exist — wrong hook triggered")
	}
}

// ========================================================================
// TestDispatcher_no_config
// SetConfig(nil) → Dispatch ne panique pas, aucune action exécutée
// ========================================================================

func TestDispatcher_no_config(t *testing.T) {
	logger := &mockLogger{}
	d := NewDispatcher(logger, 10)
	d.SetConfig(nil) // config nil explicite

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d.Start(ctx)

	// Dispatch sans paniquer
	d.Dispatch("host.new", "h1", "disconnected", "")

	// Attendre un peu — aucun log ne doit apparaître
	time.Sleep(300 * time.Millisecond)
	if logger.entryCount() != 0 {
		t.Errorf("expected 0 log entries with nil config, got %d", logger.entryCount())
	}
}

// ========================================================================
// TestDispatcher_set_config_hot_reload
// SetConfig avec nouvelle config → nouveau comportement immédiatement
// ========================================================================

func TestDispatcher_set_config_hot_reload(t *testing.T) {
	dir := t.TempDir()
	logFile := filepath.Join(dir, "events.log")

	logger := &mockLogger{}
	d := NewDispatcher(logger, 10)
	// Démarrer sans config

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d.Start(ctx)

	// Premier dispatch sans config → pas d'action
	d.Dispatch("host.new", "h1", "disconnected", "")
	time.Sleep(150 * time.Millisecond)
	if logger.entryCount() != 0 {
		t.Errorf("expected 0 logs before SetConfig, got %d", logger.entryCount())
	}

	// Hot-reload : injecter la config
	d.SetConfig(fileHookConfig("host.new", logFile, "triggered\n"))

	// Deuxième dispatch → action déclenchée
	d.Dispatch("host.new", "h1", "disconnected", "")

	waitFile(t, logFile, 3*time.Second)
	logger.waitEntries(t, 1, 3*time.Second)
}

// ========================================================================
// TestDispatcher_queue_full_drop
// bufSize=0 → Dispatch() retourne immédiatement sans bloquer
// ========================================================================

func TestDispatcher_queue_full_drop(t *testing.T) {
	logger := &mockLogger{}
	d := NewDispatcher(logger, 0) // queue de taille 0 = unbuffered

	dir := t.TempDir()
	logFile := filepath.Join(dir, "events.log")
	d.SetConfig(fileHookConfig("host.new", logFile, "triggered\n"))

	// Ne pas appeler Start() — aucun consommateur, drop immédiat garanti

	done := make(chan struct{})
	go func() {
		d.Dispatch("host.new", "h1", "disconnected", "")
		close(done)
	}()

	select {
	case <-done:
		// OK — Dispatch n'a pas bloqué
	case <-time.After(2 * time.Second):
		t.Fatal("Dispatch blocked on full queue (should have dropped immediately)")
	}

	// Aucune action ne doit avoir été exécutée
	time.Sleep(100 * time.Millisecond)
	if logger.entryCount() != 0 {
		t.Errorf("expected 0 log entries (event dropped), got %d", logger.entryCount())
	}
}

// ========================================================================
// TestDispatcher_writes_action_log
// Après exécution → journal.Append appelé avec les bons champs
// ========================================================================

func TestDispatcher_writes_action_log(t *testing.T) {
	dir := t.TempDir()
	logFile := filepath.Join(dir, "events.log")

	logger := &mockLogger{}
	d := NewDispatcher(logger, 10)
	d.SetConfig(fileHookConfig("host.new", logFile, "triggered\n"))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d.Start(ctx)

	d.Dispatch("host.new", "test-host", "disconnected", "2026-05-22T14:30:00Z")

	entries := logger.waitEntries(t, 1, 3*time.Second)
	e := entries[0]

	if e.Event != "host.new" {
		t.Errorf("ActionLogEntry.Event: got %q, want host.new", e.Event)
	}
	if e.Hostname != "test-host" {
		t.Errorf("ActionLogEntry.Hostname: got %q, want test-host", e.Hostname)
	}
	if e.ActionType != "file" {
		t.Errorf("ActionLogEntry.ActionType: got %q, want file", e.ActionType)
	}
	if e.ActionIndex != 0 {
		t.Errorf("ActionLogEntry.ActionIndex: got %d, want 0", e.ActionIndex)
	}
	if !e.Success {
		t.Errorf("ActionLogEntry.Success: got false, error: %q", e.Error)
	}
	if e.ConfigSnapshot == "" {
		t.Error("ActionLogEntry.ConfigSnapshot must not be empty")
	}
	if e.ID == "" {
		t.Error("ActionLogEntry.ID must not be empty (should be a UUID)")
	}
}

// ========================================================================
// TestDispatcher_multiple_actions
// 3 actions dans un hook → les 3 exécutées, 3 entrées dans le log
// ========================================================================

func TestDispatcher_multiple_actions(t *testing.T) {
	dir := t.TempDir()
	fileA := filepath.Join(dir, "a.log")
	fileB := filepath.Join(dir, "b.log")
	fileC := filepath.Join(dir, "c.log")

	cfg := &HooksConfig{
		Hooks: []HookDef{
			{
				Event: "host.up",
				Actions: []ActionDef{
					{Type: "file", Path: fileA, Append: "A\n"},
					{Type: "file", Path: fileB, Append: "B\n"},
					{Type: "file", Path: fileC, Append: "C\n"},
				},
			},
		},
	}

	logger := &mockLogger{}
	d := NewDispatcher(logger, 10)
	d.SetConfig(cfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d.Start(ctx)

	d.Dispatch("host.up", "h1", "connected", "")

	// 3 actions → 3 entrées dans le log
	entries := logger.waitEntries(t, 3, 5*time.Second)
	if len(entries) < 3 {
		t.Fatalf("expected at least 3 log entries, got %d", len(entries))
	}

	// Les 3 fichiers doivent exister
	for _, f := range []string{fileA, fileB, fileC} {
		if _, err := os.Stat(f); os.IsNotExist(err) {
			t.Errorf("expected file %s to exist after dispatch", f)
		}
	}

	// Les ActionIndex 0, 1, 2 doivent tous être présents
	// (l'ordre peut varier car les goroutines sont indépendantes)
	indexes := make(map[int]bool)
	for _, e := range entries {
		indexes[e.ActionIndex] = true
	}
	for _, want := range []int{0, 1, 2} {
		if !indexes[want] {
			t.Errorf("missing ActionIndex %d in log entries", want)
		}
	}
}

// #263: Wait returns only once the drop reporter has logged its last line, so nothing writes to the
// log after a stop (Node.Close relies on it). A write after Wait returned, or a missing
// "Dispatcher stopped" line at that point, fails the test.
func TestDispatcher_WaitReturnsAfterTheReporterLoggedItsLastLine(t *testing.T) {
	var mu sync.Mutex
	var lines []string
	waited := false
	late := false
	prev := log.Writer()
	log.SetOutput(writerFunc(func(p []byte) (int, error) {
		mu.Lock()
		defer mu.Unlock()
		if waited {
			late = true
		}
		lines = append(lines, string(p))
		return len(p), nil
	}))
	defer log.SetOutput(prev)

	for i := 0; i < 50; i++ {
		d := NewDispatcher(nil, 10)
		ctx, cancel := context.WithCancel(context.Background())
		d.Start(ctx)
		cancel()
		d.Wait()
		mu.Lock()
		waited = true
		got := strings.Contains(strings.Join(lines, ""), "[HOOKS] Dispatcher stopped")
		mu.Unlock()
		if !got {
			t.Fatalf("run %d: Wait returned before the reporter logged \"Dispatcher stopped\"", i)
		}
		mu.Lock()
		waited, lines = false, nil
		mu.Unlock()
	}
	mu.Lock()
	defer mu.Unlock()
	if late {
		t.Error("a log line was written after Wait returned")
	}
}

// A dispatcher that was never started has nothing to wait for.
func TestDispatcher_WaitOnANeverStartedDispatcherReturns(t *testing.T) {
	NewDispatcher(nil, 10).Wait()
}

// v3.0.6: a relay.* event is keyed by its relay_id (FIFO per relay), its variables carry the
// detail, and the webhook body has a relay object and no host object.
func TestRelayEvent_VarsKeyAndWebhookBody(t *testing.T) {
	job := dispatchJob{event: "relay.up", relayID: "zone-a", relayChain: []string{"zone-a"}, timestamp: "ts",
		detail: Detail{Mode: "pull", ConnSeq: 3, HostsRouted: 0, RelaysBelow: 2, RelaysBelowIDs: []string{"b", "c"}}}
	if job.key() != "zone-a" {
		t.Errorf("key = %q, want the relay_id", job.key())
	}
	v := job.vars()
	for k, want := range map[string]string{"event": "relay.up", "relay_id": "zone-a", "mode": "pull", "conn_seq": "3",
		"hosts_routed": "0", "relays_below": "2", "relays_below_ids": "b,c", "hostname": ""} {
		if v[k] != want {
			t.Errorf("vars[%q] = %q, want %q", k, v[k], want)
		}
	}
	env := strings.Join(shellEnvironment(nil, nil, v), "\n")
	for _, want := range []string{"SECAGENT_RELAY_ID=zone-a", "SECAGENT_CONN_SEQ=3", "SECAGENT_HOSTS_ROUTED=0", "SECAGENT_MODE=pull"} {
		if !strings.Contains(env, want) {
			t.Errorf("shell environment lacks %s:\n%s", want, env)
		}
	}
	o := relayObjOf(v)
	if o == nil || o.RelayID != "zone-a" || o.ConnSeq == nil || *o.ConnSeq != 3 || o.HostsRouted == nil || *o.HostsRouted != 0 {
		t.Errorf("relay object = %+v", o)
	}
	hostJob := dispatchJob{event: "host.up", hostname: "h", status: "connected", detail: Detail{ConnSeq: 2}}
	if hostJob.key() != "h" || relayObjOf(hostJob.vars()) != nil {
		t.Error("a host event is keyed by hostname and has no relay object")
	}
}

func TestPropagatedCoversTheNewKinds(t *testing.T) {
	for _, k := range []string{"relay.failover", "relay.up", "relay.reconnect", "relay.down", "relay.discover", "relay.rerouted",
		"relay.removed", "relay.converged", "host.reconnect", "host.discover", "host.rerouted", "host.removed", "host.up"} {
		if !Propagated(k) {
			t.Errorf("%s must be propagated", k)
		}
	}
	for _, k := range []string{"relay.updated", "host.deleted", "host.revoked", "host.conflict"} {
		if Propagated(k) {
			t.Errorf("%s must not be propagated by the dispatcher", k)
		}
	}
}

func TestConfigWarnsWhenSeveralHooksListenToTheSameEvent(t *testing.T) {
	var mu sync.Mutex
	var out strings.Builder
	prev := log.Writer()
	log.SetOutput(writerFunc(func(p []byte) (int, error) { mu.Lock(); defer mu.Unlock(); return out.Write(p) }))
	defer log.SetOutput(prev)

	cfg := &HooksConfig{Hooks: []HookDef{{Event: "host.up"}, {Event: "host.down"}, {Event: "host.up"}, {Event: "host.up"}}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	got := out.String()
	mu.Unlock()
	if n := strings.Count(got, `3 hooks listen to event "host.up": only the first matching one runs`); n != 1 {
		t.Errorf("want one warning for host.up, got %d:\n%s", n, got)
	}
	if strings.Contains(got, `"host.down"`) {
		t.Errorf("host.down has a single hook, no warning expected:\n%s", got)
	}
}
