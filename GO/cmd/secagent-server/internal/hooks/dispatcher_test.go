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
	"os"
	"path/filepath"
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
