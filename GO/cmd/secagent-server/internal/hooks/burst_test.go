package hooks

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"secagent-server/cmd/secagent-server/internal/actionlog"
)

func captureHookLogs(t *testing.T) func() string {
	t.Helper()
	var mu sync.Mutex
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(writerFunc(func(p []byte) (int, error) { mu.Lock(); defer mu.Unlock(); return buf.Write(p) }))
	t.Cleanup(func() { log.SetOutput(prev) })
	return func() string { mu.Lock(); defer mu.Unlock(); return buf.String() }
}

func TestBurst_BeyondTheQueueDropsAreCountedAndReportedOnce(t *testing.T) {
	t.Setenv("RELAY_HOOKS_MAX_CONCURRENT_ACTIONS", "4")
	logs := captureHookLogs(t)
	var executed atomic.Int32
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-release; executed.Add(1) }))
	defer srv.Close()
	logger := &mockLogger{}
	d := NewDispatcher(logger, 8) // 2 slots per worker, 4 workers
	d.SetConfig(&HooksConfig{Hooks: []HookDef{{Event: "host.up", Actions: []ActionDef{{Type: "webhook", URL: srv.URL, TimeoutSeconds: 30}}}}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d.Start(ctx)

	const sent = 200
	for i := 0; i < sent; i++ {
		d.Dispatch("host.up", fmt.Sprintf("h%03d", i), "connected", "")
	}
	dropped := d.DroppedEvents()
	if dropped == 0 || dropped >= sent {
		t.Fatalf("dropped = %d of %d: the queue must reject some and accept some", dropped, sent)
	}
	st := d.Stats()
	if st.Workers != 4 || st.QueueCapacity != 8 || st.DroppedEvents != dropped {
		t.Errorf("stats: %+v", st)
	}
	d.reportDrops()
	d.reportDrops() // nothing new: no second report
	close(release)
	logger.waitEntries(t, int(sent-dropped)+1, 15*time.Second)

	if n := strings.Count(logs(), "[WARN] hooks: "); n != 1 {
		t.Errorf("%d aggregated warnings, want exactly 1:\n%s", n, logs())
	}
	if strings.Count(logs(), "queue full") > 1 {
		t.Errorf("no line per dropped event:\n%s", logs())
	}
	var drops []actionlog.Entry
	for _, e := range logger.waitEntries(t, 1, time.Second) {
		if e.ActionType == "dropped" {
			drops = append(drops, e)
		}
	}
	if len(drops) != 1 || !strings.Contains(drops[0].Error, fmt.Sprintf("%d event(s)", dropped)) {
		t.Errorf("one journal entry expected, got %+v (dropped=%d)", drops, dropped)
	}
	if got := int64(executed.Load()); got != sent-dropped {
		t.Errorf("executed %d, want accepted %d", got, sent-dropped)
	}
}

// The order of the events of ONE host is preserved under load; hosts are not ordered between them.
func TestBurst_OrderIsPreservedPerHostname(t *testing.T) {
	t.Setenv("RELAY_HOOKS_MAX_CONCURRENT_ACTIONS", "4")
	out := filepath.Join(t.TempDir(), "order.out")
	logger := &mockLogger{}
	d := NewDispatcher(logger, 5000)
	d.SetConfig(&HooksConfig{Hooks: []HookDef{
		{Event: "host.up", Actions: []ActionDef{{Type: "file", Path: out, Append: "{{event}} {{hostname}}\n"}}},
		{Event: "host.down", Actions: []ActionDef{{Type: "file", Path: out, Append: "{{event}} {{hostname}}\n"}}},
	}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d.Start(ctx)
	const hosts = 300
	for i := 0; i < hosts; i++ {
		h := fmt.Sprintf("h%03d", i)
		d.Dispatch("host.up", h, "connected", "")
		d.Dispatch("host.down", h, "disconnected", "")
	}
	logger.waitEntries(t, 2*hosts, 30*time.Second)
	b, _ := os.ReadFile(out)
	seenUp := map[string]bool{}
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		f := strings.Fields(l)
		switch f[0] {
		case "host.up":
			seenUp[f[1]] = true
		case "host.down":
			if !seenUp[f[1]] {
				t.Fatalf("host.down of %s ran BEFORE its host.up", f[1])
			}
		}
	}
	if d.DroppedEvents() != 0 {
		t.Errorf("dropped %d", d.DroppedEvents())
	}
}

// A slow webhook blocks its own worker only: other hosts keep progressing, a host of the SAME
// worker waits.
func TestBurst_ASlowWebhookBlocksOnlyItsWorker(t *testing.T) {
	t.Setenv("RELAY_HOOKS_MAX_CONCURRENT_ACTIONS", "4")
	release := make(chan struct{})
	var slowHits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { slowHits.Add(1); <-release }))
	defer srv.Close()
	dir := t.TempDir()
	fast := filepath.Join(dir, "fast.out")
	d := NewDispatcher(&mockLogger{}, 100)
	d.SetConfig(&HooksConfig{Hooks: []HookDef{
		{Event: "host.down", Actions: []ActionDef{{Type: "webhook", URL: srv.URL, TimeoutSeconds: 30}}},
		{Event: "host.up", Actions: []ActionDef{{Type: "file", Path: fast, Append: "{{hostname}}\n"}}},
	}})
	slowHost := "slow-host"
	var same, other string
	for i := 0; same == "" || other == ""; i++ {
		h := fmt.Sprintf("probe-%d", i)
		if d.workerFor(h) == d.workerFor(slowHost) {
			if same == "" {
				same = h
			}
		} else if other == "" {
			other = h
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d.Start(ctx)
	d.Dispatch("host.down", slowHost, "disconnected", "")
	deadline := time.Now().Add(5 * time.Second)
	for slowHits.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	d.Dispatch("host.up", same, "connected", "")
	d.Dispatch("host.up", other, "connected", "")
	deadline = time.Now().Add(5 * time.Second)
	for !fileHas(fast, other) && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if !fileHas(fast, other) {
		t.Fatal("a host on another worker must progress while a webhook is slow")
	}
	time.Sleep(100 * time.Millisecond)
	if fileHas(fast, same) {
		t.Error("a host of the SAME worker waits behind the slow action (order per worker)")
	}
	close(release)
	deadline = time.Now().Add(5 * time.Second)
	for !fileHas(fast, same) && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if !fileHas(fast, same) {
		t.Error("the waiting host must run once the worker is free")
	}
}

func fileHas(path, s string) bool {
	b, _ := os.ReadFile(path)
	return strings.Contains(string(b), s+"\n")
}

// Clean stop: Drain flushes what was accepted (bounded delay), refuses new events and counts them.
func TestDrain_FlushesTheQueueThenRefusesEvents(t *testing.T) {
	t.Setenv("RELAY_HOOKS_MAX_CONCURRENT_ACTIONS", "2")
	logger := &mockLogger{}
	out := filepath.Join(t.TempDir(), "drain.out")
	d := NewDispatcher(logger, 100)
	d.SetConfig(fileHookConfig("host.up", out, "{{hostname}}\n"))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d.Start(ctx)
	for i := 0; i < 50; i++ {
		d.Dispatch("host.up", fmt.Sprintf("h%d", i), "connected", "")
	}
	if left := d.Drain(10 * time.Second); left != 0 {
		t.Fatalf("%d event(s) left after Drain", left)
	}
	if logger.entryCount() != 50 {
		t.Errorf("%d journaled, want 50", logger.entryCount())
	}
	d.Dispatch("host.up", "late", "connected", "")
	if d.DroppedEvents() != 1 {
		t.Errorf("an event after Drain must be refused and counted, dropped=%d", d.DroppedEvents())
	}
}

// Abrupt stop (context cancelled, e.g. the lock was lost): the queued events are lost but COUNTED
// and logged, with their actions.
func TestAbruptStop_CountsAndLogsTheLostEvents(t *testing.T) {
	t.Setenv("RELAY_HOOKS_MAX_CONCURRENT_ACTIONS", "1")
	logs := captureHookLogs(t)
	release := make(chan struct{})
	var hit atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit.Add(1); <-release }))
	defer srv.Close()
	defer close(release)
	d := NewDispatcher(&mockLogger{}, 20)
	d.SetConfig(&HooksConfig{Hooks: []HookDef{{Event: "host.up", Actions: []ActionDef{
		{Type: "webhook", URL: srv.URL, TimeoutSeconds: 30}, {Type: "webhook", URL: srv.URL, TimeoutSeconds: 30}}}}})
	ctx, cancel := context.WithCancel(context.Background())
	d.Start(ctx)
	for i := 0; i < 6; i++ {
		d.Dispatch("host.up", "same-host", "connected", "") // same worker: 1 running, 5 queued
	}
	deadline := time.Now().Add(5 * time.Second)
	for hit.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	deadline = time.Now().Add(5 * time.Second)
	for !strings.Contains(logs(), "queued event(s) not processed") && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !strings.Contains(logs(), "5 queued event(s) not processed (10 action(s))") {
		t.Errorf("the exit log must count the lost events:\n%s", logs())
	}
	if d.DroppedEvents() != 5 {
		t.Errorf("dropped events = %d, want 5", d.DroppedEvents())
	}
}

func TestQueueSizeFromEnv(t *testing.T) {
	t.Setenv("RELAY_HOOKS_QUEUE_SIZE", "")
	if QueueSizeFromEnv() != DefaultQueueSize || DefaultQueueSize < 10000 {
		t.Errorf("default must be >= 10000, got %d", QueueSizeFromEnv())
	}
	for _, bad := range []string{"0", "-1", "x"} {
		t.Setenv("RELAY_HOOKS_QUEUE_SIZE", bad)
		if QueueSizeFromEnv() != DefaultQueueSize {
			t.Errorf("%q must fall back", bad)
		}
	}
	t.Setenv("RELAY_HOOKS_QUEUE_SIZE", "25000")
	if QueueSizeFromEnv() != 25000 {
		t.Error("override expected")
	}
}
