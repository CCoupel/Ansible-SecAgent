package hooks

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// Slow webhooks cannot pile goroutines up: at most RELAY_HOOKS_MAX_CONCURRENT_ACTIONS actions run
// at once, the others are dropped (counted) without blocking the dispatch.
func TestDispatcher_ConcurrentActionsAreBounded(t *testing.T) {
	t.Setenv("RELAY_HOOKS_MAX_CONCURRENT_ACTIONS", "3")
	var running, peak atomic.Int32
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := running.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		<-release
		running.Add(-1)
	}))
	defer srv.Close()
	defer close(release)

	d := NewDispatcher(&mockLogger{}, 100)
	d.SetConfig(&HooksConfig{Hooks: []HookDef{{Event: "host.up",
		Actions: []ActionDef{{Type: "webhook", URL: srv.URL, TimeoutSeconds: 30}}}}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d.Start(ctx)

	start := time.Now()
	for i := 0; i < 20; i++ {
		d.Dispatch("host.up", "h", "connected", "")
	}
	if time.Since(start) > time.Second {
		t.Error("Dispatch must never block")
	}
	deadline := time.Now().Add(5 * time.Second)
	for d.DroppedActions() < 17 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	time.Sleep(200 * time.Millisecond)
	if got := d.DroppedActions(); got != 17 {
		t.Errorf("dropped = %d, want 17 (20 jobs, 3 slots)", got)
	}
	if got := peak.Load(); got > 3 {
		t.Errorf("peak concurrent actions = %d, want <= 3", got)
	}
}

// Finished actions free their slot.
func TestDispatcher_SlotsAreReleased(t *testing.T) {
	t.Setenv("RELAY_HOOKS_MAX_CONCURRENT_ACTIONS", "1")
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer srv.Close()
	d := NewDispatcher(&mockLogger{}, 100)
	d.SetConfig(&HooksConfig{Hooks: []HookDef{{Event: "host.up",
		Actions: []ActionDef{{Type: "webhook", URL: srv.URL}}}}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d.Start(ctx)
	for i := 0; i < 5; i++ {
		d.Dispatch("host.up", "h", "connected", "")
		deadline := time.Now().Add(3 * time.Second)
		for hits.Load() < int32(i+1) && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
		time.Sleep(50 * time.Millisecond) // let the slot be released
	}
	if hits.Load() != 5 || d.DroppedActions() != 0 {
		t.Errorf("hits=%d dropped=%d, want 5 and 0: a finished action must free its slot", hits.Load(), d.DroppedActions())
	}
}

func TestMaxConcurrentActions_EnvAndDefault(t *testing.T) {
	t.Setenv("RELAY_HOOKS_MAX_CONCURRENT_ACTIONS", "")
	if maxConcurrentActions() != DefaultMaxConcurrentActions {
		t.Error("default expected")
	}
	for _, bad := range []string{"0", "-4", "abc"} {
		t.Setenv("RELAY_HOOKS_MAX_CONCURRENT_ACTIONS", bad)
		if maxConcurrentActions() != DefaultMaxConcurrentActions {
			t.Errorf("%q must fall back to the default", bad)
		}
	}
	t.Setenv("RELAY_HOOKS_MAX_CONCURRENT_ACTIONS", "7")
	if maxConcurrentActions() != 7 {
		t.Error("env override expected")
	}
}
