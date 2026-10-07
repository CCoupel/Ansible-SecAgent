package hooks

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// Slow webhooks cannot pile goroutines up: at most RELAY_HOOKS_MAX_CONCURRENT_ACTIONS events are
// processed at once, the others WAIT in the queue (back-pressure, #183): none is dropped.
func TestDispatcher_ConcurrentActionsAreBoundedAndNothingIsDropped(t *testing.T) {
	t.Setenv("RELAY_HOOKS_MAX_CONCURRENT_ACTIONS", "3")
	var running, peak, done atomic.Int32
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
		done.Add(1)
	}))
	defer srv.Close()

	d := NewDispatcher(&mockLogger{}, 100)
	d.SetConfig(&HooksConfig{Hooks: []HookDef{{Event: "host.up",
		Actions: []ActionDef{{Type: "webhook", URL: srv.URL, TimeoutSeconds: 30}}}}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d.Start(ctx)

	start := time.Now()
	for i := 0; i < 20; i++ {
		d.Dispatch("host.up", fmt.Sprintf("h%d", i), "connected", "")
	}
	if time.Since(start) > time.Second {
		t.Error("Dispatch must never block")
	}
	time.Sleep(200 * time.Millisecond)
	if got := peak.Load(); got > 3 {
		t.Errorf("peak concurrent events = %d, want <= 3", got)
	}
	close(release)
	deadline := time.Now().Add(10 * time.Second)
	for done.Load() < 20 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if done.Load() != 20 || d.DroppedEvents() != 0 || d.DroppedActions() != 0 {
		t.Errorf("executed=%d droppedEvents=%d droppedActions=%d, want 20/0/0", done.Load(), d.DroppedEvents(), d.DroppedActions())
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
