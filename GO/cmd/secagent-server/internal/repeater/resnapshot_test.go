package repeater

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// serveUplink runs an Uplink on the server side of a websocket and returns the peer end, which
// records the arrival time of every topology_snapshot.
func serveUplink(t *testing.T, opts Options) (snaps chan time.Time) {
	t.Helper()
	up := NewUplink("child", opts)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			return
		}
		_ = up.Serve(context.Background(), c)
	}))
	t.Cleanup(srv.Close)
	c, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	snaps = make(chan time.Time, 64)
	go func() {
		for {
			var m map[string]any
			if err := c.ReadJSON(&m); err != nil {
				return
			}
			if m["type"] == "topology_snapshot" {
				snaps <- time.Now()
			}
		}
	}()
	return snaps
}

func nextSnap(t *testing.T, snaps chan time.Time, within time.Duration) (time.Time, bool) {
	t.Helper()
	select {
	case at := <-snaps:
		return at, true
	case <-time.After(within):
		return time.Time{}, false
	}
}

// A topology change makes the uplink send ANOTHER full snapshot; a burst of changes is coalesced
// into one, and two snapshots are never closer than TopologyMinGap (the parent rate limits them).
func TestUplink_TopologyChangeResendsOneCoalescedSnapshot(t *testing.T) {
	changed := make(chan struct{}, 1)
	var calls atomic.Int32
	snaps := serveUplink(t, Options{
		TopologyChanged:  changed,
		TopologyDebounce: 30 * time.Millisecond,
		TopologyMinGap:   400 * time.Millisecond,
		Snapshot:         func() Snapshot { calls.Add(1); return Snapshot{} },
	})
	first, ok := nextSnap(t, snaps, 3*time.Second)
	if !ok {
		t.Fatal("no initial snapshot")
	}
	// a burst of 20 signals right after the first snapshot
	for i := 0; i < 20; i++ {
		select {
		case changed <- struct{}{}:
		default:
		}
		time.Sleep(2 * time.Millisecond)
	}
	second, ok := nextSnap(t, snaps, 3*time.Second)
	if !ok {
		t.Fatal("a topology change must produce a new snapshot")
	}
	if gap := second.Sub(first); gap < 350*time.Millisecond {
		t.Errorf("two snapshots %v apart, want >= the min gap", gap)
	}
	if _, extra := nextSnap(t, snaps, 800*time.Millisecond); extra {
		t.Error("a burst of changes must be coalesced into ONE snapshot")
	}
	if calls.Load() != 2 {
		t.Errorf("Snapshot() called %d times, want 2", calls.Load())
	}
}

// Without any change, no new snapshot is sent.
func TestUplink_NoTopologyChangeNoResnapshot(t *testing.T) {
	snaps := serveUplink(t, Options{TopologyDebounce: 10 * time.Millisecond, TopologyMinGap: 20 * time.Millisecond})
	if _, ok := nextSnap(t, snaps, 3*time.Second); !ok {
		t.Fatal("no initial snapshot")
	}
	if _, extra := nextSnap(t, snaps, 500*time.Millisecond); extra {
		t.Error("unexpected snapshot without topology change")
	}
}
