// SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
// SPDX-License-Identifier: AGPL-3.0-or-later

package repeater

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// servedFrames runs an Uplink and records the order of the frames its peer receives ("snapshot[ids]" / "event:<host>").
func servedFrames(t *testing.T, opts Options) (frames func() []string) {
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
	var mu sync.Mutex
	var got []string
	go func() {
		for {
			var m struct {
				Type     string `json:"type"`
				Hostname string `json:"hostname"`
				Relays   []struct {
					RelayID string `json:"relay_id"`
				} `json:"relays"`
			}
			if err := c.ReadJSON(&m); err != nil {
				return
			}
			mu.Lock()
			switch m.Type {
			case "topology_snapshot":
				ids := ""
				for _, r := range m.Relays {
					ids += r.RelayID + ","
				}
				got = append(got, "snapshot["+ids+"]")
			case "event_forward":
				got = append(got, "event:"+m.Hostname)
			}
			mu.Unlock()
		}
	}()
	return func() []string { mu.Lock(); defer mu.Unlock(); return append([]string(nil), got...) }
}

func waitFrames(t *testing.T, frames func() []string, n int) []string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if g := frames(); len(g) >= n {
			return g
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("%d frame(s) expected, got %v", n, frames())
	return nil
}

// An event about a relay the parent has not been told about is HELD until the snapshot that declares it has been
// sent (the grandchild that has just linked: its lifecycle event used to be refused as "unknown descendant").
func TestUplink_EventForAnUndeclaredRelayWaitsForItsSnapshot(t *testing.T) {
	var mu sync.Mutex
	relays := []TopoRelay{}
	topo := make(chan struct{}, 1)
	_ = topo
	events := make(chan Event, 4)
	frames := servedFrames(t, Options{
		Events: events, TopologyChanged: topo, TopologyDebounce: 20 * time.Millisecond, TopologyMinGap: 50 * time.Millisecond,
		Snapshot: func() Snapshot {
			mu.Lock()
			defer mu.Unlock()
			return Snapshot{Relays: append([]TopoRelay(nil), relays...)}
		},
	})
	waitFrames(t, frames, 1) // the first snapshot: nothing declared

	// the node now knows gc (its store has the row), but the snapshot already SENT does not list it
	mu.Lock()
	relays = []TopoRelay{{RelayID: "gc", RelayChain: []string{"child", "gc"}}}
	mu.Unlock()
	events <- Event{Event: "relay.up", Hostname: "gc-ev", RelayID: "gc", RelayChain: []string{"gc"}}
	events <- Event{Event: "host.up", Hostname: "own-ev", RelayChain: nil}
	got := waitFrames(t, frames, 4) // initial snapshot, the snapshot the hold asked for, then the two events
	idx := func(f string) int {
		for i, g := range got {
			if g == f {
				return i
			}
		}
		return -1
	}
	if a, b, c := idx("snapshot[gc,]"), idx("event:gc-ev"), idx("event:own-ev"); a < 0 || b < a || c < b {
		t.Errorf("frames = %v, want the declaring snapshot, then the held event, then the next one", got)
	}
}

// A relay that never gets declared must not block the queue for ever: the event goes out after the hold delay.
func TestUplink_HeldEventIsSentAfterTheHoldDelay(t *testing.T) {
	prev := holdEventsFor
	holdEventsFor = 200 * time.Millisecond
	t.Cleanup(func() { holdEventsFor = prev })
	events := make(chan Event, 2)
	frames := servedFrames(t, Options{
		Events: events, TopologyDebounce: time.Hour, TopologyMinGap: time.Hour,
		Snapshot: func() Snapshot { return Snapshot{} },
	})
	waitFrames(t, frames, 1)
	events <- Event{Event: "relay.up", Hostname: "ghost-ev", RelayID: "ghost", RelayChain: []string{"ghost"}}
	waitFrames(t, frames, 2) // the initial snapshot, then (after the hold delay) the event
	if f := frames(); f[len(f)-1] != "event:ghost-ev" {
		t.Errorf("frames = %v, want the held event sent after the delay", f)
	}
}

// An event for a relay that stays undeclared is held ONCE: after the snapshot it is sent anyway and the next
// ones are not held, so a queue of N of them drains in bounded time (not N x the hold delay).
func TestUplink_ManyEventsOfAnUndeclaredRelayDrainInBoundedTime(t *testing.T) {
	events := make(chan Event, 300)
	frames := servedFrames(t, Options{
		Events: events, TopologyDebounce: 20 * time.Millisecond, TopologyMinGap: 50 * time.Millisecond,
		Snapshot: func() Snapshot { return Snapshot{} },
	})
	waitFrames(t, frames, 1)
	const n = 200
	for i := 0; i < n; i++ {
		events <- Event{Event: "host.down", Hostname: "h", RelayChain: []string{"never-declared"}}
	}
	t0 := time.Now()
	waitFrames(t, frames, 1+n) // the initial snapshot, at least one asked by the hold, and every event
	if d := time.Since(t0); d > 3*time.Second {
		t.Errorf("%d events of an undeclared relay took %v to drain (held once, then released)", n, d)
	}
}

// Relays declared earlier on the session are never held again, even when a later snapshot no longer lists them
// (an event of a relay that fell, relay.removed of a deleted child, a replay after a failover).
func TestUplink_EventsOfAFormerlyDeclaredRelayAreNotHeld(t *testing.T) {
	var mu sync.Mutex
	relays := []TopoRelay{{RelayID: "gone", RelayChain: []string{"child", "gone"}}}
	topo := make(chan struct{}, 1)
	events := make(chan Event, 1100)
	frames := servedFrames(t, Options{
		Events: events, TopologyChanged: topo, TopologyDebounce: 20 * time.Millisecond, TopologyMinGap: 50 * time.Millisecond,
		Snapshot: func() Snapshot {
			mu.Lock()
			defer mu.Unlock()
			return Snapshot{Relays: append([]TopoRelay(nil), relays...)}
		},
	})
	waitFrames(t, frames, 1)
	mu.Lock()
	relays = nil // the relay is gone: the next snapshot no longer lists it
	mu.Unlock()
	topo <- struct{}{}
	waitFrames(t, frames, 2)
	const n = 1000
	for i := 0; i < n; i++ {
		events <- Event{Event: "host.down", Hostname: "h", RelayChain: []string{"gone"}}
	}
	t0 := time.Now()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) && len(frames()) < 2+n {
		time.Sleep(20 * time.Millisecond)
	}
	if got := len(frames()); got < 2+n {
		t.Fatalf("only %d frames, want %d: events of a formerly declared relay were held", got, 2+n)
	}
	if d := time.Since(t0); d > 10*time.Second {
		t.Errorf("%d events took %v", n, d)
	}
}

// A held event still pending when the session ends is counted as lost.
func TestUplink_HeldEventAtTheEndOfTheSessionIsCounted(t *testing.T) {
	var lost sync.Mutex
	n := 0
	events := make(chan Event, 1)
	up := NewUplink("child", Options{
		Events: events, TopologyDebounce: time.Hour, TopologyMinGap: time.Hour,
		Snapshot:    func() Snapshot { return Snapshot{} },
		OnEventLost: func(k int64) { lost.Lock(); n += int(k); lost.Unlock() },
	})
	ctx, cancel := context.WithCancel(context.Background())
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			return
		}
		_ = up.Serve(ctx, c)
	}))
	defer srv.Close()
	c, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, _, _ = c.ReadMessage() // the snapshot
	events <- Event{Event: "relay.up", RelayID: "ghost", RelayChain: []string{"ghost"}}
	time.Sleep(200 * time.Millisecond) // held (the next snapshot is an hour away)
	cancel()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		lost.Lock()
		got := n
		lost.Unlock()
		if got == 1 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Error("the event held when the session ended was not counted as lost")
}
