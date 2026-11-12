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

	events <- Event{Event: "relay.up", Hostname: "gc-ev", RelayID: "gc", RelayChain: []string{"gc"}}
	events <- Event{Event: "host.up", Hostname: "own-ev", RelayChain: nil} // own host: nothing to wait for... but FIFO behind the held one
	time.Sleep(300 * time.Millisecond)
	for _, f := range frames() {
		if strings.HasPrefix(f, "event:") {
			t.Fatalf("event sent before the snapshot that declares gc: %v", frames())
		}
	}
	mu.Lock()
	relays = []TopoRelay{{RelayID: "gc", RelayChain: []string{"child", "gc"}}}
	mu.Unlock()
	topo <- struct{}{}
	got := waitFrames(t, frames, 5) // snapshots: initial, the one the hold asked for, the declaring one; 2 events
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
