// SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
// SPDX-License-Identifier: AGPL-3.0-or-later

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

// serveRated runs an Uplink fed by a pre-filled channel and returns the instants at which the peer
// received each event_forward.
func serveRated(t *testing.T, opts Options) <-chan time.Time {
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
	got := make(chan time.Time, 4096)
	go func() {
		for {
			var m map[string]any
			if err := c.ReadJSON(&m); err != nil {
				return
			}
			if m["type"] == "event_forward" {
				got <- time.Now()
			}
		}
	}()
	return got
}

// The replay of a backlog is paced at EventRate per second: nothing is lost, nothing goes faster
// than the rate (the parent refuses more than 200/s per identity).
func TestUplink_ReplayIsPacedAtEventRate(t *testing.T) {
	const n = 120
	rate := 100
	events := make(chan Event, n)
	for i := 0; i < n; i++ {
		events <- Event{Event: "host.up", Hostname: "h", RelayChain: []string{}}
	}
	var lost atomic.Int64
	got := serveRated(t, Options{Events: events, EventRate: rate, OnEventLost: func(k int64) { lost.Add(k) }})
	var first, last time.Time
	for i := 0; i < n; i++ {
		select {
		case at := <-got:
			if i == 0 {
				first = at
			}
			last = at
		case <-time.After(10 * time.Second):
			t.Fatalf("only %d/%d events received", i, n)
		}
	}
	// n events at `rate` per second need (n-1)/rate seconds; allow 15 % for the timers' granularity
	if min := time.Duration(float64(n-1) / float64(rate) * 0.85 * float64(time.Second)); last.Sub(first) < min {
		t.Errorf("%d events replayed in %v, want at least %v at %d/s", n, last.Sub(first), min, rate)
	}
	if lost.Load() != 0 {
		t.Errorf("lost = %d, want 0", lost.Load())
	}
}

// Without EventRate the uplink sends as fast as it can (unchanged behaviour).
func TestUplink_NoEventRateIsUnpaced(t *testing.T) {
	const n = 300
	events := make(chan Event, n)
	for i := 0; i < n; i++ {
		events <- Event{Event: "host.up", Hostname: "h", RelayChain: []string{}}
	}
	got := serveRated(t, Options{Events: events})
	start := time.Now()
	for i := 0; i < n; i++ {
		select {
		case <-got:
		case <-time.After(10 * time.Second):
			t.Fatalf("only %d/%d events received", i, n)
		}
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("%d unpaced events took %v", n, d)
	}
}

// An event that cannot be forwarded (loop in its chain) is counted as lost, never forgotten.
func TestUplink_UndeliverableEventIsCounted(t *testing.T) {
	events := make(chan Event, 2)
	events <- Event{Event: "host.up", Hostname: "h", RelayChain: []string{"child"}} // loop: "child" already in
	events <- Event{Event: "host.up", Hostname: "h", RelayChain: []string{}}
	var lost atomic.Int64
	got := serveRated(t, Options{Events: events, OnEventLost: func(k int64) { lost.Add(k) }})
	select {
	case <-got:
	case <-time.After(5 * time.Second):
		t.Fatal("the valid event was not delivered")
	}
	if lost.Load() != 1 {
		t.Errorf("lost = %d, want 1", lost.Load())
	}
}

// An event that sat in the queue (older than LateEventAfter) is marked late; a fresh one is not.
func TestUplink_ReplayedEventIsMarkedLate(t *testing.T) {
	old := time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)
	fresh := time.Now().UTC().Format(time.RFC3339)
	events := make(chan Event, 2)
	events <- Event{Event: "host.up", Hostname: "old", Timestamp: old, RelayChain: []string{}}
	events <- Event{Event: "host.up", Hostname: "fresh", Timestamp: fresh, RelayChain: []string{}}
	up := NewUplink("child", Options{Events: events})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			return
		}
		_ = up.Serve(context.Background(), c)
	}))
	defer srv.Close()
	c, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	late := map[string]bool{}
	deadline := time.Now().Add(5 * time.Second)
	for len(late) < 2 && time.Now().Before(deadline) {
		var m struct {
			Type     string `json:"type"`
			Hostname string `json:"hostname"`
			Late     bool   `json:"late"`
		}
		_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
		if err := c.ReadJSON(&m); err != nil {
			t.Fatal(err)
		}
		if m.Type == "event_forward" {
			late[m.Hostname] = m.Late
		}
	}
	if !late["old"] || late["fresh"] {
		t.Errorf("late flags = %v, want old=true fresh=false", late)
	}
}
