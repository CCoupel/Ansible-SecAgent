// SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"sync"
	"testing"
	"time"
)

type convRec struct {
	mu    sync.Mutex
	calls [][2]int
}

func (r *convRec) emit(c, m int) { r.mu.Lock(); r.calls = append(r.calls, [2]int{c, m}); r.mu.Unlock() }
func (r *convRec) get() [][2]int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([][2]int(nil), r.calls...)
}

func waitCalls(t *testing.T, r *convRec, n int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if len(r.get()) >= n {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("%d emission(s) expected, got %v", n, r.get())
}

// No declared child: relay.converged right away, 0 connected 0 missing.
func TestConvergence_NoChildIsImmediate(t *testing.T) {
	r := &convRec{}
	c := newConvergence(nil, r.emit)
	c.start(time.Hour)
	waitCalls(t, r, 1) // emitted from a goroutine: start never blocks its caller
	if got := r.get(); len(got) != 1 || got[0] != [2]int{0, 0} {
		t.Fatalf("emissions = %v, want [[0 0]]", got)
	}
}

// Two expected, both back (one of them below the other link): ONE emission with exact counts, nothing
// more when a child reconnects afterwards.
func TestConvergence_AllBackGivesOneEvent(t *testing.T) {
	r := &convRec{}
	c := newConvergence([]string{"relay1", "relay2"}, r.emit)
	c.start(time.Hour)
	if len(r.get()) != 0 {
		t.Fatal("emitted before any link")
	}
	c.linkUp("relay1")
	time.Sleep(20 * time.Millisecond)
	if len(r.get()) != 0 {
		t.Fatal("emitted with one relay still missing")
	}
	c.linkUp("relay1", "relay2") // a link declaring a descendant counts it
	waitCalls(t, r, 1)
	c.linkUp("relay1") // reconnection after the emission
	c.linkUp("relay2")
	time.Sleep(50 * time.Millisecond)
	if got := r.get(); len(got) != 1 || got[0] != [2]int{2, 0} {
		t.Fatalf("emissions = %v, want [[2 0]]", got)
	}
}

// One child never comes back: emission at the timeout with relays_missing=1, never re-emitted.
func TestConvergence_TimeoutEmitsWithMissing(t *testing.T) {
	r := &convRec{}
	c := newConvergence([]string{"relay1", "relay2"}, r.emit)
	c.start(80 * time.Millisecond)
	c.linkUp("relay1")
	time.Sleep(20 * time.Millisecond)
	if len(r.get()) != 0 {
		t.Fatal("emitted before the timeout")
	}
	waitCalls(t, r, 1)
	c.linkUp("relay2") // late
	time.Sleep(150 * time.Millisecond)
	if got := r.get(); len(got) != 1 || got[0] != [2]int{1, 1} {
		t.Fatalf("emissions = %v, want [[1 1]]", got)
	}
}

// A node that is closing emits nothing.
func TestConvergence_StopSilencesTheTimerAndTheLinks(t *testing.T) {
	r := &convRec{}
	c := newConvergence([]string{"relay1"}, r.emit)
	c.start(50 * time.Millisecond)
	c.stop()
	c.linkUp("relay1")
	time.Sleep(150 * time.Millisecond)
	if got := r.get(); len(got) != 0 {
		t.Fatalf("emissions after stop = %v", got)
	}
}

func TestConvergence_TimeoutEnvBounds(t *testing.T) {
	captureLog(t)
	for _, c := range []struct {
		val  string
		want time.Duration
	}{{"", 60 * time.Second}, {"5s", 5 * time.Second}, {"2s", 60 * time.Second}, {"30s", 30 * time.Second}, {"45", 45 * time.Second}, {"10m", 10 * time.Minute},
		{"500ms", 60 * time.Second}, {"11m", 60 * time.Second}, {"abc", 60 * time.Second}, {"-5s", 60 * time.Second}} {
		t.Setenv("RELAY_CONVERGENCE_TIMEOUT", c.val)
		if got := ConvergenceTimeoutFromEnv(); got != c.want {
			t.Errorf("RELAY_CONVERGENCE_TIMEOUT=%q -> %v, want %v", c.val, got, c.want)
		}
	}
}
