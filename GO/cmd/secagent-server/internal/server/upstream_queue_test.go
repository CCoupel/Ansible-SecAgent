// SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"bytes"
	"log"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"secagent-server/cmd/secagent-server/internal/repeater"
)

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

func captureLog(t *testing.T) *syncBuf {
	t.Helper()
	out := &syncBuf{}
	log.SetOutput(out)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	return out
}

// 300 events into a queue of 256 with nobody reading: 44 are lost, counted exactly, and ONE
// aggregated warning is logged (not one per event).
func TestUpstreamQueue_OverflowIsCountedAndLoggedOnce(t *testing.T) {
	out := captureLog(t)
	q := newUpstreamQueue(256, nil, 50*time.Millisecond)
	defer q.Close()
	for i := 0; i < 300; i++ {
		q.Offer(repeater.Event{Event: "host.up"})
	}
	dropped, depth, capacity := q.Stats()
	if dropped != 44 || depth != 256 || capacity != 256 {
		t.Fatalf("stats = %d/%d/%d, want 44/256/256", dropped, depth, capacity)
	}
	time.Sleep(200 * time.Millisecond)
	if n := strings.Count(out.String(), "event(s) dropped"); n != 1 {
		t.Errorf("%d drop lines, want 1:\n%s", n, out.String())
	}
	if !strings.Contains(out.String(), "44 event(s) dropped") {
		t.Errorf("the line must name the count:\n%s", out.String())
	}
}

// An event the uplink took but could not deliver is counted with the others.
func TestUpstreamQueue_LostEventsAreCounted(t *testing.T) {
	captureLog(t)
	q := newUpstreamQueue(256, nil, time.Hour)
	q.Lost(3)
	if d, _, _ := q.Stats(); d != 3 {
		t.Errorf("dropped = %d, want 3", d)
	}
	q.Close() // flushes the pending report
}

func TestUpstreamQueue_EnvBounds(t *testing.T) {
	captureLog(t)
	for _, c := range []struct {
		val  string
		want int
	}{{"", 10000}, {"256", 256}, {"100000", 100000}, {"255", 10000}, {"100001", 10000}, {"abc", 10000}} {
		t.Setenv("RELAY_UPSTREAM_QUEUE_SIZE", c.val)
		if got := UpstreamQueueSizeFromEnv(); got != c.want {
			t.Errorf("RELAY_UPSTREAM_QUEUE_SIZE=%q -> %d, want %d", c.val, got, c.want)
		}
	}
	for _, c := range []struct {
		val  string
		want int
	}{{"", 150}, {"10", 10}, {"1000", 1000}, {"9", 150}, {"1001", 150}} {
		t.Setenv("RELAY_UPSTREAM_RATE", c.val)
		if got := UpstreamRateFromEnv(); got != c.want {
			t.Errorf("RELAY_UPSTREAM_RATE=%q -> %d, want %d", c.val, got, c.want)
		}
	}
}

// Memory of a full default queue: a few MiB at most (the figure of the handoff).
func TestUpstreamQueue_MemoryOfAFullQueue(t *testing.T) {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	q := newUpstreamQueue(DefaultUpstreamQueueSize, nil, time.Hour)
	for i := 0; i < DefaultUpstreamQueueSize; i++ {
		q.Offer(repeater.Event{Event: "host.up", Hostname: "host-0001.example.org", RelayID: "dmz1",
			Status: "online", RelayChain: []string{"dmz1", "dmz2"}, Timestamp: "2026-11-11T10:00:00Z"})
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	used := int64(after.HeapAlloc) - int64(before.HeapAlloc)
	t.Logf("10000 queued events: %d KiB of heap", used/1024)
	if used > 16<<20 {
		t.Errorf("a full queue uses %d MiB, want a few MiB", used>>20)
	}
	q.Close()
}

func TestUpstreamRate_WarnsAboveTheParentQuota(t *testing.T) {
	out := captureLog(t)
	t.Setenv("RELAY_UPSTREAM_RATE", "150")
	UpstreamRateFromEnv()
	if strings.Contains(out.String(), "exceeds the parent's event quota") {
		t.Errorf("150/s must not warn:\n%s", out.String())
	}
	t.Setenv("RELAY_UPSTREAM_RATE", "250")
	if got := UpstreamRateFromEnv(); got != 250 || !strings.Contains(out.String(), "exceeds the parent's event quota") {
		t.Errorf("rate %d, log:\n%s", got, out.String())
	}
}
