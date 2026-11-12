// SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
// SPDX-License-Identifier: AGPL-3.0-or-later

package storage

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

func enroll(t *testing.T, s *Store, host string) {
	t.Helper()
	if _, err := s.RegisterAgent(context.Background(), host, "PEM-"+host, "jti-"+host); err != nil {
		t.Fatal(err)
	}
}

func persistedFirstSeen(t *testing.T, s *Store, host string) *time.Time {
	t.Helper()
	a, ok := s.snap().Agent(host)
	if !ok {
		t.Fatalf("agent %s missing", host)
	}
	return a.FirstSeenAt
}

// Two concurrent first handshakes of the same host give exactly ONE "first"; an unknown host none.
func TestFirstSeen_AtomicOneFirstPerHost(t *testing.T) {
	s := newTestStore(t)
	s.SetFirstSeenFlush(time.Hour)
	enroll(t, s, "h1")
	var wg sync.WaitGroup
	var mu sync.Mutex
	firsts := 0
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if f, _ := s.MarkFirstSeen("h1"); f {
				mu.Lock()
				firsts++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if firsts != 1 {
		t.Errorf("%d first marks for one host, want 1", firsts)
	}
	if f, _ := s.MarkFirstSeen("ghost"); f {
		t.Error("an unknown host must not be marked")
	}
}

// The mark is persisted within the flush delay, once; later handshakes are never "first".
func TestFirstSeen_FlushPersistsThenNeverFirstAgain(t *testing.T) {
	s := newTestStore(t)
	s.SetFirstSeenFlush(100 * time.Millisecond)
	enroll(t, s, "h1")
	first, at := s.MarkFirstSeen("h1")
	if !first || at.IsZero() {
		t.Fatalf("first = %v at = %v", first, at)
	}
	if persistedFirstSeen(t, s, "h1") != nil {
		t.Fatal("persisted before the flush delay")
	}
	rec, _ := s.GetAgent(context.Background(), "h1")
	if rec.FirstSeenAt == nil || !rec.FirstSeenAt.Equal(at) {
		t.Errorf("the in-memory mark must be visible meanwhile: %v", rec.FirstSeenAt)
	}
	deadline := time.Now().Add(3 * time.Second)
	for persistedFirstSeen(t, s, "h1") == nil && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	got := persistedFirstSeen(t, s, "h1")
	if got == nil || !got.Equal(at) {
		t.Fatalf("persisted mark = %v, want %v", got, at)
	}
	if f, _ := s.MarkFirstSeen("h1"); f {
		t.Error("a second handshake must not be first")
	}
}

// A natural write of the state carries the pending marks (piggyback): no extra write is needed.
func TestFirstSeen_PiggybackedOnANaturalWrite(t *testing.T) {
	s := newTestStore(t)
	s.SetFirstSeenFlush(time.Hour)
	enroll(t, s, "h1")
	enroll(t, s, "h2")
	s.MarkFirstSeen("h1")
	s.MarkFirstSeen("h2")
	enroll(t, s, "h3") // any write
	for _, h := range []string{"h1", "h2"} {
		if persistedFirstSeen(t, s, h) == nil {
			t.Errorf("%s: mark not written by the natural write", h)
		}
	}
	if persistedFirstSeen(t, s, "h3") != nil {
		t.Error("h3 was never marked")
	}
}

// A burst of first connections: a handful of writes, not one per host (200 hosts here: each enrolment costs a state write).
func TestFirstSeen_BurstIsGrouped(t *testing.T) {
	s := newTestStore(t)
	s.SetFirstSeenFlush(300 * time.Millisecond)
	const n = 200
	for i := 0; i < n; i++ {
		enroll(t, s, fmt.Sprintf("b-%04d", i))
	}
	w0 := s.Engine().Writes()
	for i := 0; i < n; i++ {
		s.MarkFirstSeen(fmt.Sprintf("b-%04d", i))
	}
	time.Sleep(time.Second)
	if w := s.Engine().Writes() - w0; w > 10 {
		t.Errorf("%d state writes for %d first connections, want <= 10", w, n)
	}
	for i := 0; i < n; i += 50 {
		if persistedFirstSeen(t, s, fmt.Sprintf("b-%04d", i)) == nil {
			t.Errorf("b-%04d not persisted", i)
		}
	}
}

// A refused write (lock lost, #163) keeps the marks and tries again; once allowed they are written.
func TestFirstSeen_RefusedWriteKeepsTheMarks(t *testing.T) {
	s := newTestStore(t)
	s.SetFirstSeenFlush(50 * time.Millisecond)
	enroll(t, s, "h1")
	var mu sync.Mutex
	deny := true
	s.SetWriteGuard(func() error {
		mu.Lock()
		defer mu.Unlock()
		if deny {
			return errors.New("lock lost")
		}
		return nil
	})
	s.MarkFirstSeen("h1")
	time.Sleep(300 * time.Millisecond)
	if persistedFirstSeen(t, s, "h1") != nil {
		t.Fatal("written although the guard refused")
	}
	mu.Lock()
	deny = false
	mu.Unlock()
	deadline := time.Now().Add(3 * time.Second)
	for persistedFirstSeen(t, s, "h1") == nil && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if persistedFirstSeen(t, s, "h1") == nil {
		t.Error("the kept mark was never written after the guard allowed")
	}
}

// Re-enrolment WITHOUT deletion keeps the mark; DELETE clears it (a new enrolment is "first" again).
func TestFirstSeen_ReenrolKeepsDeleteClears(t *testing.T) {
	s := newTestStore(t)
	s.SetFirstSeenFlush(20 * time.Millisecond)
	enroll(t, s, "h1")
	s.MarkFirstSeen("h1")
	time.Sleep(200 * time.Millisecond)
	want := persistedFirstSeen(t, s, "h1")
	if want == nil {
		t.Fatal("not persisted")
	}
	enroll(t, s, "h1") // re-enrolment: key and JTI refreshed
	if got := persistedFirstSeen(t, s, "h1"); got == nil || !got.Equal(*want) {
		t.Errorf("re-enrolment changed the mark: %v -> %v", want, got)
	}
	if f, _ := s.MarkFirstSeen("h1"); f {
		t.Error("a re-enrolled host is not first again")
	}
	if ok, err := s.DeleteAgent(context.Background(), "h1"); err != nil || !ok {
		t.Fatal(ok, err)
	}
	enroll(t, s, "h1")
	if persistedFirstSeen(t, s, "h1") != nil {
		t.Error("the mark survived the deletion")
	}
	if f, _ := s.MarkFirstSeen("h1"); !f {
		t.Error("a host enrolled again after a deletion must be first again")
	}
}

// Close writes what is pending.
func TestFirstSeen_CloseFlushes(t *testing.T) {
	dir := t.TempDir()
	s, err := OpenTestDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	s.SetFirstSeenFlush(time.Hour)
	enroll(t, s, "h1")
	s.MarkFirstSeen("h1")
	_ = s.Close()
	s2, err := OpenTestDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s2.Close() }()
	if persistedFirstSeen(t, s2, "h1") == nil {
		t.Error("the pending mark was lost at Close")
	}
}

// A DECLARED relay node gets a mark; an undeclared relay none.
func TestFirstSeen_RelayNode(t *testing.T) {
	s := newTestStore(t)
	s.SetFirstSeenFlush(50 * time.Millisecond)
	if f, _ := s.MarkRelayFirstSeen("nobody"); f {
		t.Fatal("an undeclared relay must not be marked")
	}
	if err := s.UpsertRelayNode(RelayNode{ID: "id1", RelayID: "dmz1", Mode: "pull"}); err != nil {
		t.Fatal(err)
	}
	if f, _ := s.MarkRelayFirstSeen("dmz1"); !f {
		t.Fatal("first snapshot of a declared relay must be first")
	}
	if f, _ := s.MarkRelayFirstSeen("dmz1"); f {
		t.Error("pending: not first twice")
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if n, _ := s.snap().RelayNode("dmz1"); n.FirstSeenAt != nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	n, _ := s.snap().RelayNode("dmz1")
	if n.FirstSeenAt == nil {
		t.Fatal("not persisted")
	}
	// an update of the declaration keeps the mark
	if err := s.UpsertRelayNode(RelayNode{ID: "id1", RelayID: "dmz1", Mode: "pull", Description: "x"}); err != nil {
		t.Fatal(err)
	}
	if n2, _ := s.snap().RelayNode("dmz1"); n2.FirstSeenAt == nil || !n2.FirstSeenAt.Equal(*n.FirstSeenAt) {
		t.Error("UpsertRelayNode must keep first_seen_at")
	}
}

func TestFirstSeenFlushFromEnv(t *testing.T) {
	for v, want := range map[string]time.Duration{"": time.Second, "100ms": 100 * time.Millisecond, "10s": 10 * time.Second, "50ms": time.Second, "11s": time.Second, "x": time.Second} {
		t.Setenv("RELAY_FIRST_SEEN_FLUSH", v)
		if got := FirstSeenFlushFromEnv(); got != want {
			t.Errorf("%q -> %v, want %v", v, got, want)
		}
	}
}
