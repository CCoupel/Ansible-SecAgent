// SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
// SPDX-License-Identifier: AGPL-3.0-or-later

package storage

import (
	"log"
	"os"
	"strings"
	"time"

	"secagent-server/cmd/secagent-server/internal/state"
)

// First-seen marks (v3.0.6, #266): the date of the first handshake of an agent (host.discover) or of the
// first snapshot of a declared relay (relay.discover). A mark is decided in MEMORY, atomically (two
// concurrent first handshakes of the same host give ONE "first"), and persisted GROUPED: every pending
// mark goes into the next natural write of the state (piggyback) or, at the latest FirstSeenFlush later,
// into one mutation for all of them (a burst of 3 000 first connections costs a handful of writes, not
// 3 000). The event is emitted before the persistence: after a crash inside that delay the host is
// "first" again, so at most one more discover (at-least-once). A refused write (write guard of #163)
// keeps the marks and tries again.

// Bounds of RELAY_FIRST_SEEN_FLUSH.
const (
	DefaultFirstSeenFlush = time.Second
	MinFirstSeenFlush     = 100 * time.Millisecond
	MaxFirstSeenFlush     = 10 * time.Second
	maxPendingFirstSeen   = 100000
)

// FirstSeenFlushFromEnv returns RELAY_FIRST_SEEN_FLUSH (a Go duration) within [100ms, 10s], else the default
// (with a warning).
func FirstSeenFlushFromEnv() time.Duration {
	raw := strings.TrimSpace(os.Getenv("RELAY_FIRST_SEEN_FLUSH"))
	if raw == "" {
		return DefaultFirstSeenFlush
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d < MinFirstSeenFlush || d > MaxFirstSeenFlush {
		log.Printf("[WARN] RELAY_FIRST_SEEN_FLUSH=%q is not a duration in [%s, %s]: using the default %s", raw, MinFirstSeenFlush, MaxFirstSeenFlush, DefaultFirstSeenFlush)
		return DefaultFirstSeenFlush
	}
	return d
}

type firstSeenState struct {
	agents map[string]time.Time
	relays map[string]time.Time
	timer  *time.Timer
	every  time.Duration
	closed bool
}

// SetFirstSeenFlush sets the maximum delay before pending marks are written (tests, RELAY_FIRST_SEEN_FLUSH).
func (s *Store) SetFirstSeenFlush(d time.Duration) {
	s.fsMu.Lock()
	s.fs.every = d
	s.fsMu.Unlock()
}

// MarkFirstSeen reports whether this is the FIRST handshake of the agent (exists, no persisted mark, not
// already marked in memory) and, if so, remembers the date to persist. Unknown host: false.
func (s *Store) MarkFirstSeen(hostname string) (first bool, at time.Time) {
	a, ok := s.snap().Agent(hostname)
	if !ok || a.FirstSeenAt != nil {
		return false, time.Time{}
	}
	s.fsMu.Lock()
	defer s.fsMu.Unlock()
	if s.fs.closed {
		return false, time.Time{}
	}
	if _, pending := s.fs.agents[hostname]; pending || len(s.fs.agents)+len(s.fs.relays) >= maxPendingFirstSeen {
		return false, time.Time{}
	}
	at = nowUTC()
	if s.fs.agents == nil {
		s.fs.agents = map[string]time.Time{}
	}
	s.fs.agents[hostname] = at
	s.armFirstSeenLocked()
	return true, at
}

// MarkRelayFirstSeen is MarkFirstSeen for a DECLARED relay node (no row: false, nothing is created).
func (s *Store) MarkRelayFirstSeen(relayID string) (first bool, at time.Time) {
	n, ok := s.snap().RelayNode(relayID)
	if !ok || n.FirstSeenAt != nil {
		return false, time.Time{}
	}
	s.fsMu.Lock()
	defer s.fsMu.Unlock()
	if s.fs.closed {
		return false, time.Time{}
	}
	if _, pending := s.fs.relays[relayID]; pending || len(s.fs.agents)+len(s.fs.relays) >= maxPendingFirstSeen {
		return false, time.Time{}
	}
	at = nowUTC()
	if s.fs.relays == nil {
		s.fs.relays = map[string]time.Time{}
	}
	s.fs.relays[relayID] = at
	s.armFirstSeenLocked()
	return true, at
}

func (s *Store) armFirstSeenLocked() {
	if s.fs.timer != nil {
		return
	}
	d := s.fs.every
	if d <= 0 {
		d = DefaultFirstSeenFlush
	}
	s.fs.timer = time.AfterFunc(d, func() { s.FlushFirstSeen() })
}

// mergeFirstSeen puts the pending marks into a payload about to be written (piggyback).
func (s *Store) mergeFirstSeen(p *state.Payload) {
	s.fsMu.Lock()
	defer s.fsMu.Unlock()
	for h, at := range s.fs.agents {
		if a, ok := p.Agents[h]; ok && a.FirstSeenAt == nil {
			t := at
			a.FirstSeenAt = &t
			p.Agents[h] = a
		}
	}
	for id, at := range s.fs.relays {
		if n, ok := p.RelayNodes[id]; ok && n.FirstSeenAt == nil {
			t := at
			n.FirstSeenAt = &t
			p.RelayNodes[id] = n
		}
	}
}

// reapFirstSeen forgets the pending marks the state now holds (after any successful write).
func (s *Store) reapFirstSeen() {
	s.fsMu.Lock()
	defer s.fsMu.Unlock()
	if len(s.fs.agents) == 0 && len(s.fs.relays) == 0 {
		return
	}
	snap := s.snap()
	for h := range s.fs.agents {
		if a, ok := snap.Agent(h); !ok || a.FirstSeenAt != nil {
			delete(s.fs.agents, h)
		}
	}
	for id := range s.fs.relays {
		if n, ok := snap.RelayNode(id); !ok || n.FirstSeenAt != nil {
			delete(s.fs.relays, id)
		}
	}
}

// pendingFirstSeen returns the in-memory mark of an agent that is not persisted yet.
func (s *Store) pendingFirstSeen(hostname string) (time.Time, bool) {
	s.fsMu.Lock()
	defer s.fsMu.Unlock()
	t, ok := s.fs.agents[hostname]
	return t, ok
}

// forgetFirstSeen drops the pending mark of a deleted agent / relay.
func (s *Store) forgetFirstSeen(hostname, relayID string) {
	s.fsMu.Lock()
	delete(s.fs.agents, hostname)
	delete(s.fs.relays, relayID)
	s.fsMu.Unlock()
}

// FlushFirstSeen writes every pending mark in ONE mutation. A refused write keeps them and is retried
// after the flush delay.
func (s *Store) FlushFirstSeen() {
	s.fsMu.Lock()
	s.fs.timer = nil
	agents, relays := s.fs.agents, s.fs.relays
	s.fs.agents, s.fs.relays = map[string]time.Time{}, map[string]time.Time{}
	s.fsMu.Unlock()
	if len(agents) == 0 && len(relays) == 0 {
		return
	}
	err := s.mutate(func(tx *state.Tx) error {
		for h, at := range agents {
			if a, ok := tx.Agent(h); ok && a.FirstSeenAt == nil {
				t := at
				a.FirstSeenAt = &t
				if err := tx.PutAgent(a); err != nil {
					return err
				}
			}
		}
		for id, at := range relays {
			if n, ok := tx.RelayNode(id); ok && n.FirstSeenAt == nil {
				t := at
				n.FirstSeenAt = &t
				if err := tx.PutRelayNode(n); err != nil {
					return err
				}
			}
		}
		return nil
	})
	if err == nil {
		return
	}
	log.Printf("[WARN] first_seen_at: %d agent mark(s) and %d relay mark(s) not written (kept, retried): %v", len(agents), len(relays), err)
	s.fsMu.Lock()
	for h, at := range agents {
		if _, newer := s.fs.agents[h]; !newer {
			if s.fs.agents == nil {
				s.fs.agents = map[string]time.Time{}
			}
			s.fs.agents[h] = at
		}
	}
	for id, at := range relays {
		if _, newer := s.fs.relays[id]; !newer {
			if s.fs.relays == nil {
				s.fs.relays = map[string]time.Time{}
			}
			s.fs.relays[id] = at
		}
	}
	if !s.fs.closed {
		s.armFirstSeenLocked()
	}
	s.fsMu.Unlock()
}

// closeFirstSeen stops the timer and writes what is pending (a refused write is only logged).
func (s *Store) closeFirstSeen() {
	s.fsMu.Lock()
	s.fs.closed = true
	if s.fs.timer != nil {
		s.fs.timer.Stop()
		s.fs.timer = nil
	}
	s.fsMu.Unlock()
	s.FlushFirstSeen()
}
