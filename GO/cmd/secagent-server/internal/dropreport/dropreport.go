// SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package dropreport aggregates a stream of losses into ONE report per period: whatever the number
// of events lost in the period, the log (and the journal) gets a single line instead of one per event.
package dropreport

import (
	"sync"
	"time"
)

// Aggregator counts losses and calls flush once per interval with the number lost in that period.
// The first loss of a quiet period arms a timer; the report is therefore never missed (no trailing
// loss), never more frequent than interval, and costs nothing while nothing is lost.
type Aggregator struct {
	interval time.Duration
	flush    func(n int64)

	mu      sync.Mutex
	pending int64
	timer   *time.Timer
	stopped bool
	running sync.WaitGroup // one count per armed timer, released when its flush has returned (or it was cancelled)
}

// New returns an Aggregator reporting at most once per interval.
func New(interval time.Duration, flush func(n int64)) *Aggregator {
	return &Aggregator{interval: interval, flush: flush}
}

// Add records n losses (n <= 0 is ignored).
func (a *Aggregator) Add(n int64) {
	if n <= 0 {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.stopped {
		return
	}
	a.pending += n
	if a.timer == nil {
		a.running.Add(1)
		a.timer = time.AfterFunc(a.interval, a.fire)
	}
}

func (a *Aggregator) fire() {
	defer a.running.Done()
	a.mu.Lock()
	n := a.pending
	a.pending, a.timer = 0, nil
	a.mu.Unlock()
	if n > 0 {
		a.flush(n)
	}
}

// cancelTimerLocked disarms the timer; when it had not fired yet its WaitGroup count is released here.
func (a *Aggregator) cancelTimerLocked() {
	if a.timer != nil && a.timer.Stop() {
		a.running.Done()
	}
	a.timer = nil
}

// Stop reports what is still pending, once, disarms the Aggregator for good, and waits for a flush
// already started by the timer to return (nothing logs after Stop returns).
func (a *Aggregator) Stop() {
	a.mu.Lock()
	a.stopped = true
	a.cancelTimerLocked()
	n := a.pending
	a.pending = 0
	a.mu.Unlock()
	if n > 0 {
		a.flush(n)
	}
	a.running.Wait()
}

// Flush reports what is pending now and keeps the Aggregator armed for the next period.
func (a *Aggregator) Flush() {
	a.mu.Lock()
	a.cancelTimerLocked()
	n := a.pending
	a.pending = 0
	a.mu.Unlock()
	if n > 0 {
		a.flush(n)
	}
}
