// SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"log"
	"os"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"secagent-server/cmd/secagent-server/internal/actionlog"
	"secagent-server/cmd/secagent-server/internal/dropreport"
	"secagent-server/cmd/secagent-server/internal/repeater"
)

// Bounds of the upstream queue and of the replay rate (#246).
const (
	// DefaultUpstreamQueueSize holds the events of a subtree while the uplink is down (an event is
	// about 200 bytes plus its strings: ~2-3 MB when full).
	DefaultUpstreamQueueSize = 10000
	MinUpstreamQueueSize     = 256
	MaxUpstreamQueueSize     = 100000
	// DefaultUpstreamRate is the replay rate toward the parent, under its per-identity quota of 200/s.
	DefaultUpstreamRate = 150
	MinUpstreamRate     = 10
	MaxUpstreamRate     = 1000
	// upstreamDropReportInterval is the period of the aggregated drop warning / journal entry.
	upstreamDropReportInterval = time.Minute
)

// boundedEnvInt reads an integer environment variable within [lo, hi]; anything else gives def and a warning.
func boundedEnvInt(name string, def, lo, hi int) int {
	raw := os.Getenv(name)
	if raw == "" {
		return def
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < lo || n > hi {
		log.Printf("[WARN] %s=%q is not an integer in [%d, %d]: using the default %d", name, raw, lo, hi, def)
		return def
	}
	return n
}

// UpstreamQueueSizeFromEnv returns RELAY_UPSTREAM_QUEUE_SIZE (256..100000, default 10000).
func UpstreamQueueSizeFromEnv() int {
	return boundedEnvInt("RELAY_UPSTREAM_QUEUE_SIZE", DefaultUpstreamQueueSize, MinUpstreamQueueSize, MaxUpstreamQueueSize)
}

// UpstreamRateFromEnv returns RELAY_UPSTREAM_RATE in events per second (10..1000, default 150).
func UpstreamRateFromEnv() int {
	return boundedEnvInt("RELAY_UPSTREAM_RATE", DefaultUpstreamRate, MinUpstreamRate, MaxUpstreamRate)
}

// upstreamQueue is the bounded buffer between the handlers and the uplink: it never blocks a
// producer, and every event it cannot keep (full) or the uplink cannot deliver is counted, with ONE
// aggregated warning and ONE journal entry per period instead of a line per event.
type upstreamQueue struct {
	ch      chan repeater.Event
	dropped atomic.Int64
	agg     *dropreport.Aggregator
}

// newUpstreamQueue creates a queue of the given capacity; journal may be nil.
func newUpstreamQueue(capacity int, journal *actionlog.Journal, interval time.Duration) *upstreamQueue {
	q := &upstreamQueue{ch: make(chan repeater.Event, capacity)}
	q.agg = dropreport.New(interval, func(n int64) {
		msg := strconv.FormatInt(n, 10) + " event(s) dropped in the last period (total " +
			strconv.FormatInt(q.dropped.Load(), 10) + "), upstream queue full or event undeliverable; see RELAY_UPSTREAM_QUEUE_SIZE"
		log.Printf("[REPEATER] upstream: %s", msg)
		if journal != nil {
			if err := journal.Append(actionlog.Entry{
				ID: uuid.New().String(), Event: "*", ActionType: "upstream_dropped", Error: msg, ExecutedAt: time.Now().UTC(),
			}); err != nil {
				log.Printf("[WARN] upstream: action journal: %v", err)
			}
		}
	})
	return q
}

// Offer hands an event to the uplink without ever blocking a handler.
func (q *upstreamQueue) Offer(ev repeater.Event) {
	select {
	case q.ch <- ev:
	default:
		q.Lost(1)
	}
}

// Lost counts n events that were taken from the queue (or refused by it) and never delivered.
func (q *upstreamQueue) Lost(n int64) {
	q.dropped.Add(n)
	q.agg.Add(n)
}

// Chan is the consumer side given to the uplink.
func (q *upstreamQueue) Chan() <-chan repeater.Event { return q.ch }

// Stats returns the counters exposed by the admin status.
func (q *upstreamQueue) Stats() (dropped int64, depth, capacity int) {
	return q.dropped.Load(), len(q.ch), cap(q.ch)
}

// Close flushes the pending drop report.
func (q *upstreamQueue) Close() { q.agg.Stop() }
