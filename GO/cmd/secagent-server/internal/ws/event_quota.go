// SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
// SPDX-License-Identifier: AGPL-3.0-or-later

package ws

// Rate limit of the `event_forward` messages by IDENTITY (#216): the quota (maxEventsPerSecond per
// second) belongs to the relay_id (the verified jwt.sub), not to the link, so a reconnection never
// resets it (the same defect #156 fixed for the topology snapshots). Memory only; a restart of the node
// forgets the counters, which only gives the children a fresh window. The table is bounded and purged
// by activity, never swept.

import (
	"log"
	"sync"
	"time"

	"secagent-server/cmd/secagent-server/internal/dropreport"
)

// eventRejectReportInterval is the period of the aggregated "quota exceeded" log: ONE line per
// identity and per period, never one per refused event (#246).
const eventRejectReportInterval = time.Minute

var (
	eventRejectMu  sync.Mutex
	eventRejects   = map[string]int64{} // identity -> events refused since the last report
	eventRejectAgg = dropreport.New(eventRejectReportInterval, flushEventRejects)
)

// noteEventRejected counts an event_forward refused by the quota; the log comes once per period.
func noteEventRejected(relayID string) {
	eventRejectMu.Lock()
	if _, known := eventRejects[relayID]; known || len(eventRejects) < maxQuotaEntries {
		eventRejects[relayID]++
	}
	eventRejectMu.Unlock()
	eventRejectAgg.Add(1)
}

func flushEventRejects(int64) {
	eventRejectMu.Lock()
	rejects := eventRejects
	eventRejects = map[string]int64{}
	eventRejectMu.Unlock()
	for id, n := range rejects {
		log.Printf("[RELAY] event_forward rate limit exceeded: relay_id=%q, %d event(s) dropped in the last minute", id, n)
	}
}

// The event_forward quota is a TOKEN BUCKET per identity (#216, #246): the sustained rate is
// maxEventsPerSecond, and a burst of up to eventQuotaBurst events is accepted after a quiet moment.
// A fixed one-second window refused events when a stalled parent caught up on frames that a child had
// sent at a perfectly regular, lower rate; the bucket only looks at the average, so a pause of up to
// eventQuotaBurst/maxEventsPerSecond seconds costs nothing. There is no exemption (a replay counts like
// any event) and the memory is O(1) per identity (two numbers).
const (
	// eventQuotaBurst is the bucket capacity: 2 seconds of the sustained rate.
	eventQuotaBurst = 2 * maxEventsPerSecond
	// eventQuotaFullAfter is the idle time after which a bucket is full again (its entry can be forgotten).
	eventQuotaFullAfter = eventQuotaBurst / maxEventsPerSecond * time.Second
)

type eventQuota struct {
	tokens float64   // available events
	last   time.Time // instant tokens was computed at
}

var (
	eventQuotaMu     sync.Mutex
	eventQuotas      = map[string]*eventQuota{}
	eventQuotaPurged time.Time
)

// purgeEventQuotaLocked drops the identities idle long enough for their bucket to be full again (a new
// entry starts full anyway). Runs at most once per second.
func purgeEventQuotaLocked(now time.Time) {
	if now.Sub(eventQuotaPurged) < time.Second {
		return
	}
	eventQuotaPurged = now
	for id, q := range eventQuotas {
		if now.Sub(q.last) >= eventQuotaFullAfter {
			delete(eventQuotas, id)
		}
	}
}

// evictEventQuotaLocked makes room for a NEW identity: only an insertion may push an entry out (B41), a
// call for an identity already in the table never gives another relay a fresh bucket.
func evictEventQuotaLocked() {
	for len(eventQuotas) >= maxQuotaEntries {
		var oldest string
		var ot time.Time
		for id, q := range eventQuotas {
			if oldest == "" || q.last.Before(ot) {
				oldest, ot = id, q.last
			}
		}
		delete(eventQuotas, oldest)
	}
}

// allowEvent takes one token of the identity's bucket and reports whether the event is within the quota.
func allowEvent(relayID string, now time.Time) bool {
	eventQuotaMu.Lock()
	defer eventQuotaMu.Unlock()
	purgeEventQuotaLocked(now)
	q := eventQuotas[relayID]
	if q == nil {
		evictEventQuotaLocked()
		q = &eventQuota{tokens: eventQuotaBurst, last: now}
		eventQuotas[relayID] = q
	} else if d := now.Sub(q.last); d > 0 {
		q.tokens = min(eventQuotaBurst, q.tokens+d.Seconds()*maxEventsPerSecond)
		q.last = now
	}
	if q.tokens < 1 {
		return false
	}
	q.tokens--
	return true
}

func eventQuotaEntries() int {
	eventQuotaMu.Lock()
	defer eventQuotaMu.Unlock()
	return len(eventQuotas)
}
