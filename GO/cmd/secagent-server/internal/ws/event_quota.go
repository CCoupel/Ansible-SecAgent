package ws

// Rate limit of the `event_forward` messages by IDENTITY (#216): the quota (maxEventsPerSecond per
// second) belongs to the relay_id (the verified jwt.sub), not to the link, so a reconnection never
// resets it (the same defect #156 fixed for the topology snapshots). Memory only; a restart of the node
// forgets the counters, which only gives the children a fresh window. The table is bounded and purged
// by activity, never swept.

import (
	"sync"
	"time"
)

// eventQuotaWindow is the length of the counting window.
const eventQuotaWindow = time.Second

type eventQuota struct {
	start time.Time
	count int
}

var (
	eventQuotaMu     sync.Mutex
	eventQuotas      = map[string]*eventQuota{}
	eventQuotaPurged time.Time
)

// purgeEventQuotaLocked drops the identities whose window is over (their counter restarts at zero anyway).
// Runs at most once per window, or when the table is full (then the oldest windows are evicted).
func purgeEventQuotaLocked(now time.Time) {
	if now.Sub(eventQuotaPurged) < eventQuotaWindow && len(eventQuotas) < maxQuotaEntries {
		return
	}
	eventQuotaPurged = now
	for id, q := range eventQuotas {
		if now.Sub(q.start) >= eventQuotaWindow {
			delete(eventQuotas, id)
		}
	}
	for len(eventQuotas) >= maxQuotaEntries {
		var oldest string
		var ot time.Time
		for id, q := range eventQuotas {
			if oldest == "" || q.start.Before(ot) {
				oldest, ot = id, q.start
			}
		}
		delete(eventQuotas, oldest)
	}
}

// allowEvent counts one event_forward of the identity and reports whether it is within the quota.
func allowEvent(relayID string, now time.Time) bool {
	eventQuotaMu.Lock()
	defer eventQuotaMu.Unlock()
	purgeEventQuotaLocked(now)
	q := eventQuotas[relayID]
	if q == nil || now.Sub(q.start) >= eventQuotaWindow {
		q = &eventQuota{start: now}
		eventQuotas[relayID] = q
	}
	q.count++
	return q.count <= maxEventsPerSecond
}

func eventQuotaEntries() int {
	eventQuotaMu.Lock()
	defer eventQuotaMu.Unlock()
	return len(eventQuotas)
}
