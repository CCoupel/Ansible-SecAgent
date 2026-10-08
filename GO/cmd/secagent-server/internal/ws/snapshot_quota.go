package ws

// Rate limit of the topology snapshots by IDENTITY (#156, L4): the quota belongs to the relay_id (the
// verified jwt.sub), not to the link, so a reconnection never resets it. Every snapshot counts, the first
// of a link included. Memory only (nothing in relay.state): a restart of the node forgets the counters,
// which only gives the children a fresh window.

import (
	"log"
	"sync"
	"time"
)

// maxQuotaEntries bounds the table (identities are only created for authenticated relays); beyond it the
// oldest window is evicted.
const maxQuotaEntries = 4096

type snapQuota struct {
	start time.Time // start of the current window
	count int
}

var (
	snapQuotaMu sync.Mutex
	snapQuotas  = map[string]*snapQuota{}
	snapPurged  time.Time
)

// purgeSnapQuotaLocked drops the identities whose window is over (their counter would restart at zero
// anyway). Runs at most once per window.
func purgeSnapQuotaLocked(now time.Time) {
	if now.Sub(snapPurged) < snapshotReplaceWindow && len(snapQuotas) < maxQuotaEntries {
		return
	}
	snapPurged = now
	for id, q := range snapQuotas {
		if now.Sub(q.start) >= snapshotReplaceWindow {
			delete(snapQuotas, id)
		}
	}
	for len(snapQuotas) >= maxQuotaEntries { // still full: evict the oldest window
		var oldest string
		var ot time.Time
		for id, q := range snapQuotas {
			if oldest == "" || q.start.Before(ot) {
				oldest, ot = id, q.start
			}
		}
		delete(snapQuotas, oldest)
	}
}

// allowSnapshot counts one snapshot of the identity and reports whether it is within the quota.
func allowSnapshot(relayID string, now time.Time) bool {
	snapQuotaMu.Lock()
	defer snapQuotaMu.Unlock()
	purgeSnapQuotaLocked(now)
	q := snapQuotas[relayID]
	if q == nil || now.Sub(q.start) >= snapshotReplaceWindow {
		q = &snapQuota{start: now}
		snapQuotas[relayID] = q
	}
	q.count++
	return q.count <= snapshotReplaceLimit
}

// snapshotQuotaExhausted reports, without counting, that the identity has spent its quota in the
// current window (the handshake refuses it before any snapshot).
func snapshotQuotaExhausted(relayID string, now time.Time) bool {
	snapQuotaMu.Lock()
	defer snapQuotaMu.Unlock()
	q := snapQuotas[relayID]
	return q != nil && now.Sub(q.start) < snapshotReplaceWindow && q.count >= snapshotReplaceLimit
}

func snapshotQuotaEntries() int {
	snapQuotaMu.Lock()
	defer snapQuotaMu.Unlock()
	return len(snapQuotas)
}

func logSnapshotQuota(relayID string) {
	log.Printf("[SECURITY WARNING] topology_snapshot rate limit exceeded: relay_id=%q (> %d per %s)", relayID, snapshotReplaceLimit, snapshotReplaceWindow)
}
