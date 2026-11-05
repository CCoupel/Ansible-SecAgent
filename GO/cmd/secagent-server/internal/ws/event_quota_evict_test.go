// SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
// SPDX-License-Identifier: AGPL-3.0-or-later

package ws

import (
	"fmt"
	"testing"
	"time"
)

// B41 (#216): with a full table, a call for an identity already present never evicts another one; only
// the insertion of a NEW identity pushes the oldest out.
func TestEventQuota_OnlyANewIdentityEvicts(t *testing.T) {
	resetRelayState()
	t.Cleanup(resetRelayState)
	now := time.Now()
	for i := 0; i < maxQuotaEntries; i++ {
		allowEvent(fmt.Sprintf("relay-%05d", i), now.Add(time.Duration(i)*time.Microsecond))
	}
	if n := eventQuotaEntries(); n != maxQuotaEntries {
		t.Fatalf("entries = %d, want %d", n, maxQuotaEntries)
	}
	allowEvent("relay-00007", now.Add(time.Millisecond)) // existing identity
	if n := eventQuotaEntries(); n != maxQuotaEntries {
		t.Fatalf("a call for a known identity changed the table: %d", n)
	}
	eventQuotaMu.Lock()
	_, oldestKept := eventQuotas["relay-00000"]
	eventQuotaMu.Unlock()
	if !oldestKept {
		t.Fatal("a call for a known identity evicted another one")
	}
	allowEvent("relay-new", now.Add(2*time.Millisecond)) // a new identity pushes the oldest out
	eventQuotaMu.Lock()
	_, oldestKept = eventQuotas["relay-00000"]
	_, newIn := eventQuotas["relay-new"]
	n := len(eventQuotas)
	eventQuotaMu.Unlock()
	if oldestKept || !newIn || n > maxQuotaEntries {
		t.Fatalf("after a new insertion: oldest kept=%v new in=%v entries=%d", oldestKept, newIn, n)
	}
}
