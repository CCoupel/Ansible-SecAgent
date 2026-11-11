// SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
// SPDX-License-Identifier: AGPL-3.0-or-later

package ws

import (
	"fmt"
	"testing"
	"time"
)

func resetEventQuota(t *testing.T) {
	t.Helper()
	eventQuotaMu.Lock()
	eventQuotas = map[string]*eventQuota{}
	eventQuotaPurged = time.Time{}
	eventQuotaMu.Unlock()
}

// The sustained rate of the quota (200/s) is accepted without any refusal, however it is phased.
func TestEventBucket_SustainedQuotaRateIsNeverRefused(t *testing.T) {
	resetEventQuota(t)
	t0 := time.Unix(1_000_000, 0)
	step := time.Second / maxEventsPerSecond
	for i := 0; i < 10*maxEventsPerSecond; i++ {
		if !allowEvent("steady", t0.Add(time.Duration(i)*step)) {
			t.Fatalf("event %d refused at the sustained rate", i)
		}
	}
}

// After a silence a burst of the bucket capacity is accepted, the next event is refused.
func TestEventBucket_BurstAfterSilenceThenRefusal(t *testing.T) {
	resetEventQuota(t)
	t0 := time.Unix(1_000_000, 0)
	allowEvent("burst", t0)
	now := t0.Add(10 * time.Second) // long silence: the bucket is full
	for i := 0; i < eventQuotaBurst; i++ {
		if !allowEvent("burst", now) {
			t.Fatalf("event %d of the burst refused (capacity %d)", i+1, eventQuotaBurst)
		}
	}
	if allowEvent("burst", now) {
		t.Fatalf("event %d accepted: over the bucket capacity", eventQuotaBurst+1)
	}
}

// 1 000 events/s for 10 s: the accepted average is the quota rate, plus the bucket once.
func TestEventBucket_FloodIsLimitedToTheQuotaRate(t *testing.T) {
	resetEventQuota(t)
	t0 := time.Unix(1_000_000, 0)
	accepted := 0
	for i := 0; i < 10_000; i++ {
		if allowEvent("flood", t0.Add(time.Duration(i)*time.Millisecond)) {
			accepted++
		}
	}
	max := 10*maxEventsPerSecond + eventQuotaBurst
	if accepted > max || accepted < 10*maxEventsPerSecond-5 {
		t.Errorf("accepted %d of 10000 over 10 s, want about %d (rate) up to %d (rate + bucket)", accepted, 10*maxEventsPerSecond, max)
	}
}

// A stall followed by a catch-up burst inside the bucket is not refused (the fixed-window defect).
func TestEventBucket_CatchUpAfterAStallIsAccepted(t *testing.T) {
	resetEventQuota(t)
	t0 := time.Unix(1_000_000, 0)
	for i := 0; i < 150; i++ { // sender at 150/s for a second
		allowEvent("stall", t0.Add(time.Duration(i)*time.Second/150))
	}
	// the receiver stalled 1.5 s: 225 frames read back to back
	now := t0.Add(2500 * time.Millisecond)
	for i := 0; i < 225; i++ {
		if !allowEvent("stall", now) {
			t.Fatalf("catch-up event %d refused", i)
		}
	}
}

func TestEventBucket_IdentitiesAreIndependentAndTheTableIsBounded(t *testing.T) {
	resetEventQuota(t)
	now := time.Unix(1_000_000, 0)
	for i := 0; i < eventQuotaBurst; i++ {
		allowEvent("a", now)
	}
	if allowEvent("a", now) {
		t.Fatal("a must be exhausted")
	}
	if !allowEvent("b", now) {
		t.Fatal("b must not be affected by a")
	}
	for i := 0; i < maxQuotaEntries+50; i++ {
		allowEvent(fmt.Sprintf("relay-%05d", i), now.Add(time.Duration(i)*time.Microsecond))
	}
	if n := eventQuotaEntries(); n > maxQuotaEntries {
		t.Errorf("%d entries, bound %d", n, maxQuotaEntries)
	}
}

// An identity that was refused is not served again by being pushed out of the table by others'
// idle entries: a full-again (idle) bucket is the only thing the purge forgets.
func TestEventBucket_PurgeForgetsOnlyIdleBuckets(t *testing.T) {
	resetEventQuota(t)
	t0 := time.Unix(1_000_000, 0)
	for i := 0; i < eventQuotaBurst; i++ {
		allowEvent("busy", t0)
	}
	allowEvent("idle", t0)
	now := t0.Add(1500 * time.Millisecond) // < 2 s: nobody is full again
	allowEvent("trigger", now)
	if _, ok := eventQuotas["busy"]; !ok {
		t.Error("busy forgotten before its bucket refilled")
	}
	now = t0.Add(3 * time.Second)
	allowEvent("trigger", now)
	if _, ok := eventQuotas["idle"]; ok {
		t.Error("idle bucket (full again) must be forgotten")
	}
}
