// SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
// SPDX-License-Identifier: AGPL-3.0-or-later

package ws

import (
	"sync"
	"testing"
	"time"
)

// M10 (#215): "direct" follows the provenance of the link_state: only a relay that confirms ITSELF on its own
// link counts; a link_state relayed for a descendant by an intermediary, or a mere connection, never does.
func TestDirectLinkTimes_OnlyASelfReportedLinkStateCounts(t *testing.T) {
	resetRelayState()
	t.Cleanup(resetRelayState)
	kid := "AAAAAAAAAAAAAAAAAAAAAA" // 22 characters of the kid alphabet
	inter := &RelayConnection{RelayID: "inter", descendants: map[string]struct{}{"grand": {}}}

	// the intermediary reports for its descendant: not direct for "grand"
	handleLinkState(inter, RelayMessage{Type: MsgLinkState, RelayID: "grand", Seq: 1, CurrentKID: kid})
	if _, ok := DirectLinkTimes()["grand"]; ok {
		t.Fatal("a link_state relayed by an intermediary must not make the descendant direct")
	}
	// the intermediary reports for itself: direct
	handleLinkState(inter, RelayMessage{Type: MsgLinkState, RelayID: "inter", Seq: 1, CurrentKID: kid})
	at, ok := DirectLinkTimes()["inter"]
	if !ok || time.Since(at) > 5*time.Second {
		t.Fatalf("a self-reported link_state makes the relay direct: %v %v", at, ok)
	}
	// connecting alone is not a confirmation
	registerRelayConnection(&RelayConnection{RelayID: "silent"})
	t.Cleanup(func() { unregisterRelayConnection("silent") })
	if _, ok := DirectLinkTimes()["silent"]; ok {
		t.Fatal("a connection without a link_state must not count as direct")
	}
}

// M10: the LAST link_state decides — a relay that was direct and is then reported through an
// intermediary stops being direct.
func TestDirectLinkTimes_ALaterRelayedLinkStateClearsTheStamp(t *testing.T) {
	resetRelayState()
	t.Cleanup(resetRelayState)
	kid := "AAAAAAAAAAAAAAAAAAAAAA"
	child := &RelayConnection{RelayID: "child"}
	inter := &RelayConnection{RelayID: "inter", descendants: map[string]struct{}{"child": {}}}
	handleLinkState(child, RelayMessage{Type: MsgLinkState, RelayID: "child", Seq: 1, CurrentKID: kid})
	if _, ok := DirectLinkTimes()["child"]; !ok {
		t.Fatal("child confirmed itself: direct")
	}
	handleLinkState(inter, RelayMessage{Type: MsgLinkState, RelayID: "child", Seq: 2, CurrentKID: kid})
	if _, ok := DirectLinkTimes()["child"]; ok {
		t.Fatal("a later link_state relayed by an intermediary must clear the direct stamp")
	}
}

// B43: the confirmation and its provenance are stored under one lock. Concurrent link_state of the same
// relay, direct and relayed, must always leave a stamp that agrees with the LAST stored confirmation; the
// -race detector also covers the readers of the status.
func TestRecordLinkState_ProvenanceAndConfirmationAreAtomic(t *testing.T) {
	resetRelayState()
	t.Cleanup(resetRelayState)
	const kidD, kidR = "DDDDDDDDDDDDDDDDDDDDDD", "RRRRRRRRRRRRRRRRRRRRRR" // direct reports carry kidD, relayed ones kidR
	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Add(1)
	go func() { // reader: a stamp may only exist next to a confirmation that came directly
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			linkMu.RLock()
			st, okS := linkStates["x"]
			_, okD := directSeen["x"]
			linkMu.RUnlock()
			if okS && okD != (st.KID == kidD) {
				t.Errorf("stamp (%v) disagrees with the stored confirmation (kid %s)", okD, st.KID)
				return
			}
		}
	}()
	var writers sync.WaitGroup
	for w := 0; w < 4; w++ {
		writers.Add(1)
		go func(w int) {
			defer writers.Done()
			for i := 0; i < 2000; i++ {
				if (i+w)%2 == 0 {
					recordLinkState("x", uint64(i), kidD, provDirect)
				} else {
					recordLinkState("x", uint64(i), kidR, provRelayed)
				}
			}
		}(w)
	}
	writers.Wait()
	close(stop)
	wg.Wait()
}
