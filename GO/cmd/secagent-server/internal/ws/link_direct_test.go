package ws

import (
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
