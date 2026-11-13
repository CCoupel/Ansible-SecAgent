// SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
// SPDX-License-Identifier: AGPL-3.0-or-later

package integration

import (
	"testing"
	"time"
)

// #244 (QUALIF relay-rerouted, 3 levels): when dmz2 is re-pointed from dmz1 to the root, the host behind dmz2
// keeps the same carrier (dmz2): the reparent is ONE relay.rerouted at the root and NO host.rerouted anywhere,
// whichever of the new link's snapshot or the host's host.up reaches the root first.
func TestReparent_ThreeLevels_OneRelayReroutedAndNoHostRerouted(t *testing.T) {
	parallel(t)
	root := startNode(t, nodeSpec{ID: "root", Hooks: lot32Hooks})
	dmz1 := startNode(t, nodeSpec{ID: "dmz1", Root: root, Hooks: lot32Hooks})
	dmz2 := startNode(t, nodeSpec{ID: "dmz2", Root: root, Hooks: lot32Hooks})
	tok := dmz2.enrollAgent("minion-grand")
	dmz1.linkTo(root)
	waitFor(t, "dmz1 linked", func() bool { return dmz1.upstreamState() == "connected" })
	dmz2.linkTo(dmz1)
	waitFor(t, "dmz2 linked under dmz1", func() bool { return dmz2.upstreamState() == "connected" })
	connectMinionWithToken(t, dmz2, "minion-grand", tok)
	waitFor(t, "the root routes minion-grand", func() bool { return root.hasHost("minion-grand") })
	time.Sleep(settle)
	for _, n := range []*node{root, dmz1, dmz2} {
		if got := len(n.eventsOf("host.rerouted", nil)) + len(n.eventsOf("relay.rerouted", nil)); got != 0 {
			t.Fatalf("%s: %d rerouted event(s) before the reparent, want 0 (first routes)", n.id, got)
		}
	}

	dmz2.linkTo(root) // reparent: dmz2 now hangs directly under the root
	waitFor(t, "dmz2 linked under the root", func() bool { return dmz2.upstreamState() == "connected" })
	connectMinionWithToken(t, dmz2, "minion-grand", tok) // the host reconnects to its (restarted) relay
	waitFor(t, "relay.rerouted for dmz2 at the root", func() bool { return len(root.eventsOf("relay.rerouted", map[string]string{"relay": "dmz2"})) >= 1 })
	time.Sleep(2 * settle)
	if got := len(root.eventsOf("relay.rerouted", nil)); got != 1 {
		t.Errorf("root: %d relay.rerouted, want exactly 1: %v", got, root.eventsOf("relay.rerouted", nil))
	}
	for _, n := range []*node{root, dmz1, dmz2} {
		if got := n.eventsOf("host.rerouted", nil); len(got) != 0 {
			t.Errorf("%s: %d host.rerouted after a reparent (the carrier dmz2 did not change), want 0: %v", n.id, len(got), got)
		}
	}
	e := root.eventsOf("relay.rerouted", map[string]string{"relay": "dmz2"})[0]
	if e["oldc"] != "dmz1,dmz2" || e["newc"] != "dmz2" {
		t.Errorf("relay.rerouted = %v, want oldc=dmz1,dmz2 newc=dmz2", e)
	}
}
