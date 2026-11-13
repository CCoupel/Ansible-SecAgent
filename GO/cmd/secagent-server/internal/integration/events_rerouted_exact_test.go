// SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
// SPDX-License-Identifier: AGPL-3.0-or-later

package integration

import (
	"testing"
	"time"
)

// LOT-3.2, code review (_work/reports/code-reviewer-lot32-v3.0.6-20261111.md) — EXACT counts of host.rerouted per node on
// three levels (MAJEUR-1) and relay.rerouted on a real reparent, in both orders of arrival (MAJEUR-2).

// agentListMark returns a function that waits until `parent` has processed TWO MORE agent_lists of `child` than when
// agentListMark was called (call it AFTER the child logged the change: the first one may have been in flight before it): the state the parent holds after the child's change is then settled (no fixed sleep).
func agentListMark(parent *node, child string) func(t *testing.T) {
	key := "agent_list: relay_id=" + child
	base := parent.logs.count(key)
	return func(t *testing.T) {
		t.Helper()
		waitFor(t, parent.id+" processed an agent_list of "+child, func() bool { return parent.logs.count(key) >= base+2 })
	}
}

// (MAJEUR-1) three levels, a host goes from a grandchild to the child: cause=direct, EXACTLY one host.rerouted per node
// that sees it (the child that receives the host, the root above), none at the grandchild that lost it.
func TestHostRerouted_ThreeLevels_GrandchildToChildIsDirectExactlyOncePerNode(t *testing.T) {
	parallel(t)
	root := startNode(t, nodeSpec{ID: "root", Hooks: lot32Hooks})
	q := startNode(t, nodeSpec{ID: "Q", Root: root, Hooks: lot32Hooks})
	r := startNode(t, nodeSpec{ID: "R", Root: root, Hooks: lot32Hooks})
	tokQ, tokR := q.enrollAgent("mover"), r.enrollAgent("mover")
	q.linkTo(root)
	waitFor(t, "Q linked", func() bool { return q.upstreamState() == "connected" })
	r.linkTo(q)
	waitFor(t, "R linked", func() bool { return r.upstreamState() == "connected" })

	atR := connectMinionWithToken(t, r, "mover", tokR)
	waitFor(t, "the root routes mover", func() bool { return root.hasHost("mover") })
	_ = atR.conn.Close()
	waitFor(t, "R released mover", func() bool { return r.logs.count("Agent disconnected: hostname=mover") >= 1 })
	agentListMark(q, "R")(t)
	agentListMark(root, "Q")(t)
	connectMinionWithToken(t, q, "mover", tokQ) // direct at Q

	want := map[string]string{"host": "mover", "cause": "direct"}
	for _, n := range []*node{q, root} {
		n := n
		waitFor(t, n.id+": host.rerouted direct", func() bool { return len(n.eventsOf("host.rerouted", want)) >= 1 })
	}
	time.Sleep(settle)
	for _, n := range []*node{q, root} {
		if ev := n.eventsOf("host.rerouted", map[string]string{"host": "mover"}); len(ev) != 1 || ev[0]["cause"] != "direct" {
			t.Errorf("%s: %d host.rerouted for mover (want exactly 1, cause=direct): %v", n.id, len(ev), ev)
		}
	}
	if got := len(r.eventsOf("host.rerouted", nil)); got != 0 {
		t.Errorf("R (the grandchild that lost the host) emitted %d host.rerouted, want 0", got)
	}
}

// reparentTree: P with the fake peer dmz1 declaring its child relay dmz2 ([dmz1,dmz2]) and one host behind it.
func reparentTree(t *testing.T) (root *node, dmz1 *fakeChild) {
	t.Helper()
	root = startNode(t, nodeSpec{ID: "root", Hooks: lot32Hooks})
	dmz1 = newFakeChild(t, root, "dmz1")
	dmz1.snapshot(
		[]map[string]any{{"relay_id": "dmz2", "relay_chain": []string{"dmz1", "dmz2"}}},
		[]map[string]any{{"hostname": "behind-dmz2", "relay_id": "dmz2", "relay_chain": []string{"dmz1", "dmz2"}}},
	)
	waitFor(t, "dmz2's subtree is routed via dmz1", func() bool { return root.hasHost("behind-dmz2") })
	return
}

func assertOneRelayRerouted(t *testing.T, root *node) {
	t.Helper()
	waitFor(t, "relay.rerouted for dmz2", func() bool { return len(root.eventsOf("relay.rerouted", map[string]string{"relay": "dmz2"})) >= 1 })
	time.Sleep(settle)
	ev := root.eventsOf("relay.rerouted", nil)
	if len(ev) != 1 || ev[0]["relay"] != "dmz2" || ev[0]["oldc"] != "dmz1,dmz2" || ev[0]["newc"] != "dmz2" {
		t.Errorf("want exactly one relay.rerouted for dmz2 (oldc=dmz1,dmz2 newc=dmz2), got %v", ev)
	}
	if got := len(root.eventsOf("host.rerouted", nil)); got != 0 {
		t.Errorf("a reparent produced %d host.rerouted, want 0", got)
	}
}

// (MAJEUR-2) real reparent, order 1: the OLD parent withdraws dmz2 from its snapshot BEFORE the new link exists, then
// dmz2 connects to the root. Exactly one relay.rerouted (the withdrawal must not make dmz2 look like a first route).
func TestRelayRerouted_ReparentOldParentWithdrawsBeforeTheNewLink_ExactlyOne(t *testing.T) {
	parallel(t)
	root, dmz1 := reparentTree(t)
	if !dmz1.snapshotAcked() { // dmz1's replacement snapshot: no dmz2 any more
		t.Fatal("the root refused the withdrawal snapshot of dmz1")
	}
	newFakeChild(t, root, "dmz2") // dmz2 re-pointed to the root: its own link
	assertOneRelayRerouted(t, root)
}
