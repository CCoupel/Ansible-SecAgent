// SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
// SPDX-License-Identifier: AGPL-3.0-or-later

package integration

import (
	"testing"
	"time"
)

// LOT-3.2 (#244 amended) — host.rerouted (one host, causes moved | direct | indirect) and relay.rerouted (one per
// relay moved by a reparent). Contract: planner-lot32 §T16 ; maquette relay_events__hooks_lifecycle §4-§6.
// RED on e0d1970: neither event exists. The "0 event" scenarios (3, 4) are GREEN by absence there: they are the
// guard against a false positive once dev-relay emits them.

const settle = 1500 * time.Millisecond

// twoRelays: root with the lot32 hooks and two pull children, each owning an enrollment of the same host "roamer"
// made while the child had no parent (a real enrollment is a host.new that would move routes during the test).
func twoRelaysWithRoamer(t *testing.T) (root, relayA, relayB *node, tokA, tokB string) {
	t.Helper()
	root = startNode(t, nodeSpec{ID: "root", Hooks: lot32Hooks})
	relayA = startNode(t, nodeSpec{ID: "relayA", Root: root})
	relayB = startNode(t, nodeSpec{ID: "relayB", Root: root})
	tokA, tokB = relayA.enrollAgent("roamer"), relayB.enrollAgent("roamer")
	relayA.linkTo(root)
	relayB.linkTo(root)
	waitFor(t, "relays linked", func() bool { return relayA.upstreamState() == "connected" && relayB.upstreamState() == "connected" })
	return
}

// (1) a host that leaves relayA and shows up behind relayB, nobody contesting: exactly ONE host.rerouted
// cause=moved, with the old and new chains and their origins; no host.conflict.
func TestHostRerouted_MovedWithoutContest_OneEventWithChains(t *testing.T) {
	parallel(t)
	root, relayA, relayB, tokA, tokB := twoRelaysWithRoamer(t)
	atA := connectMinionWithToken(t, relayA, "roamer", tokA)
	waitFor(t, "root routes roamer via relayA", func() bool { return root.hasHost("roamer") })
	waitFor(t, "first route: host.up", func() bool { return len(root.eventsOf("host.up", map[string]string{"host": "roamer"})) >= 1 })
	if got := len(root.eventsOf("host.rerouted", nil)); got != 0 {
		t.Fatalf("(4) first route: %d host.rerouted, want 0", got)
	}
	_ = atA.conn.Close()
	waitFor(t, "relayA no longer holds roamer", func() bool { return relayA.logs.count("Agent disconnected: hostname=roamer") >= 1 })
	agentListMark(root, "relayA")(t) // A's next agent_list reached the root: the claim has ended, nobody contests
	connectMinionWithToken(t, relayB, "roamer", tokB)

	want := map[string]string{"host": "roamer"}
	waitFor(t, "host.rerouted", func() bool { return len(root.eventsOf("host.rerouted", want)) >= 1 })
	quiet(t, root, "host.rerouted", want, settle)
	ev := root.eventsOf("host.rerouted", want)
	if len(ev) != 1 {
		t.Fatalf("%d host.rerouted for roamer, want exactly 1: %v", len(ev), ev)
	}
	e := ev[0]
	for k, v := range map[string]string{"cause": "moved", "old": "relayA", "new": "relayB", "oldc": "relayA", "newc": "relayB"} {
		if e[k] != v {
			t.Errorf("host.rerouted %s = %q, want %q (%v)", k, e[k], v, e)
		}
	}
	if got := len(root.eventsOf("host.conflict", nil)); got != 0 {
		t.Errorf("%d host.conflict on an uncontested move, want 0", got)
	}
}

// (2) + (4) a reparent seen by the ancestor: the relay r2 (and r3 below it) moves from under r1 to directly under the
// peer F. ONE relay.rerouted per relay moved, NO host.rerouted for the hosts behind them; the first declaration of the
// subtree raised nothing.
func TestRelayRerouted_ReparentGivesOneEventPerMovedRelay_NoHostRerouted(t *testing.T) {
	parallel(t)
	root := startNode(t, nodeSpec{ID: "root", Hooks: lot32Hooks})
	f := newFakeChild(t, root, "F")
	rel := func(id string, chain ...string) map[string]any {
		return map[string]any{"relay_id": id, "relay_chain": chain}
	}
	ag := func(host, relay string, chain ...string) map[string]any {
		return map[string]any{"hostname": host, "relay_id": relay, "relay_chain": chain}
	}
	f.snapshot(
		[]map[string]any{rel("r1", "F", "r1"), rel("r2", "F", "r1", "r2"), rel("r3", "F", "r1", "r2", "r3")},
		[]map[string]any{ag("under-r3-a", "r3", "F", "r1", "r2", "r3"), ag("under-r3-b", "r3", "F", "r1", "r2", "r3"), ag("under-r1", "r1", "F", "r1")},
	)
	waitFor(t, "the first subtree is routed", func() bool {
		return root.hasHost("under-r3-a") && root.hasHost("under-r3-b") && root.hasHost("under-r1")
	})
	time.Sleep(settle)
	if n, m := len(root.eventsOf("relay.rerouted", nil)), len(root.eventsOf("host.rerouted", nil)); n != 0 || m != 0 {
		t.Fatalf("(4) first declaration of the subtree: %d relay.rerouted / %d host.rerouted, want 0 / 0", n, m)
	}

	// r2 is re-attached directly under F (r1 stays); r3 follows r2.
	f.snapshot(
		[]map[string]any{rel("r1", "F", "r1"), rel("r2", "F", "r2"), rel("r3", "F", "r2", "r3")},
		[]map[string]any{ag("under-r3-a", "r3", "F", "r2", "r3"), ag("under-r3-b", "r3", "F", "r2", "r3"), ag("under-r1", "r1", "F", "r1")},
	)
	waitFor(t, "relay.rerouted for r2 and r3", func() bool { return len(root.eventsOf("relay.rerouted", nil)) >= 2 })
	quiet(t, root, "relay.rerouted", nil, settle)
	if got := len(root.eventsOf("relay.rerouted", nil)); got != 2 {
		t.Fatalf("%d relay.rerouted, want exactly 2 (r2 and r3)", got)
	}
	for _, c := range []struct{ id, oldc, newc, hr string }{
		{"r2", "F,r1,r2", "F,r2", "2"}, // hosts_routed: the hosts routed through this relay (the two behind r3)
		{"r3", "F,r1,r2,r3", "F,r2,r3", "2"},
	} {
		ev := root.eventsOf("relay.rerouted", map[string]string{"relay": c.id})
		if len(ev) != 1 {
			t.Errorf("relay.rerouted for %s: %d events, want 1", c.id, len(ev))
			continue
		}
		if ev[0]["oldc"] != c.oldc || ev[0]["newc"] != c.newc || ev[0]["hr"] != c.hr || ev[0]["host"] != "" {
			t.Errorf("relay.rerouted %s = %v, want oldc=%s newc=%s hr=%s and no hostname", c.id, ev[0], c.oldc, c.newc, c.hr)
		}
	}
	if len(root.eventsOf("relay.rerouted", map[string]string{"relay": "r1"})) != 0 {
		t.Errorf("r1 did not move: no relay.rerouted for it")
	}
	if got := len(root.eventsOf("host.rerouted", nil)); got != 0 {
		t.Errorf("a reparent produced %d host.rerouted, want 0 (one relay.rerouted per relay, never one event per host)", got)
	}
}

// (5) contested: relay FB claims a host that relay FA still owns. host.conflict, THEN host.rerouted, once each.
func TestHostRerouted_ContestedGivesConflictThenRerouted(t *testing.T) {
	parallel(t)
	root := startNode(t, nodeSpec{ID: "root", Hooks: lot32Hooks})
	fa := newFakeChild(t, root, "FA")
	fa.snapshot(nil, []map[string]any{{"hostname": "twin", "relay_id": "FA", "relay_chain": []string{"FA"}}})
	waitFor(t, "twin is routed via FA", func() bool { return root.hasHost("twin") })
	fb := newFakeChild(t, root, "FB")
	fb.event("host.up", "twin", "connected", "FB")

	want := map[string]string{"host": "twin"}
	waitFor(t, "host.conflict", func() bool { return len(root.eventsOf("host.conflict", want)) >= 1 })
	waitFor(t, "host.rerouted", func() bool { return len(root.eventsOf("host.rerouted", want)) >= 1 })
	time.Sleep(settle)
	if n, m := len(root.eventsOf("host.conflict", want)), len(root.eventsOf("host.rerouted", want)); n != 1 || m != 1 {
		t.Fatalf("%d host.conflict / %d host.rerouted for twin, want 1 / 1", n, m)
	}
	if c, r := root.firstIndex("host.conflict", want), root.firstIndex("host.rerouted", want); c >= r {
		t.Errorf("host.conflict must come BEFORE host.rerouted (lines %d, %d):\n%v", c, r, root.hookLines())
	}
	e := root.eventsOf("host.rerouted", want)[0]
	if e["cause"] != "moved" || e["old"] != "FA" || e["new"] != "FB" {
		t.Errorf("contested move: want cause=moved old=FA new=FB, got %v", e)
	}
}

// (5b) a host behind relay1 that reconnects to the root itself (direct), then goes back behind relay1 (indirect).
func TestHostRerouted_DirectThenIndirect(t *testing.T) {
	parallel(t)
	root := startNode(t, nodeSpec{ID: "root", Hooks: lot32Hooks})
	relay1 := startNode(t, nodeSpec{ID: "relay1", Root: root})
	tokRelay, tokRoot := relay1.enrollAgent("nomad"), root.enrollAgent("nomad")
	relay1.linkTo(root)
	waitFor(t, "relay1 linked", func() bool { return relay1.upstreamState() == "connected" })

	behind := connectMinionWithToken(t, relay1, "nomad", tokRelay)
	waitFor(t, "root routes nomad via relay1", func() bool { return root.hasHost("nomad") })
	waitFor(t, "first route: host.up", func() bool { return len(root.eventsOf("host.up", map[string]string{"host": "nomad"})) >= 1 })
	_ = behind.conn.Close()
	waitFor(t, "relay1 no longer holds nomad", func() bool { return relay1.logs.count("Agent disconnected: hostname=nomad") >= 1 })
	agentListMark(root, "relay1")(t) // relay1's agent_list without nomad reached the root

	local := connectMinionWithToken(t, root, "nomad", tokRoot) // direct
	want := map[string]string{"host": "nomad", "cause": "direct"}
	waitFor(t, "host.rerouted direct", func() bool { return len(root.eventsOf("host.rerouted", want)) >= 1 })
	if d := root.eventsOf("host.rerouted", want)[0]; d["oldc"] != "relay1" || d["newc"] != "root" || d["old"] != "relay1" || d["new"] != "root" {
		t.Errorf("direct: want oldc=relay1 newc=root old=relay1 new=root, got %v", d)
	}

	_ = local.conn.Close()
	waitFor(t, "the root no longer holds nomad", func() bool { return root.logs.count("Agent disconnected: hostname=nomad") >= 1 })
	connectMinionWithToken(t, relay1, "nomad", tokRelay) // indirect again
	want = map[string]string{"host": "nomad", "cause": "indirect"}
	waitFor(t, "host.rerouted indirect", func() bool { return len(root.eventsOf("host.rerouted", want)) >= 1 })
	if d := root.eventsOf("host.rerouted", want)[0]; d["new"] != "relay1" || d["newc"] != "relay1" {
		t.Errorf("indirect: want new=relay1 newc=relay1, got %v", d)
	}
	time.Sleep(settle)
	if n := len(root.eventsOf("host.rerouted", map[string]string{"host": "nomad", "cause": "direct"})); n != 1 {
		t.Errorf("%d direct events, want exactly 1", n)
	}
	if n := len(root.eventsOf("host.rerouted", map[string]string{"host": "nomad", "cause": "indirect"})); n != 1 {
		t.Errorf("%d indirect events, want exactly 1", n)
	}
	if n := len(root.eventsOf("host.rerouted", map[string]string{"host": "nomad", "cause": "moved"})); n != 0 {
		t.Errorf("%d moved events for a host that only alternated direct / indirect, want 0", n)
	}
}
