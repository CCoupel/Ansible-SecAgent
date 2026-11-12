// SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build slow

// LOT-3.2 tests moved out of the fast suite so that the package stays under the CI timeout (go test -race, 5 min):
// the fast suite keeps at least one short case per feature, these variants add depth. Run with `-tags slow`.

package integration

import (
	"strings"
	"testing"
	"time"
)

// The scenario with the long wait of the fast TwoChildren test: > RELAY_CONVERGENCE_TIMEOUT (5s), no second event.
func TestRelayConverged_TwoChildrenBack_NeverReemittedAfterTheTimeout(t *testing.T) {
	twoChildrenBack(t, 7*time.Second)
}

// The same full-queue scenario, waiting for the aggregated report (once per minute): ONE [WARN], ONE journal entry.
func TestUpstreamQueue_FullQueue_OneWarnOneJournalEntry(t *testing.T) {
	fullQueue(t, true)
}

func TestOwnHostEvents_PushChildReplaysThemAfterTheCut(t *testing.T) { testOwnHostsReplayed(t, "push") }

// (8) one declared child never comes back: relay.converged at the timeout, relays_missing=1.
func TestRelayConverged_AbsentChildGivesEventAtTheTimeoutWithMissingOne(t *testing.T) {
	parallel(t)
	a, b := convergedPair(t, []string{"relay1", "relay2"}, 1) // relay2 declared, never started
	before := len(b.eventsOf("relay.converged", ownConverged))
	switchOver(t, a, b)
	t0 := time.Now()

	waitFor(t, "relay.converged at the timeout", func() bool { return len(b.eventsOf("relay.converged", ownConverged)) == before+1 })
	if d := time.Since(t0); d < 3*time.Second {
		t.Errorf("relay.converged after %s with one child missing: it must wait for RELAY_CONVERGENCE_TIMEOUT (5s)", d)
	}
	all := b.eventsOf("relay.converged", ownConverged)
	e := all[len(all)-1]
	if e["rc"] != "1" || e["rm"] != "1" {
		t.Errorf("relay.converged counts: want rc=1 rm=1, got %v", e)
	}
	// the late child does not make a second event
	time.Sleep(7 * time.Second)
	if got := len(b.eventsOf("relay.converged", ownConverged)); got != before+1 {
		t.Errorf("%d relay.converged, want %d (never re-emitted)", got, before+1)
	}
}

// (7) two levels: the host.rerouted decided below travels up and runs the hooks of every ancestor EXACTLY once per node
// (the root must not count it twice: once forwarded by mid, once decided by its own route memory).
func TestHostRerouted_PropagatesUpTwoLevels_ExactlyOncePerNode(t *testing.T) {
	parallel(t)
	root, mid, leafA, leafB := threeLevelTree(t, "trav")
	tokA, tokB := leafA.enrolled["trav"], leafB.enrolled["trav"]
	a := connectMinionWithToken(t, leafA.node, "trav", tokA)
	waitFor(t, "root routes trav", func() bool { return root.hasHost("trav") })
	_ = a.conn.Close()
	waitFor(t, "leafA released trav", func() bool { return leafA.logs.count("Agent disconnected: hostname=trav") >= 1 })
	agentListMark(mid, "leafA")(t)
	agentListMark(root, "mid")(t)
	connectMinionWithToken(t, leafB.node, "trav", tokB)

	want := map[string]string{"host": "trav", "cause": "moved"}
	for _, n := range []*node{mid, root} {
		n := n
		waitFor(t, n.id+": host.rerouted", func() bool { return len(n.eventsOf("host.rerouted", want)) >= 1 })
	}
	time.Sleep(settle)
	for _, n := range []*node{mid, root} {
		ev := n.eventsOf("host.rerouted", want)
		if len(ev) != 1 {
			t.Fatalf("%s: %d host.rerouted for trav, want exactly 1: %v", n.id, len(ev), ev)
		}
		if e := ev[0]; e["old"] != "leafA" || e["new"] != "leafB" || e["oldc"] == "" || e["newc"] == "" {
			t.Errorf("%s: host.rerouted must carry old=leafA new=leafB and both chains, got %v", n.id, e)
		}
	}
	if got := len(leafA.eventsOf("host.rerouted", nil)) + len(leafB.eventsOf("host.rerouted", nil)); got != 0 {
		t.Errorf("the leaves emitted %d host.rerouted, want 0 (they never saw the move)", got)
	}
}

// (3) fail-over a -> b: the routes are rebuilt from the child's snapshot, nothing moved: 0 host.rerouted, 0 relay.rerouted.
func TestRerouted_RootFailoverGivesNoRerouteEvent(t *testing.T) {
	parallel(t)
	addrA, addrB := newNodeAddrs(t), newNodeAddrs(t)
	a := startNode(t, nodeSpec{ID: "root", Env: addrA.env(), Hooks: lot32Hooks})
	tok := a.registerChild("relay1")
	b := a.sibling()
	b.launchSecondary(addrB.env())
	t.Cleanup(b.stop)
	waitFor(t, "the standby polls the lock", b.localStatusPolled)
	child := startNode(t, nodeSpec{ID: "relay1", ParentURL: "wss://" + addrA.ws + ",wss://" + addrB.ws, ParentToken: tok})
	waitFor(t, "the child is linked to the active root", func() bool { return child.upstreamState() == "connected" })
	connectMinion(t, child, "leaf-host")
	waitFor(t, "the master routes the leaf", func() bool { return a.hasHost("leaf-host") })

	a.killNow()
	if !b.awaitPromotion(30 * time.Second) {
		t.Fatalf("the passive root never took over; logs:\n%s", b.logs.String())
	}
	waitFor(t, "the new master routes the leaf again", func() bool { return b.hasHost("leaf-host") })
	waitFor(t, "the child reconnected (relay.reconnect)", func() bool { return len(b.eventsOf("relay.reconnect", map[string]string{"relay": "relay1"})) >= 1 })
	time.Sleep(settle)
	if n, m := len(b.eventsOf("host.rerouted", nil)), len(b.eventsOf("relay.rerouted", nil)); n != 0 || m != 0 {
		t.Errorf("fail-over: %d host.rerouted / %d relay.rerouted, want 0 / 0 (volatile routes, no known chain)", n, m)
	}
}

// (MAJEUR-2) order 2: the NEW link exists first, the old parent's withdrawal arrives afterwards: still exactly one.
func TestRelayRerouted_ReparentNewLinkBeforeTheOldParentWithdraws_ExactlyOne(t *testing.T) {
	parallel(t)
	root, dmz1 := reparentTree(t)
	newFakeChild(t, root, "dmz2")
	waitFor(t, "relay.rerouted for the new link", func() bool { return len(root.eventsOf("relay.rerouted", map[string]string{"relay": "dmz2"})) >= 1 })
	if !dmz1.snapshotAcked() {
		t.Fatal("the root refused the withdrawal snapshot of dmz1")
	}
	assertOneRelayRerouted(t, root)
}

// (10) #247: a brutal stop of the master (kill -9) while a direct agent dies during the window: NO host.down anywhere
// (documented loss, option A), and the agent that is still alive comes back as host.reconnect.
func TestFailoverLosses_BrutalStopGivesNoHostDownForAnAgentLostInTheWindow(t *testing.T) {
	parallel(t)
	addrA, addrB := newNodeAddrs(t), newNodeAddrs(t)
	a := startNode(t, nodeSpec{ID: "root", Env: addrA.env(), Hooks: lot32Hooks})
	b := a.sibling()
	b.launchSecondary(addrB.env())
	t.Cleanup(b.stop)
	waitFor(t, "the standby polls the lock", b.localStatusPolled)

	tokAlive, tokDead := a.enrollAgent("alive-host"), a.enrollAgent("dead-host")
	connectMinionWithToken(t, a, "alive-host", tokAlive)
	dead := connectMinionWithToken(t, a, "dead-host", tokDead)
	waitFor(t, "host.up of both", func() bool { return len(a.eventsOf("host.up", nil)) >= 2 })

	a.killNow()
	_ = dead.conn.Close() // the agent dies during the window: nobody is there to say host.down
	if !b.awaitPromotion(30 * time.Second) {
		t.Fatalf("the passive root never took over; logs:\n%s", b.logs.String())
	}
	seq := "2"
	dialAgentSeq(t, b, tokAlive, &seq) // the live agent reconnects to the new master
	waitFor(t, "host.reconnect of the live agent", func() bool { return len(b.eventsOf("host.reconnect", map[string]string{"host": "alive-host"})) >= 1 })
	time.Sleep(settle)
	if got := len(b.eventsOf("host.down", nil)); got != 0 {
		t.Errorf("%d host.down after a brutal stop, want 0 (nobody can tell the agent lost in the window is gone):\n%s", got, strings.Join(b.hookLines(), "\n"))
	}
}

// (T22) same for a PUSH child (serveParentLink): the parent that dials it sees peer_closed:1001 when it stops in order.
func TestRelayDown_OrderlyStopOfAPushChildIsPeerClosed1001(t *testing.T) {
	parallel(t)
	root := startNode(t, nodeSpec{ID: "root", Hooks: lot32Hooks})
	relay1 := startNode(t, nodeSpec{ID: "relay1", Root: root})
	linkPush(t, root, relay1)
	waitFor(t, "relay.up (push)", func() bool { return len(root.eventsOf("relay.up", map[string]string{"relay": "relay1"})) == 1 })
	relay1.stop()
	waitFor(t, "relay.down (push)", func() bool { return len(root.eventsOf("relay.down", map[string]string{"relay": "relay1"})) >= 1 })
	if e := root.eventsOf("relay.down", map[string]string{"relay": "relay1"})[0]; e["reason"] != "peer_closed:1001" {
		t.Errorf("relay.down of an orderly push child stop: reason = %q, want peer_closed:1001", e["reason"])
	}
}

// Queue forced to 256: the loss is exact and counted.
func TestOwnHostEvents_FullQueueLossIsExactAndCounted(t *testing.T) {
	if testing.Short() {
		t.Skip("replay")
	}
	parallel(t)
	root, child, tokens := ownHostsTree(t, "pull", "RELAY_UPSTREAM_QUEUE_SIZE=256")
	before := ownCount(root)
	cutAndBack(t, root, child, func() { produceOwn(t, child, tokens) })
	produced := ownCount(child)
	want := produced - 256
	waitFor(t, "the counter reaches the exact loss", func() bool {
		v, _ := child.statusField("upstream_dropped_events")
		return int(v) == want
	})
	rootBack(t, root, child, "pull")
	waitFor(t, "the 256 queued events are replayed", func() bool { return ownCount(root)-before >= 256 })
	time.Sleep(settle)
	if got := ownCount(root) - before; got != 256 {
		t.Errorf("the root received %d own events, want exactly 256 (the queue's content; %d lost, produced %d)", got, want, produced)
	}
}

// threeLevelTree: root <- mid <- leafA, root <- mid <- leafB (pull links, lot32 hooks everywhere). The given hosts are
// enrolled on both leaves while they have no parent (a real enrollment is a host.new that would move routes).
func threeLevelTree(t *testing.T, hosts ...string) (root, mid *node, leafA, leafB *enrolledNode) {
	t.Helper()
	root = startNode(t, nodeSpec{ID: "root", Hooks: lot32Hooks})
	mid = startNode(t, nodeSpec{ID: "mid", Root: root, Hooks: lot32Hooks})
	mid.linkTo(root)
	waitFor(t, "mid linked", func() bool { return mid.upstreamState() == "connected" })
	mk := func(id string) *enrolledNode {
		n := startNode(t, nodeSpec{ID: id, Root: root, Hooks: lot32Hooks})
		e := &enrolledNode{node: n, enrolled: map[string]string{}}
		for _, h := range hosts {
			e.enrolled[h] = n.enrollAgent(h)
		}
		n.linkTo(mid)
		return e
	}
	leafA, leafB = mk("leafA"), mk("leafB")
	waitFor(t, "leaves linked", func() bool { return leafA.upstreamState() == "connected" && leafB.upstreamState() == "connected" })
	return
}

type enrolledNode struct {
	*node
	enrolled map[string]string // host -> agent token on this node
}
