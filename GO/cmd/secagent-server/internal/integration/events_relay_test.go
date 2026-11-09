// SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
// SPDX-License-Identifier: AGPL-3.0-or-later

package integration

import (
	"strings"
	"testing"
	"time"
)

// #225 #245 #265 — events of the life of a relay link (relay.up / relay.reconnect / relay.down), seen by the
// parent. up = a NEW child process, reconnect = the SAME child process coming back (conn_seq announced in
// relay_hello for a pull child). relay.* events carry no hostname.

func pullChild(t *testing.T) (root, child *node) {
	t.Helper()
	root = startNode(t, nodeSpec{ID: "root", Hooks: lifecycleHooks})
	tok := root.registerChild("relay1")
	child = startNode(t, nodeSpec{ID: "relay1", ParentURL: root.wssURL(), ParentToken: tok})
	waitFor(t, "the child is linked to the root", func() bool { return child.upstreamState() == "connected" })
	return root, child
}

func TestRelayEvents_FirstLinkIsRelayUp_NoHostnameNoReconnect(t *testing.T) {
	parallel(t)
	root, _ := pullChild(t)
	waitFor(t, "relay.up for the child", func() bool { return len(root.relayLines("relay.up", "relay1")) == 1 })
	l := root.relayLines("relay.up", "relay1")[0]
	for _, want := range []string{" host= ", " mode=pull ", " seq=1 ", " hosts=0 "} {
		if !strings.Contains(l, want) {
			t.Errorf("relay.up line lacks %q: %s", want, l)
		}
	}
	time.Sleep(200 * time.Millisecond)
	if got := len(root.relayLines("relay.reconnect", "relay1")); got != 0 {
		t.Errorf("%d relay.reconnect on a first link, want 0", got)
	}
	if got := len(root.relayLines("relay.up", "relay1")); got != 1 {
		t.Errorf("%d relay.up, want exactly 1", got)
	}
}

// The link is cut by the parent, the SAME child process reconnects: relay.down then relay.reconnect (conn_seq > 1),
// and no second relay.up.
func TestRelayEvents_CutAndSameProcessReturnsIsRelayDownThenReconnect(t *testing.T) {
	parallel(t)
	root, child := pullChild(t)
	waitFor(t, "relay.up", func() bool { return len(root.relayLines("relay.up", "relay1")) == 1 })
	root.closeRelay("relay1", 1011) // a transient close: the child reconnects by itself
	waitFor(t, "relay.down", func() bool { return len(root.relayLines("relay.down", "relay1")) >= 1 })
	waitFor(t, "relay.reconnect", func() bool { return len(root.relayLines("relay.reconnect", "relay1")) >= 1 })
	waitFor(t, "the child is linked again", func() bool { return child.upstreamState() == "connected" })
	d := root.relayLines("relay.down", "relay1")[0]
	if !strings.Contains(d, " reason=") || strings.Contains(d, " reason= ") {
		t.Errorf("relay.down must carry a reason: %s", d)
	}
	if !strings.Contains(d, " host= ") {
		t.Errorf("relay.down must have no hostname: %s", d)
	}
	r := root.relayLines("relay.reconnect", "relay1")[0]
	if strings.Contains(r, " seq=1 ") || strings.Contains(r, " seq= ") {
		t.Errorf("relay.reconnect must announce conn_seq > 1: %s", r)
	}
	if got := len(root.relayLines("relay.up", "relay1")); got != 1 {
		t.Errorf("%d relay.up in total, want 1 (up and reconnect are exclusive)", got)
	}
	// ordering of the lifecycle: up, down, reconnect
	idx := func(prefix string) int {
		for i, l := range root.hookLines() {
			if strings.HasPrefix(l, prefix+" relay=relay1 ") {
				return i
			}
		}
		return -1
	}
	if !(idx("relay.up") < idx("relay.down") && idx("relay.down") < idx("relay.reconnect")) {
		t.Errorf("order must be up < down < reconnect, got:\n%s", strings.Join(root.hookLines(), "\n"))
	}
}

// A restarted child (NEW process, conn_seq 1) gives relay.up again, not relay.reconnect.
func TestRelayEvents_RestartOfTheChildIsRelayUpAgain(t *testing.T) {
	parallel(t)
	root, child := pullChild(t)
	waitFor(t, "relay.up", func() bool { return len(root.relayLines("relay.up", "relay1")) == 1 })
	child.restart()
	waitFor(t, "relay.down for the stopped process", func() bool { return len(root.relayLines("relay.down", "relay1")) >= 1 })
	waitFor(t, "the second relay.up", func() bool { return len(root.relayLines("relay.up", "relay1")) == 2 })
	if got := len(root.relayLines("relay.reconnect", "relay1")); got != 0 {
		t.Errorf("%d relay.reconnect after a restart of the child process, want 0", got)
	}
}

// 4010 (permanent refusal / revocation): relay.down reason=revoked, and the child does not come back.
func TestRelayEvents_Close4010IsRelayDownRevoked(t *testing.T) {
	parallel(t)
	root, _ := pullChild(t)
	waitFor(t, "relay.up", func() bool { return len(root.relayLines("relay.up", "relay1")) == 1 })
	root.closeRelay("relay1", 4010)
	waitFor(t, "relay.down", func() bool { return len(root.relayLines("relay.down", "relay1")) == 1 })
	if l := root.relayLines("relay.down", "relay1")[0]; !strings.Contains(l, " reason=revoked ") {
		t.Errorf("a 4010 close must give reason=revoked: %s", l)
	}
	time.Sleep(500 * time.Millisecond)
	if got := len(root.relayLines("relay.reconnect", "relay1")) + len(root.relayLines("relay.up", "relay1")); got != 1 {
		t.Errorf("the child came back after a permanent refusal (%d up/reconnect lines)", got)
	}
}

// Fail-over of the root a/b with a pull child: the new master emits relay.failover (takeover, an instance id) BEFORE
// the child's link, then relay.reconnect for the child (same process, conn_seq > 1) — and NO host.up for the hosts
// behind the child, which never reconnected.
func TestRelayEvents_RootFailoverGivesFailoverThenReconnect_NoHostUp(t *testing.T) {
	parallel(t)
	addrA, addrB := newNodeAddrs(t), newNodeAddrs(t)
	a := startNode(t, nodeSpec{ID: "root", Env: addrA.env(), Hooks: lifecycleHooks})
	tok := a.registerChild("relay1")
	b := a.sibling()
	b.launchSecondary(addrB.env())
	t.Cleanup(b.stop)
	waitFor(t, "the standby polls the lock", b.localStatusPolled)
	child := startNode(t, nodeSpec{ID: "relay1", ParentURL: "wss://" + addrA.ws + ",wss://" + addrB.ws, ParentToken: tok})
	waitFor(t, "the child is linked to the active root", func() bool { return child.upstreamState() == "connected" })
	connectMinion(t, child, "leaf-host")
	waitFor(t, "the master ran host.up for the leaf", func() bool { return len(a.hostLines("host.up", "leaf-host")) == 1 })
	waitFor(t, "relay.up on A", func() bool { return len(a.relayLines("relay.up", "relay1")) == 1 })
	failoversBefore := len(a.linesWith("relay.failover "))

	a.killNow()
	if !b.awaitPromotion(30 * time.Second) {
		t.Fatalf("the passive root never took over; logs:\n%s", b.logs.String())
	}
	waitFor(t, "relay.failover by the new master", func() bool { return len(b.linesWith("relay.failover ")) == failoversBefore+1 })
	waitFor(t, "the child reconnected to the new master", func() bool { return len(b.relayLines("relay.reconnect", "relay1")) >= 1 })
	f := b.linesWith("relay.failover ")
	last := f[len(f)-1]
	if !strings.Contains(last, " cause=takeover ") {
		t.Errorf("the new master took a stale lock: cause must be takeover: %s", last)
	}
	if !strings.Contains(last, " host= ") || strings.Contains(last, " inst= ") {
		t.Errorf("relay.failover must carry an instance id and no hostname: %s", last)
	}
	if r := b.relayLines("relay.reconnect", "relay1")[0]; strings.Contains(r, " seq=1 ") {
		t.Errorf("the same child process reconnecting must announce conn_seq > 1: %s", r)
	}
	// ordering: relay.failover before the reconnection of the child
	lines := b.hookLines()
	fi, ri := -1, -1
	for i, l := range lines {
		if strings.HasPrefix(l, "relay.failover ") {
			fi = i
		}
		if ri < 0 && strings.HasPrefix(l, "relay.reconnect relay=relay1 ") {
			ri = i
		}
	}
	if fi < 0 || ri < 0 || fi > ri {
		t.Errorf("relay.failover must precede the child's relay.reconnect (failover line %d, reconnect line %d):\n%s", fi, ri, strings.Join(lines, "\n"))
	}
	time.Sleep(500 * time.Millisecond)
	if got := len(b.hostLines("host.up", "leaf-host")); got != 1 {
		t.Errorf("%d host.up for the leaf host in total, want 1 (the old master's): no indirect host.up at a fail-over", got)
	}
	if got := len(b.hostLines("host.reconnect", "leaf-host")); got != 0 {
		t.Errorf("%d host.reconnect for a host that never reconnected, want 0", got)
	}
}

// Fail-over of a CHILD pair behind a root: relay.failover is emitted by the new master BEFORE its uplink is up, and
// still climbs to the ancestor (deferred propagation), with the id of the failing-over relay.
func TestRelayEvents_ChildFailoverClimbsToTheAncestor(t *testing.T) {
	parallel(t)
	root := startNode(t, nodeSpec{ID: "root", Hooks: lifecycleHooks})
	tok := root.registerChild("relay1")
	addrA, addrB := newNodeAddrs(t), newNodeAddrs(t)
	ca := startNode(t, nodeSpec{ID: "relay1", Env: addrA.env(), ParentURL: root.wssURL(), ParentToken: tok})
	waitFor(t, "the child master is linked to the root", func() bool { return ca.upstreamState() == "connected" })
	waitFor(t, "relay.up on the root", func() bool { return len(root.relayLines("relay.up", "relay1")) == 1 })
	cb := ca.sibling()
	cb.launchSecondary(addrB.env())
	t.Cleanup(cb.stop)
	waitFor(t, "the child standby polls the lock", cb.localStatusPolled)
	before := len(root.relayLines("relay.failover", "relay1"))

	ca.killNow()
	if !cb.awaitPromotion(30 * time.Second) {
		t.Fatalf("the child standby never took over; logs:\n%s", cb.logs.String())
	}
	waitFor(t, "relay.failover of relay1 reached the ancestor", func() bool { return len(root.relayLines("relay.failover", "relay1")) == before+1 })
	f := root.relayLines("relay.failover", "relay1")
	if l := f[len(f)-1]; !strings.Contains(l, " cause=takeover ") || !strings.Contains(l, " host= ") {
		t.Errorf("relay.failover at the ancestor: want cause=takeover and no hostname: %s", l)
	}
	// the new child process links to the root: a NEW process of the child (conn_seq 1) ⇒ relay.up
	waitFor(t, "the child's new master linked to the root", func() bool { return cb.upstreamState() == "connected" })
	waitFor(t, "relay.up for the new child master", func() bool { return len(root.relayLines("relay.up", "relay1")) == 2 })
}
