// SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
// SPDX-License-Identifier: AGPL-3.0-or-later

package integration

import (
	"fmt"
	"testing"
	"time"
)

// T24 — the host.* events of a child's OWN agents are queued (bounded upstream queue, #246) while its parent
// link is cut, and replayed paced at the reconnection, for a pull child AND a push child.

const (
	ownHosts  = 10
	ownCycles = 15 // 10 hosts x 15 x (up + down) = 300 events
)

// ownHostsTree starts root (fixed addresses), a child in `mode` ("pull" | "push") and enrolls the agents.
func ownHostsTree(t *testing.T, mode string, childEnv ...string) (root, child *node, tokens []string) {
	t.Helper()
	addr := newNodeAddrs(t)
	root = startNode(t, nodeSpec{ID: "root", Env: addr.env(), Hooks: lot32Hooks})
	if mode == "pull" {
		child = startNode(t, nodeSpec{ID: "relay1", ParentURL: root.wssURL(), ParentToken: root.registerChild("relay1"), Hooks: lot32Hooks, Env: childEnv})
		waitFor(t, "the child is linked", func() bool { return child.upstreamState() == "connected" })
	} else {
		child = startNode(t, nodeSpec{ID: "relay1", Root: root, Hooks: lot32Hooks, Env: childEnv})
		linkPush(t, root, child)
	}
	for i := 0; i < ownHosts; i++ {
		tokens = append(tokens, child.enrollAgent(fmt.Sprintf("own-%02d", i)))
	}
	return root, child, tokens
}

// produceOwn connects and disconnects each own agent ownCycles times on the child.
func produceOwn(t *testing.T, child *node, tokens []string) {
	t.Helper()
	for c := 0; c < ownCycles; c++ {
		for i, tok := range tokens {
			m := connectMinionWithToken(t, child, fmt.Sprintf("own-%02d", i), tok)
			_ = m.conn.Close()
		}
	}
}

func ownCount(n *node) int {
	total := 0
	for i := 0; i < ownHosts; i++ {
		w := map[string]string{"host": fmt.Sprintf("own-%02d", i)}
		total += len(n.eventsOf("host.up", w)) + len(n.eventsOf("host.down", w)) + len(n.eventsOf("host.reconnect", w))
	}
	return total
}

func cutAndBack(t *testing.T, root, child *node, produce func()) {
	t.Helper()
	root.stop()
	waitFor(t, "the child's uplink is down", func() bool { return child.upstreamState() != "connected" })
	produce()
}

func rootBack(t *testing.T, root, child *node, mode string) {
	t.Helper()
	root.launch([]string{"NODE_API_ADDR=" + root.ready.API, "NODE_ADMIN_ADDR=" + root.ready.Admin, "NODE_WS_ADDR=" + root.ready.WS})
	if mode == "pull" {
		waitFor(t, "the child is linked again", func() bool { return child.upstreamState() == "connected" })
	} else {
		waitFor(t, "the root dials the push child again", func() bool { return root.pushState(child.id) == "connected" })
	}
}

func testOwnHostsReplayed(t *testing.T, mode string) {
	if testing.Short() {
		t.Skip("replay")
	}
	parallel(t)
	root, child, tokens := ownHostsTree(t, mode)
	before := ownCount(root)
	cutAndBack(t, root, child, func() { produceOwn(t, child, tokens) })
	produced := ownCount(child)
	if produced < 2*ownHosts*ownCycles {
		t.Fatalf("the child journaled %d own events, want at least %d", produced, 2*ownHosts*ownCycles)
	}
	if v, _ := child.statusField("upstream_queue_depth"); int(v) < 2*ownHosts*ownCycles {
		t.Errorf("upstream_queue_depth = %v while cut, want at least %d queued own events", v, 2*ownHosts*ownCycles)
	}
	rootBack(t, root, child, mode)
	waitFor(t, "every own event is replayed to the root", func() bool { return ownCount(root)-before >= produced })
	time.Sleep(settle)
	if got := ownCount(root) - before; got != produced {
		t.Errorf("the root received %d own events, want exactly %d (none lost, none duplicated)", got, produced)
	}
	if v, ok := child.statusField("upstream_dropped_events"); !ok || v != 0 {
		t.Errorf("upstream_dropped_events = %v (present %v), want 0", v, ok)
	}
	if got := len(root.eventsOf("host.rerouted", nil)) + len(root.eventsOf("host.conflict", nil)); got != 0 {
		t.Errorf("replayed history raised %d host.rerouted/host.conflict, want 0", got)
	}
}

func TestOwnHostEvents_PullChildReplaysThemAfterTheCut(t *testing.T) { testOwnHostsReplayed(t, "pull") }
func TestOwnHostEvents_PushChildReplaysThemAfterTheCut(t *testing.T) { testOwnHostsReplayed(t, "push") }

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
