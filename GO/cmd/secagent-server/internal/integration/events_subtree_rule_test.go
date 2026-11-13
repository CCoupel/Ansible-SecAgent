// SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
// SPDX-License-Identifier: AGPL-3.0-or-later

package integration

import (
	"testing"
	"time"
)

// T34 (#266, user rule): a child can only report events for the hosts of its own subtree. A fake child F, declared
// on the root, sends host.down / host.removed / host.discover / host.rerouted for a host that lives behind ANOTHER
// child (relayA, 3 levels with the root): the root refuses them all (no hook line, nothing forwarded); the owner's
// own events are still accepted.
func TestSubtreeRule_ChildCannotReportHostsOfAnotherSubtree(t *testing.T) {
	parallel(t)
	root := startNode(t, nodeSpec{ID: "root", Hooks: lot32Hooks})
	relayA := startNode(t, nodeSpec{ID: "relayA", Root: root, Hooks: lot32Hooks})
	tok := relayA.enrollAgent("owned-host")
	relayA.linkTo(root)
	waitFor(t, "relayA linked", func() bool { return relayA.upstreamState() == "connected" })
	m := connectMinionWithToken(t, relayA, "owned-host", tok)
	waitFor(t, "the root routes owned-host via relayA", func() bool { return root.hasHost("owned-host") })
	waitFor(t, "root: host.up of owned-host", func() bool { return len(root.eventsOf("host.up", map[string]string{"host": "owned-host"})) >= 1 })

	f := newFakeChild(t, root, "F")
	f.snapshot(nil, nil)
	want := map[string]string{"host": "owned-host"}
	before := len(root.hookLines())
	f.event("host.down", "owned-host", "disconnected", "F")
	f.send(map[string]any{"type": "event_forward", "event": "host.removed", "hostname": "owned-host", "cause": "deleted", "relay_chain": []string{"F"}})
	f.send(map[string]any{"type": "event_forward", "event": "host.discover", "hostname": "owned-host", "first_seen_at": "2026-11-12T10:00:00Z", "relay_chain": []string{"F"}})
	f.send(map[string]any{"type": "event_forward", "event": "host.rerouted", "hostname": "owned-host", "cause": "moved", "old_relay": "F", "new_relay": "F",
		"old_chain": []string{"F"}, "new_chain": []string{"F"}, "relay_chain": []string{"F"}})
	time.Sleep(2 * settle)
	for _, k := range []string{"host.down", "host.removed", "host.discover", "host.rerouted"} {
		if got := root.eventsOf(k, want); len(got) != 0 {
			t.Errorf("root: %d %s for a host of another subtree, want 0: %v", len(got), k, got)
		}
	}
	for _, l := range root.hookLines()[before:] {
		if _, kv := parseLine(l); kv["host"] == "owned-host" {
			t.Errorf("root journaled a refused event about owned-host: %s", l)
		}
	}
	// the owner can still speak about its own host
	_ = m.conn.Close()
	waitFor(t, "owner's host.down reaches the root", func() bool { return len(root.eventsOf("host.down", want)) >= 1 })
}
