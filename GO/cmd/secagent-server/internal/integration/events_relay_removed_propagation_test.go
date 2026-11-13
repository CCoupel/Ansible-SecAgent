// SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
// SPDX-License-Identifier: AGPL-3.0-or-later

package integration

import "testing"

// #266 review: relay.removed of a deleted child reaches the ROOT. Tree root <- A <- B <- C: B deletes C (3 levels:
// the root receives it through A), then A deletes B (2 levels). The events used to be refused (no relay_chain) or
// held back behind the snapshot that declares the relay.
func TestRelayRemoved_ClimbsToTheRootThroughTwoAndThreeLevels(t *testing.T) {
	parallel(t)
	root := startNode(t, nodeSpec{ID: "root", Hooks: lot33Hooks})
	a := startNode(t, nodeSpec{ID: "relayA", Root: root, Hooks: lot33Hooks})
	b := startNode(t, nodeSpec{ID: "relayB", Root: root, Hooks: lot33Hooks})
	c := startNode(t, nodeSpec{ID: "relayC", Root: root, Hooks: lot33Hooks})
	a.linkTo(root)
	waitFor(t, "A linked", func() bool { return a.upstreamState() == "connected" })
	b.linkTo(a)
	waitFor(t, "B linked", func() bool { return b.upstreamState() == "connected" })
	c.linkTo(b)
	waitFor(t, "C linked", func() bool { return c.upstreamState() == "connected" })
	waitFor(t, "the root saw relay.up of C", func() bool { return len(root.eventsOf("relay.up", map[string]string{"relay": "relayC"})) >= 1 })

	idOf := func(n *node, relay string) string {
		code, m := n.admin("GET", "/api/admin/relays", nil)
		if code != 200 {
			t.Fatalf("list relays on %s: %d", n.id, code)
		}
		rows, _ := m["relays"].([]any)
		for _, r := range rows {
			if row, ok := r.(map[string]any); ok && row["relay_id"] == relay {
				return row["id"].(string)
			}
		}
		t.Fatalf("%s: relay %s not declared", n.id, relay)
		return ""
	}
	del := func(n *node, relay string) {
		t.Helper()
		if code, raw := n.admin("DELETE", "/api/admin/relays/"+idOf(n, relay), nil); code >= 300 {
			t.Fatalf("delete %s on %s: %d %v", relay, n.id, code, raw)
		}
	}
	del(b, "relayC") // 3 levels
	waitFor(t, "root: relay.removed of C", func() bool { return len(root.eventsOf("relay.removed", map[string]string{"relay": "relayC"})) == 1 })
	if e := root.eventsOf("relay.removed", map[string]string{"relay": "relayC"})[0]; e["cause"] != "deleted" {
		t.Errorf("relay.removed at the root = %v, want cause=deleted", e)
	}
	del(a, "relayB") // 2 levels
	waitFor(t, "root: relay.removed of B", func() bool { return len(root.eventsOf("relay.removed", map[string]string{"relay": "relayB"})) == 1 })
}
