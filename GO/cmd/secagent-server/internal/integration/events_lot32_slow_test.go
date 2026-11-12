// SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build slow

// Slow suite: run with `-tags slow`, in its own CI job (slow-tests).

package integration

import (
	"fmt"
	"testing"
	"time"
)

// LOT-3.2 (#244, #246a) — the two load scenarios.

// (9) a reparent of 3 000 hosts: ONE relay.rerouted (hosts_routed=3000), no host.rerouted, nothing dropped by the
// hooks queue of the node.
func TestRelayRerouted_Reparent3000HostsGivesOneEventNoHostRerouted(t *testing.T) {
	const hosts = 3000
	root := startNode(t, nodeSpec{ID: "root", Hooks: lot32Hooks})
	f := newFakeChild(t, root, "F")
	snap := func(chain ...string) {
		agents := make([]map[string]any, hosts)
		for i := range agents {
			agents[i] = map[string]any{"hostname": fmt.Sprintf("bulk-%04d", i), "relay_id": "r2", "relay_chain": chain}
		}
		f.snapshot([]map[string]any{{"relay_id": "r1", "relay_chain": []string{"F", "r1"}}, {"relay_id": "r2", "relay_chain": chain}}, agents)
	}
	snap("F", "r1", "r2")
	waitFor(t, "3000 hosts routed", func() bool { return len(root.inventoryHosts()) >= hosts })
	time.Sleep(settle)
	snap("F", "r2") // r2 (and its 3000 hosts) re-attached directly under F
	waitFor(t, "relay.rerouted for r2", func() bool { return len(root.eventsOf("relay.rerouted", map[string]string{"relay": "r2"})) >= 1 })
	time.Sleep(3 * time.Second)
	ev := root.eventsOf("relay.rerouted", nil)
	if len(ev) != 1 || ev[0]["relay"] != "r2" || ev[0]["hr"] != "3000" {
		t.Errorf("want exactly one relay.rerouted for r2 with hosts_routed=3000, got %v", ev)
	}
	if got := len(root.eventsOf("host.rerouted", nil)); got != 0 {
		t.Errorf("%d host.rerouted for a reparent of %d hosts, want 0", got, hosts)
	}
	if v, ok := root.statusField("hooks_dropped_events"); !ok || v != 0 {
		t.Errorf("hooks_dropped_events = %v (present %v), want 0", v, ok)
	}
}

// (7) 9 600 events + one relay.discover per identity (160 identities x 61, under the 10 000 slots of the queue, so that nothing is lost by the queue itself) queued while the uplink is cut are replayed CADENCED (RELAY_UPSTREAM_RATE, default 150/s, under the
// parent quota of 200/s): all of them arrive, the parent refuses none, the replay takes about 67 s (not an instant burst).
func TestUpstreamQueue_Replay10000IsCadencedUnderTheParentQuota(t *testing.T) {
	c := newCutTree(t, 9600, "RELAY_HOOKS_QUEUE_SIZE=100000") // the child's own hooks journal must keep up with the production
	c.cut(t)
	c.produce(t, 16)
	waitFor(t, "the child journaled every event it produced", func() bool { return c.count(c.child) >= 9600 })
	produced := c.count(c.child)

	t0 := time.Now()
	c.back(t)
	deadline := time.Now().Add(150 * time.Second)
	for c.count(c.root) < produced && time.Now().Before(deadline) {
		time.Sleep(time.Second)
	}
	took := time.Since(t0)
	if got := c.count(c.root); got != produced {
		t.Errorf("the root received %d of the %d events produced", got, produced)
	}
	if took < time.Duration(float64(produced)/200*float64(time.Second)) {
		t.Errorf("replay of %d events took %s: faster than the parent quota of 200/s allows, it was not cadenced", produced, took)
	}
	if c.root.logs.has("event_forward rate limit exceeded") {
		t.Errorf("the parent refused events over its quota during the replay")
	}
	if v, _ := c.child.statusField("upstream_dropped_events"); v != 0 {
		t.Errorf("upstream_dropped_events = %v, want 0 (9 760 events fit the 10 000 slots of the default queue)", v)
	}
}
