// SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
// SPDX-License-Identifier: AGPL-3.0-or-later

package integration

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// LOT-3.2 (#246) — upstream event queue of a child relay (server.go: upEvents, capacity 256 in v3.0.5).
// Contract: plan LOT-3.2 §T15 (file amont bornee et mesuree, rejeu cadence sous le quota parent 200/s).

// Non-regression 300 / 256 (commit 1, written BEFORE the queue becomes configurable): a child whose uplink is
// UP forwards 300 host events — more than the 256 slots of its upstream queue — without losing one and without
// logging a local drop. The events are produced at ~100/s: under the parent's quota of 200 events/s per relay
// (ws.maxEventsPerSecond), so only the queue can lose them. GREEN on e0d1970 (queue drained as fast as it
// fills); it must stay GREEN after T15 (bigger queue + replay cadenced at RELAY_UPSTREAM_RATE).
func TestUpstreamQueue_NR_300EventsOverA256SlotQueue_AllDeliveredNoneDropped(t *testing.T) {
	if testing.Short() {
		t.Skip("300 agents")
	}
	parallel(t)
	const hosts = 300 // > 256 = the capacity of the v3.0.5 queue
	root := startNode(t, nodeSpec{ID: "root", Hooks: lifecycleHooks})
	child := startNode(t, nodeSpec{ID: "relay1", Root: root})

	// Enrolled while the child has no parent: the host.new events have nowhere to go and the parent quota
	// is not consumed before the measured phase.
	tokens := make([]string, hosts)
	if err := forEachAgent(hosts, 16, func(i int) (err error) {
		tokens[i], err = child.enrollAgentErr(fmt.Sprintf("q256-%03d", i))
		return err
	}); err != nil {
		t.Fatalf("an agent could not enroll on the child: %v", err)
	}
	child.linkTo(root)
	waitFor(t, "the child is linked to the root", func() bool { return child.upstreamState() == "connected" })

	var conns []*websocket.Conn
	t.Cleanup(func() {
		for _, c := range conns {
			_ = c.Close()
		}
	})
	d := websocket.Dialer{TLSClientConfig: tlsClientConfig(), HandshakeTimeout: 10 * time.Second}
	for i := 0; i < hosts; i++ { // sequential + paced: ~100 host.up per second
		h := http.Header{}
		h.Set("Authorization", "Bearer "+tokens[i])
		c, _, err := d.Dial(child.wssURL()+"/ws/agent", h)
		if err != nil {
			t.Fatalf("agent %d dial: %v", i, err)
		}
		conns = append(conns, c)
		time.Sleep(10 * time.Millisecond)
	}

	waitFor(t, "300 host.up at the root", func() bool { return root.hookCount("host.up ") >= hosts })
	ups := 0
	for _, l := range root.hookLines() {
		if strings.HasPrefix(l, "host.up ") && strings.Contains(l, " host=q256-") {
			ups++
		}
	}
	if ups != hosts {
		t.Errorf("%d host.up of the 300 hosts at the root, want exactly %d (none lost, none duplicated)", ups, hosts)
	}
	if child.logs.has("upstream event queue full") {
		t.Errorf("the child dropped events from its upstream queue (uplink up):\n%s", child.logs.String())
	}
	if root.logs.has("event_forward rate limit exceeded") {
		t.Errorf("the parent refused events over its quota (the child must stay under 200/s):\n%s", root.logs.String())
	}
}
