// SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build slow

package integration

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// #245 — a child with 3 000 hosts behind it whose link is cut and comes back (same process): the parent emits ONE
// relay.reconnect (hosts=3000) and NO event per indirect host (the snapshot is routing, not inventory), and the
// hooks queue drops nothing.
func TestRelayEvents_3000HostsBehindAChildGiveOneRelayEvent(t *testing.T) {
	if testing.Short() {
		t.Skip("subtree test")
	}
	const agents = 3000
	root := startNode(t, nodeSpec{ID: "root", Hooks: lifecycleHooks})
	tok := root.registerChild("relay1")
	child := startNode(t, nodeSpec{ID: "relay1", ParentURL: root.wssURL(), ParentToken: tok})
	waitFor(t, "the child is linked", func() bool { return child.upstreamState() == "connected" })

	tokens := make([]string, agents)
	if err := forEachAgent(agents, 64, func(i int) (err error) {
		tokens[i], err = child.enrollAgentErr(fmt.Sprintf("sub-%04d", i))
		return err
	}); err != nil {
		t.Fatalf("an agent could not enroll on the child: %v", err)
	}
	var mu sync.Mutex
	var conns []*websocket.Conn
	t.Cleanup(func() {
		mu.Lock()
		defer mu.Unlock()
		for _, c := range conns {
			_ = c.Close()
		}
	})
	if err := forEachAgent(agents, 64, func(i int) error {
		h := http.Header{}
		h.Set("Authorization", "Bearer "+tokens[i])
		d := websocket.Dialer{TLSClientConfig: tlsClientConfig(), HandshakeTimeout: 30 * time.Second}
		c, _, err := d.Dial(child.wssURL()+"/ws/agent", h)
		if err != nil {
			return err
		}
		mu.Lock()
		conns = append(conns, c) // kept open: the hosts stay connected to the child
		mu.Unlock()
		return nil
	}); err != nil {
		t.Fatalf("an agent could not connect to the child: %v", err)
	}
	waitFor(t, "the root ran a host.up per indirect host", func() bool { return root.hookCount("host.up ") >= agents })
	waitFor(t, "relay.up", func() bool { return len(root.relayLines("relay.up", "relay1")) == 1 })
	hostUps := root.hookCount("host.up ")

	root.closeRelay("relay1", 1011)
	waitFor(t, "relay.reconnect after the cut", func() bool { return len(root.relayLines("relay.reconnect", "relay1")) == 1 })
	waitFor(t, "the child is linked again", func() bool { return child.upstreamState() == "connected" })
	time.Sleep(2 * time.Second) // any per-host event of the snapshot would have been dispatched by now
	if l := root.relayLines("relay.reconnect", "relay1")[0]; !strings.Contains(l, fmt.Sprintf(" hosts=%d ", agents)) {
		t.Errorf("relay.reconnect must count the %d hosts routed: %s", agents, l)
	}
	if got := len(root.relayLines("relay.reconnect", "relay1")); got != 1 {
		t.Errorf("%d relay.reconnect, want exactly 1", got)
	}
	if got := root.hookCount("host.up "); got != hostUps {
		t.Errorf("%d host.up after the re-link, was %d: the snapshot must emit no event per host", got, hostUps)
	}
	if got := root.hookCount("host.reconnect "); got != 0 {
		t.Errorf("%d host.reconnect for hosts that never reconnected", got)
	}
	code, status := root.admin("GET", "/api/admin/status", nil)
	if code != http.StatusOK || status["hooks_dropped_events"] != float64(0) {
		t.Errorf("status %d: hooks_dropped_events must be 0: %v", code, status)
	}
}
