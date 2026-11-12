// SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
// SPDX-License-Identifier: AGPL-3.0-or-later

package integration

import (
	"strings"
	"testing"
	"time"
)

// LOT-3.2 (#247 option A, #246 remark, T21, T22) — what a switch-over loses and what it does not, a known-but-empty
// variable rendered empty, and the orderly stop of a child.

// (10) orderly stop of the master: the host.down of its direct agents are drained (<= 10 s) before it exits.
func TestFailoverLosses_OrderlyStopDrainsHostDownOfDirectAgents(t *testing.T) {
	parallel(t)
	addrA, addrB := newNodeAddrs(t), newNodeAddrs(t)
	a := startNode(t, nodeSpec{ID: "root", Env: addrA.env(), Hooks: lot32Hooks})
	b := a.sibling()
	b.launchSecondary(addrB.env())
	t.Cleanup(b.stop)
	waitFor(t, "the standby polls the lock", b.localStatusPolled)
	connectMinion(t, a, "d1")
	connectMinion(t, a, "d2")
	waitFor(t, "host.up of both", func() bool { return len(a.eventsOf("host.up", nil)) >= 2 })

	a.stop() // SIGTERM-equivalent: graceful shutdown
	for _, h := range []string{"d1", "d2"} {
		h := h
		waitFor(t, "host.down of "+h+" drained by the stopping master", func() bool { return len(a.eventsOf("host.down", map[string]string{"host": h})) >= 1 })
		if got := len(a.eventsOf("host.down", map[string]string{"host": h})); got != 1 {
			t.Errorf("%d host.down for %s, want exactly 1", got, h)
		}
	}
}

// (11) T21: a variable that is KNOWN but not carried by the event renders empty ({{previous_instance_id}} on a
// `start`), a takeover renders the previous instance id, an UNKNOWN token stays as written.
func TestRender_KnownButEmptyVariableIsRenderedEmpty_InAFileHook(t *testing.T) {
	parallel(t)
	addrA, addrB := newNodeAddrs(t), newNodeAddrs(t)
	a := startNode(t, nodeSpec{ID: "root", Env: addrA.env(), Hooks: func(out string) string {
		return `{"hooks":[{"event":"relay.failover","actions":[{"type":"file","path":"` + out +
			`","append":"FAILOVER cause={{cause}} instance={{instance_id}} previous={{previous_instance_id}} unknown={{not_a_variable}}\n"}]}]}`
	}})
	waitFor(t, "relay.failover (start) rendered by the first master", func() bool { return a.hookHas("FAILOVER cause=start ") })
	start := a.hookLines()[0]
	if strings.Contains(start, "{{previous_instance_id}}") || !strings.Contains(start, " previous= ") {
		t.Errorf("start: {{previous_instance_id}} must render empty (known variable, not carried): %q", start)
	}
	if !strings.Contains(start, "unknown={{not_a_variable}}") {
		t.Errorf("an UNKNOWN token must stay as written: %q", start)
	}
	var instA string
	for _, f := range strings.Fields(start) {
		if strings.HasPrefix(f, "instance=") {
			instA = strings.TrimPrefix(f, "instance=")
		}
	}
	if instA == "" {
		t.Fatalf("start: no instance id rendered: %q", start)
	}

	b := a.sibling()
	b.launchSecondary(addrB.env())
	t.Cleanup(b.stop)
	waitFor(t, "the standby polls the lock", b.localStatusPolled)
	a.killNow()
	if !b.awaitPromotion(30 * time.Second) {
		t.Fatalf("the passive root never took over; logs:\n%s", b.logs.String())
	}
	waitFor(t, "relay.failover (takeover) rendered by the new master", func() bool { return b.hookHas("FAILOVER cause=takeover ") })
	var take string
	for _, l := range b.hookLines() {
		if strings.HasPrefix(l, "FAILOVER cause=takeover ") {
			take = l
		}
	}
	if !strings.Contains(take, " previous="+instA+" ") {
		t.Errorf("takeover: want previous=%s (the instance of the stopped master), got %q", instA, take)
	}
}

// (T22, decision Q1) orderly stop of a child: its parent sees relay.down reason=peer_closed:1001 (going away), not 1006.
func TestRelayDown_OrderlyStopOfAPullChildIsPeerClosed1001(t *testing.T) {
	parallel(t)
	root := startNode(t, nodeSpec{ID: "root", Hooks: lot32Hooks})
	child := startNode(t, nodeSpec{ID: "relay1", ParentURL: root.wssURL(), ParentToken: root.registerChild("relay1")})
	waitFor(t, "relay.up", func() bool { return len(root.eventsOf("relay.up", map[string]string{"relay": "relay1"})) == 1 })
	child.stop()
	waitFor(t, "relay.down", func() bool { return len(root.eventsOf("relay.down", map[string]string{"relay": "relay1"})) >= 1 })
	if e := root.eventsOf("relay.down", map[string]string{"relay": "relay1"})[0]; e["reason"] != "peer_closed:1001" {
		t.Errorf("relay.down of an orderly child stop: reason = %q, want peer_closed:1001", e["reason"])
	}
}
