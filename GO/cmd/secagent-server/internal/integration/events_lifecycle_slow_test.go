// SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build slow

// LOT-3.3 (#266) — the long scenarios of the inventory life-cycle events (the fast suite has two short ones, see
// events_lifecycle_test.go). Run with `-tags slow`.

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

// (2) 3 000 first connections: 3 000 host.discover and 3 000 host.up run, the marks are written GROUPED (a few state
// writes, not one per host), nothing dropped by the hooks queue.
func TestLifecycleSlow_3000FirstConnectionsAreGroupedWrites(t *testing.T) {
	const agents = 3000
	root := startNode(t, nodeSpec{ID: "root", Hooks: lot33Hooks})
	tokens := make([]string, agents)
	if err := forEachAgent(agents, 64, func(i int) (err error) {
		tokens[i], err = root.enrollAgentErr(fmt.Sprintf("burst-%04d", i))
		return err
	}); err != nil {
		t.Fatalf("an agent could not enroll: %v", err)
	}
	var mu sync.Mutex
	var conns []*websocket.Conn
	t.Cleanup(func() {
		for _, c := range conns {
			_ = c.Close()
		}
	})
	before := stateWriteSeq(t, root.stateDir)
	if err := forEachAgent(agents, 64, func(i int) error {
		h := http.Header{}
		h.Set("Authorization", "Bearer "+tokens[i])
		d := websocket.Dialer{TLSClientConfig: tlsClientConfig(), HandshakeTimeout: 30 * time.Second}
		c, _, err := d.Dial(root.wssURL()+"/ws/agent", h)
		if err != nil {
			return err
		}
		mu.Lock()
		conns = append(conns, c)
		mu.Unlock()
		go func() { // a real agent reads its link (answers the pings)
			for {
				if _, _, err := c.ReadMessage(); err != nil {
					return
				}
			}
		}()
		return nil
	}); err != nil {
		t.Fatalf("an agent could not connect: %v", err)
	}
	waitFor(t, "a host.discover and a host.up for each of the 3000 hosts", func() bool {
		return root.hookCount("host.discover ") >= agents && root.hookCount("host.up ") >= agents
	})
	time.Sleep(3 * time.Second) // the grouped flush of the marks (<= 1 s)
	if got := root.hookCount("host.discover "); got != agents {
		t.Errorf("%d host.discover, want exactly %d", got, agents)
	}
	if writes := stateWriteSeq(t, root.stateDir) - before; writes > 10 {
		t.Errorf("%d state writes for %d first connections, want at most 10 (grouped marks)", writes, agents)
	}
	if v, ok := root.statusField("hooks_dropped_events"); !ok || v != 0 {
		t.Errorf("hooks_dropped_events = %v (present %v), want 0", v, ok)
	}
}

// (7) a restart of the node (real process, same state): the already-discovered host raises no new discover.
func TestLifecycleSlow_NodeRestartRaisesNoDiscover(t *testing.T) {
	root := startNode(t, nodeSpec{ID: "root", Hooks: lot33Hooks})
	const h = "slow-restart-host"
	tok := root.enrollAgent(h)
	m := connectMinionWithToken(t, root, h, tok)
	waitFor(t, "host.discover", func() bool { return countOf(root, "host.discover", h) == 1 })
	waitFor(t, "first_seen_at persisted", func() bool { return firstSeenOf(root, h) != "" })
	_ = m.conn.Close()
	root.restart()
	connectMinionWithToken(t, root, h, tok)
	waitFor(t, "host.up after the restart", func() bool { return countOf(root, "host.up", h) >= 2 })
	time.Sleep(settle)
	if got := countOf(root, "host.discover", h); got != 1 {
		t.Errorf("%d host.discover after a restart of the node, want exactly 1 (the mark is persisted)", got)
	}
}

// (8) a/b switch-over (shared state): neither the agent that comes back nor the child relay that comes back is
// discovered again by the new master.
func TestLifecycleSlow_SwitchOverRaisesNoDiscover(t *testing.T) {
	addrA, addrB := newNodeAddrs(t), newNodeAddrs(t)
	a := startNode(t, nodeSpec{ID: "root", Env: addrA.env(), Hooks: lot33Hooks})
	tokChild := a.registerChild("so-relay")
	b := a.sibling()
	b.launchSecondary(addrB.env())
	t.Cleanup(b.stop)
	waitFor(t, "the standby polls the lock", b.localStatusPolled)
	child := startNode(t, nodeSpec{ID: "so-relay", ParentURL: "wss://" + addrA.ws + ",wss://" + addrB.ws, ParentToken: tokChild})
	waitFor(t, "the child is linked", func() bool { return child.upstreamState() == "connected" })
	const h = "slow-so-host"
	tok := a.enrollAgent(h)
	connectMinionWithToken(t, a, h, tok)
	waitFor(t, "host.discover and relay.discover on the first master", func() bool {
		return countOf(a, "host.discover", h) == 1 && len(a.eventsOf("relay.discover", map[string]string{"relay": "so-relay"})) == 1
	})
	waitFor(t, "first_seen_at persisted", func() bool { return firstSeenOf(a, h) != "" })

	a.killNow()
	if !b.awaitPromotion(30 * time.Second) {
		t.Fatalf("the passive root never took over; logs:\n%s", b.logs.String())
	}
	seq := "2"
	dialAgentSeq(t, b, tok, &seq)
	waitFor(t, "the host and the child are back on the new master", func() bool {
		return countOf(b, "host.reconnect", h) >= 1 && len(b.eventsOf("relay.reconnect", map[string]string{"relay": "so-relay"})) >= 1
	})
	time.Sleep(settle)
	if got := countOf(b, "host.discover", h); got != 1 {
		t.Errorf("%d host.discover in total after the switch-over, want exactly 1", got)
	}
	if got := len(b.eventsOf("relay.discover", map[string]string{"relay": "so-relay"})); got != 1 {
		t.Errorf("%d relay.discover in total after the switch-over, want exactly 1", got)
	}
}

// (9) two levels: the host.discover / host.removed of a host of the CHILD reach the root with the relay_chain.
func TestLifecycleSlow_HostEventsClimbTwoLevelsWithTheirChain(t *testing.T) {
	root := startNode(t, nodeSpec{ID: "root", Hooks: lot33Hooks})
	mid := startNode(t, nodeSpec{ID: "mid", ParentURL: root.wssURL(), ParentToken: root.registerChild("mid"), Hooks: lot33Hooks})
	waitFor(t, "mid linked", func() bool { return mid.upstreamState() == "connected" })
	const h = "slow-climb-host"
	connectMinionWithToken(t, mid, h, mid.enrollAgent(h))
	want := map[string]string{"host": h}
	waitFor(t, "host.discover at the root", func() bool { return len(root.eventsOf("host.discover", want)) >= 1 })
	if d := root.eventsOf("host.discover", want)[0]; d["chain"] != "mid" || d["first"] == "" {
		t.Errorf("root: host.discover must carry relay_chain=mid and first_seen_at: %v", d)
	}
	if code, raw := mid.admin("DELETE", "/api/admin/minions/"+h, nil); code >= 300 {
		t.Fatalf("DELETE minion on mid: %d %v", code, raw)
	}
	waitFor(t, "host.removed at the root", func() bool { return len(root.eventsOf("host.removed", want)) >= 1 })
	time.Sleep(settle)
	if r := root.eventsOf("host.removed", want); len(r) != 1 || r[0]["chain"] != "mid" || r[0]["cause"] != "deleted" {
		t.Errorf("root: want ONE host.removed with relay_chain=mid cause=deleted, got %v", r)
	}
	if got := len(root.eventsOf("host.deleted", want)); got != 0 {
		t.Errorf("root ran %d host.deleted: it is local to the node that deletes (deprecated), never propagated", got)
	}
}

// (9) three levels: relay.discover / relay.removed of dmz2 (a child of dmz1) reach the root through dmz1 with the chain;
// NO cascade: deleting dmz2 raises ONE relay.removed, none for dmz3 below it and no host.removed for its host.
func TestLifecycleSlow_RelayEventsClimbThreeLevelsWithoutCascade(t *testing.T) {
	root := startNode(t, nodeSpec{ID: "root", Hooks: lot33Hooks})
	dmz1 := startNode(t, nodeSpec{ID: "dmz1", ParentURL: root.wssURL(), ParentToken: root.registerChild("dmz1"), Hooks: lot33Hooks})
	waitFor(t, "dmz1 linked", func() bool { return dmz1.upstreamState() == "connected" })
	tok2, id2 := dmz1.registerChildWithID("dmz2")
	dmz2 := startNode(t, nodeSpec{ID: "dmz2", ParentURL: dmz1.wssURL(), ParentToken: tok2, Hooks: lot33Hooks})
	waitFor(t, "dmz2 linked", func() bool { return dmz2.upstreamState() == "connected" })
	dmz3 := startNode(t, nodeSpec{ID: "dmz3", ParentURL: dmz2.wssURL(), ParentToken: dmz2.registerChild("dmz3"), Hooks: lot33Hooks})
	waitFor(t, "dmz3 linked", func() bool { return dmz3.upstreamState() == "connected" })
	connectMinionWithToken(t, dmz3, "slow-below-host", dmz3.enrollAgent("slow-below-host"))

	d2 := map[string]string{"relay": "dmz2"}
	waitFor(t, "relay.discover of dmz2 at the root", func() bool { return len(root.eventsOf("relay.discover", d2)) >= 1 })
	if e := root.eventsOf("relay.discover", d2)[0]; e["chain"] != "dmz1,dmz2" {
		t.Errorf("root: relay.discover of dmz2 must carry relay_chain=dmz1,dmz2, got %v", e)
	}

	if code, raw := dmz1.admin("DELETE", "/api/admin/relays/"+id2, nil); code >= 300 {
		t.Fatalf("DELETE relay dmz2 on dmz1: %d %v", code, raw)
	}
	waitFor(t, "relay.removed of dmz2 at the root", func() bool { return len(root.eventsOf("relay.removed", d2)) >= 1 })
	time.Sleep(settle * 2)
	if r := root.eventsOf("relay.removed", nil); len(r) != 1 || r[0]["relay"] != "dmz2" || r[0]["chain"] != "dmz1,dmz2" {
		t.Errorf("root: want exactly ONE relay.removed (dmz2, chain dmz1,dmz2), got %v", r)
	}
	for _, n := range []*node{root, dmz1} {
		if got := len(n.eventsOf("host.removed", nil)); got != 0 {
			t.Errorf("%s: %d host.removed after deleting a relay, want 0 (no cascade)", n.id, got)
		}
	}
	if !strings.Contains(strings.Join(dmz1.hookLines(), "\n"), "relay.removed relay=dmz2") {
		t.Errorf("dmz1 (the node that deleted it) must journal its own relay.removed")
	}
}

// (10) late: a host.discover that stayed more than 10 s in the child's upstream queue (parent unreachable) is executed at the
// root as any discover, with the ORIGINAL timestamp — `late` changes nothing for the inventory life-cycle (Q3).
func TestLifecycleSlow_LateDiscoverIsStillADiscoverWithItsOriginalTimestamp(t *testing.T) {
	addr := newNodeAddrs(t)
	root := startNode(t, nodeSpec{ID: "root", Env: addr.env(), Hooks: lot33Hooks})
	child := startNode(t, nodeSpec{ID: "relay1", ParentURL: root.wssURL(), ParentToken: root.registerChild("relay1"), Hooks: lot33Hooks})
	waitFor(t, "the child is linked", func() bool { return child.upstreamState() == "connected" })
	const h = "slow-late-host"
	tok := child.enrollAgent(h)
	root.stop()
	waitFor(t, "the child's uplink is down", func() bool { return child.upstreamState() != "connected" })
	connectMinionWithToken(t, child, h, tok)
	waitFor(t, "the child ran host.discover", func() bool { return countOf(child, "host.discover", h) == 1 })
	at := time.Now()
	time.Sleep(12 * time.Second) // > 10 s: the event is late when it is replayed
	root.launch([]string{"NODE_API_ADDR=" + root.ready.API, "NODE_ADMIN_ADDR=" + root.ready.Admin, "NODE_WS_ADDR=" + root.ready.WS})
	waitFor(t, "the child is linked again", func() bool { return child.upstreamState() == "connected" })
	waitFor(t, "host.discover replayed at the root", func() bool { return countOf(root, "host.discover", h) >= 1 })
	time.Sleep(settle)
	d := root.eventsOf("host.discover", map[string]string{"host": h})
	if len(d) != 1 {
		t.Fatalf("%d host.discover at the root, want exactly 1 (late has no effect)", len(d))
	}
	ts, err := time.Parse(time.RFC3339, d[0]["ts"])
	if err != nil {
		t.Fatalf("timestamp %q: %v", d[0]["ts"], err)
	}
	if ts.After(at.Add(2*time.Second)) || at.Sub(ts) > 30*time.Second {
		t.Errorf("the replayed host.discover must keep its ORIGINAL timestamp (%s), got %s", at.Format(time.RFC3339), d[0]["ts"])
	}
	if d[0]["first"] == "" || d[0]["chain"] != "relay1" {
		t.Errorf("replayed host.discover: want first_seen_at and relay_chain=relay1, got %v", d[0])
	}
}
