// SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
// SPDX-License-Identifier: AGPL-3.0-or-later

package integration

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

// LOT-3.3 (#266) — inventory life-cycle events: host.discover (first handshake, persisted, exactly once), host.removed
// (admin deletion; a revocation raises none), relay.discover (first snapshot of a declared relay, by its direct parent),
// relay.removed (admin deletion, no cascade). host.deleted stays (deprecated, local).
// Contract: planner-lot33-v3.0.6-20261112 §T30/T31, decisions lot33-decisions-20261112 (Q2-Q4).
// Fast suite budget: 25 s of summed duration (Q5): two tests. Everything else is in events_lifecycle_slow_test.go.
// RED before T30/T31: none of the four kinds exists.

// lot33Events are the events the lot33Hooks file hooks log.
var lot33Events = []string{
	"host.discover", "host.removed", "host.deleted", "host.up", "host.reconnect", "host.down",
	"relay.discover", "relay.removed", "relay.up", "relay.reconnect", "relay.down",
}

// lot33Hooks writes ONE line per event with the template engine (a value the event does not carry renders empty):
//
//	<event> relay=<relay_id> host=<hostname> cause=<cause> first=<first_seen_at> enrolled=<enrolled_at> chain=<relay_chain>
//	        mode=<mode> hr=<hosts_routed> reason=<reason> ts=<timestamp>
//
// Read it with parseLine / node.eventsOf (helpers of events_lot32_helpers_test.go).
func lot33Hooks(out string) string {
	line := "{{event}} relay={{relay_id}} host={{hostname}} cause={{cause}} first={{first_seen_at}} enrolled={{enrolled_at}} " +
		"chain={{relay_chain}} mode={{mode}} hr={{hosts_routed}} reason={{reason}} ts={{timestamp}}\n"
	var hooks []map[string]any
	for _, ev := range lot33Events {
		hooks = append(hooks, map[string]any{"event": ev, "actions": []map[string]any{{"type": "file", "path": out, "append": line}}})
	}
	return mustJSONString(map[string]any{"hooks": hooks})
}

// firstSeenOf reads first_seen_at of GET /api/admin/minions/{host} ("" while absent).
func firstSeenOf(n *node, host string) string {
	code, raw := n.callOn(n.adminURL(), "GET", "/api/admin/minions/"+host, n.adminTok, nil)
	if code != http.StatusOK {
		return ""
	}
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return ""
	}
	s, _ := m["first_seen_at"].(string)
	return s
}

func countOf(n *node, ev, host string) int {
	return len(n.eventsOf(ev, map[string]string{"host": host}))
}

// (1a-c, 3) one node, the life of a host: discover THEN up at the first handshake (first_seen_at readable within seconds),
// no discover for a reconnection (same process, new process) nor for a re-enrollment without deletion, host.removed then
// host.deleted at the deletion, a new discover after delete + re-enrollment, a revocation raises no host.removed.
func TestLifecycle_HostDiscoverOnceRemovedOnDelete_RevokeRaisesNone(t *testing.T) {
	parallel(t)
	root := startNode(t, nodeSpec{ID: "root", Hooks: lot33Hooks})
	const h = "lc-host"

	// Q2: the hooks of this node subscribe to host.deleted: the load of the configuration warns (deprecated since v3.0.6,
	// removed in v3.0.7, use host.removed). The hook itself keeps running (checked below).
	if !root.logs.has("deprecated since v3.0.6, removed in v3.0.7, use host.removed") {
		t.Errorf("a configuration subscribed to host.deleted must log a [WARN] \"deprecated since v3.0.6, removed in v3.0.7, use host.removed\":\n%s", root.logs.String())
	}

	tok := root.enrollAgent(h)
	connectMinionWithToken(t, root, h, tok)
	waitFor(t, "host.discover", func() bool { return countOf(root, "host.discover", h) >= 1 })
	waitFor(t, "host.up", func() bool { return countOf(root, "host.up", h) >= 1 })
	if d, u := root.firstIndex("host.discover", map[string]string{"host": h}), root.firstIndex("host.up", map[string]string{"host": h}); d >= u {
		t.Errorf("host.discover must come BEFORE host.up (lines %d, %d):\n%s", d, u, strings.Join(root.hookLines(), "\n"))
	}
	d := root.eventsOf("host.discover", map[string]string{"host": h})[0]
	if d["first"] == "" || d["enrolled"] == "" || d["relay"] != "" {
		t.Errorf("host.discover must carry first_seen_at and enrolled_at (relay_id empty for a host): %v", d)
	}
	var first string
	waitFor(t, "first_seen_at in GET /minions/{h}", func() bool { first = firstSeenOf(root, h); return first != "" })

	// (1b) a reconnection of the same process (conn_seq 2) and a new process (conn_seq 1): no discover
	seq2, seq1 := "2", "1"
	dialAgentSeq(t, root, tok, &seq2)
	waitFor(t, "host.reconnect", func() bool { return countOf(root, "host.reconnect", h) >= 1 })
	dialAgentSeq(t, root, tok, &seq1)
	waitFor(t, "host.up of the new process", func() bool { return countOf(root, "host.up", h) >= 2 })

	// (1c) a re-enrollment of an EXISTING host (no deletion) keeps first_seen_at: no new discover
	tok2, err := root.enrollAgentErr(h)
	if err != nil {
		t.Fatalf("re-enrollment of an existing host: %v", err)
	}
	connectMinionWithToken(t, root, h, tok2)
	waitFor(t, "host.up after the re-enrollment", func() bool { return countOf(root, "host.up", h) >= 3 })
	if got := countOf(root, "host.discover", h); got != 1 {
		t.Errorf("%d host.discover after reconnections and a re-enrollment, want exactly 1", got)
	}
	if got := firstSeenOf(root, h); got != first {
		t.Errorf("first_seen_at changed (%q -> %q): a re-enrollment keeps it", first, got)
	}

	// (3) deletion: host.removed (cause deleted, first_seen_at) THEN the deprecated local host.deleted
	if code, raw := root.admin("DELETE", "/api/admin/minions/"+h, nil); code >= 300 {
		t.Fatalf("DELETE minion: %d %v", code, raw)
	}
	waitFor(t, "host.removed", func() bool { return countOf(root, "host.removed", h) >= 1 })
	waitFor(t, "host.deleted (deprecated, still emitted)", func() bool { return countOf(root, "host.deleted", h) >= 1 })
	r := root.eventsOf("host.removed", map[string]string{"host": h})
	if len(r) != 1 || r[0]["cause"] != "deleted" || r[0]["first"] != first {
		t.Errorf("host.removed: want exactly one, cause=deleted first=%s, got %v", first, r)
	}
	if rm, del := root.firstIndex("host.removed", map[string]string{"host": h}), root.firstIndex("host.deleted", map[string]string{"host": h}); rm >= del {
		t.Errorf("host.removed must come BEFORE host.deleted (lines %d, %d)", rm, del)
	}

	// re-enrollment after the deletion: the host is new again => a second discover
	connectMinionWithToken(t, root, h, root.enrollAgent(h))
	waitFor(t, "a new host.discover after delete + re-enrollment", func() bool { return countOf(root, "host.discover", h) >= 2 })

	// a revocation raises no host.removed
	const rv = "lc-revoked"
	connectMinionWithToken(t, root, rv, root.enrollAgent(rv))
	waitFor(t, "host.discover of the host to revoke", func() bool { return countOf(root, "host.discover", rv) >= 1 })
	if code, raw := root.admin("POST", "/api/admin/revoke/"+rv, nil); code >= 300 {
		t.Fatalf("revoke: %d %v", code, raw)
	}
	waitFor(t, "the revoked host is cut", func() bool { return countOf(root, "host.down", rv) >= 1 })
	time.Sleep(settle)
	if got := countOf(root, "host.removed", rv) + countOf(root, "host.deleted", rv); got != 0 {
		t.Errorf("a revocation raised %d host.removed/host.deleted, want 0", got)
	}
}

// (5, 6) a pull child: relay.discover BEFORE relay.up at the first link, none at the following links, then DELETE of the
// relay: relay.removed THEN relay.down reason=revoked (never a removed for a revocation, covered by the slow suite).
func TestLifecycle_RelayDiscoverOnceRemovedOnDelete(t *testing.T) {
	parallel(t)
	root := startNode(t, nodeSpec{ID: "root", Hooks: lot33Hooks})
	tok, id := root.registerChildWithID("lc-relay")
	startNode(t, nodeSpec{ID: "lc-relay", ParentURL: root.wssURL(), ParentToken: tok})
	want := map[string]string{"relay": "lc-relay"}
	waitFor(t, "relay.discover", func() bool { return len(root.eventsOf("relay.discover", want)) >= 1 })
	waitFor(t, "relay.up", func() bool { return len(root.eventsOf("relay.up", want)) >= 1 })
	if d, u := root.firstIndex("relay.discover", want), root.firstIndex("relay.up", want); d >= u {
		t.Errorf("relay.discover must come BEFORE relay.up (lines %d, %d):\n%s", d, u, strings.Join(root.hookLines(), "\n"))
	}
	e := root.eventsOf("relay.discover", want)[0]
	if e["mode"] != "pull" || e["first"] == "" || e["host"] != "" {
		t.Errorf("relay.discover: want mode=pull, first_seen_at set, no hostname: %v", e)
	}

	root.closeRelay("lc-relay", 1011) // a transient cut: the same process comes back
	waitFor(t, "relay.reconnect", func() bool { return len(root.eventsOf("relay.reconnect", want)) >= 1 })
	if got := len(root.eventsOf("relay.discover", want)); got != 1 {
		t.Errorf("%d relay.discover after a reconnection, want exactly 1", got)
	}

	if code, raw := root.admin("DELETE", "/api/admin/relays/"+id, nil); code >= 300 {
		t.Fatalf("DELETE relay: %d %v", code, raw)
	}
	waitFor(t, "relay.removed", func() bool { return len(root.eventsOf("relay.removed", want)) >= 1 })
	revoked := map[string]string{"relay": "lc-relay", "reason": "revoked"}
	waitFor(t, "relay.down reason=revoked", func() bool { return len(root.eventsOf("relay.down", revoked)) >= 1 })
	if rm, dn := root.firstIndex("relay.removed", want), root.firstIndex("relay.down", revoked); rm >= dn {
		t.Errorf("relay.removed must come BEFORE relay.down revoked (lines %d, %d):\n%s", rm, dn, strings.Join(root.hookLines(), "\n"))
	}
	if r := root.eventsOf("relay.removed", want); len(r) != 1 || r[0]["cause"] != "deleted" || r[0]["mode"] != "pull" {
		t.Errorf("relay.removed: want exactly one, cause=deleted mode=pull, got %v", r)
	}
}
