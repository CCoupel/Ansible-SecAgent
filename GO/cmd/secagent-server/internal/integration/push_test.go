package integration

import (
	"net/http"
	"strings"
	"testing"
)

// (b) push direction: the PARENT opens the link (dial-out). Mixed tree: root ──push──▶ relay1
// ◀──pull── relay2 (relay1 accepts its parent and is itself the parent of a relay that dials it).
func TestPush_ParentDialsChild_ExecReachesDeepAgent(t *testing.T) {
	parallel(t)
	root := startNode(t, nodeSpec{ID: "root"})
	relay1 := startNode(t, nodeSpec{ID: "relay1"}) // no REPEATER_UPSTREAM_*: its parent will dial it
	relay2 := startNode(t, nodeSpec{ID: "relay2", ParentURL: relay1.wssURL(), ParentToken: relay1.registerChild("relay2")})
	waitFor(t, "relay2 linked to relay1 (pull)", func() bool { return relay2.upstreamState() == "connected" })

	mDeep := connectMinion(t, relay2, "host-deep")
	mMid := connectMinion(t, relay1, "host-mid")
	waitFor(t, "relay1 learns host-deep", func() bool { return relay1.hasHost("host-deep") })

	// The child mints the token for its parent; the parent registers it (push) and dials.
	parentTok, _ := relay1.mintParentToken("root")
	code, m := root.admin("POST", "/api/admin/relays", map[string]any{"relay_id": "relay1", "mode": "push", "url": relay1.wssURL(), "token": parentTok})
	if code != http.StatusCreated {
		t.Fatalf("register push child: %d %v", code, m)
	}
	if _, leaked := m["jwt_token"]; leaked || strings.Contains(string(mustJSON(t, m)), parentTok) {
		t.Error("the push registration response must not echo the token")
	}
	waitFor(t, "root dialer connected", func() bool { return root.pushState("relay1") == "connected" })
	waitFor(t, "relay1 sees its (dialed) parent", func() bool {
		u := relay1.health().Links.Upstream
		return u != nil && u.Mode == "push" && u.State == "connected"
	})

	// The snapshot sent at link-up carries relay1's direct agent AND the deep one (via relay2).
	waitFor(t, "root inventory has the mid and deep agents", func() bool { return root.hasHost("host-mid") && root.hasHost("host-deep") })

	for host, m := range map[string]*minion{"host-mid": mMid, "host-deep": mDeep} {
		r := root.exec(host, execBody("id"))
		if r.Code != http.StatusOK || r.Body["stdout"] != `ran "id" on `+host {
			t.Fatalf("exec %s through the push link = %d %v", host, r.Code, r.Body)
		}
		if got := m.received(); len(got) != 1 || got[0]["stdin"] == nil {
			t.Errorf("%s must have received the task with its stdin: %v", host, got)
		}
	}
	// file transfers follow the same path
	code, raw := root.call("POST", "/api/fetch/host-deep", root.pluginToken(), map[string]any{"src": "/etc/hostname"})
	if code != http.StatusOK || !strings.Contains(string(raw), "ZmV0Y2hlZA==") {
		t.Errorf("fetch through the push link = %d %s", code, raw)
	}
	assertNoSecrets(t, allLogs(root, relay1, relay2), parentTok)
}

// (g) since #126: with relay2 DECLARED to the root (it is part of relay1's snapshot at link-up), the
// host.up of a NEW agent connecting under relay2 routes it at the root at once — no new snapshot,
// no link cut. This is the only way the root can learn it: relay1's agent_list lists direct agents
// only, so only the forwarded event makes the deep host routable.
func TestPush_NewDeepHostIsRoutableFromItsHostUpWithoutNewSnapshot(t *testing.T) {
	parallel(t)
	root := startNode(t, nodeSpec{ID: "root"})
	relay1 := startNode(t, nodeSpec{ID: "relay1"})
	relay2 := startNode(t, nodeSpec{ID: "relay2", ParentURL: relay1.wssURL(), ParentToken: relay1.registerChild("relay2")})
	waitFor(t, "relay2 linked to relay1", func() bool { return relay2.upstreamState() == "connected" })
	parentTok, _ := relay1.mintParentToken("root")
	if code, m := root.admin("POST", "/api/admin/relays", map[string]any{"relay_id": "relay1", "mode": "push", "url": relay1.wssURL(), "token": parentTok}); code != http.StatusCreated {
		t.Fatalf("register push: %d %v", code, m)
	}
	waitFor(t, "root dialer connected", func() bool { return root.pushState("relay1") == "connected" })
	waitFor(t, "root received relay1's snapshot", func() bool { return root.logs.count("topology_snapshot: relay_id=relay1") >= 1 })

	m := connectMinion(t, relay2, "deep-after-link") // connects AFTER the snapshot was sent
	waitFor(t, "the root routes the new deep host", func() bool { return root.hasHost("deep-after-link") })
	if n := root.logs.count("topology_snapshot: relay_id=relay1"); n != 1 {
		t.Errorf("root received %d snapshots from relay1: the host must be learned from its host.up", n)
	}
	r := root.exec("deep-after-link", execBody("id"))
	if r.Code != http.StatusOK || r.Body["stdout"] != `ran "id" on deep-after-link` || len(m.received()) != 1 {
		t.Errorf("exec on the host learned from its event = %d %v", r.Code, r.Body)
	}
}
