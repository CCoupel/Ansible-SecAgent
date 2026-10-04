package integration

import (
	"net/http"
	"strings"
	"testing"
)

// (b) push direction: the PARENT opens the link (dial-out). Mixed tree: root ──push──▶ relay1
// ◀──pull── relay2 (relay1 accepts its parent and is itself the parent of a relay that dials it).
func TestPush_ParentDialsChild_ExecReachesDeepAgent(t *testing.T) {
	t.Parallel()
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
