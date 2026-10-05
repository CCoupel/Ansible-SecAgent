package integration

// Restart of a node on its PERSISTENT database: the harness keeps one SQLite file per node, and a
// restarted node reuses it (same identity, secrets, configuration and listening addresses).

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// hostvar returns one hostvar of a host of the node's aggregated inventory.
func hostvar(t *testing.T, n *node, host, key string) any {
	t.Helper()
	return n.inventoryHosts()[host][key]
}

// A middle relay is stopped and restarted on the SAME database: its child reconnects with the token
// it was given before (the registration survived), the routes and chains are rebuilt, a host.up of
// the leaf reaches the root with the exact chain; and a relay token revoked at the root stays
// refused after the ROOT itself restarts (blacklist and revoked flag are persistent).
func TestRestart_MidRelayAndRootKeepTheirStateOnTheirDatabase(t *testing.T) {
	parallel(t)
	root := startNode(t, nodeSpec{ID: "root", Hooks: standardHooks})
	mid := startNode(t, nodeSpec{ID: "mid", ParentURL: root.wssURL(), ParentToken: root.registerChild("mid"), Hooks: standardHooks})
	waitFor(t, "mid linked", func() bool { return mid.upstreamState() == "connected" })
	leaf := startNode(t, nodeSpec{ID: "leaf", ParentURL: mid.wssURL(), ParentToken: mid.registerChild("leaf"), Hooks: standardHooks})
	waitFor(t, "leaf linked", func() bool { return leaf.upstreamState() == "connected" })
	connectMinion(t, leaf, "m-leaf")
	waitFor(t, "root routes the leaf's host", func() bool { return root.hasHost("m-leaf") })
	if got := toStrings(hostvar(t, root, "m-leaf", "secagent_relay_chain")); len(got) != 2 || got[0] != "leaf" || got[1] != "mid" {
		t.Fatalf("chain before the restart = %v, want [leaf mid]", got)
	}

	// ── the middle relay restarts on its database ──
	connectedBefore := root.logs.count("Relay connected: relay_id=mid")
	mid.restart()
	waitFor(t, "the root saw the link of mid come back", func() bool { return root.logs.count("Relay connected: relay_id=mid") > connectedBefore })
	waitFor(t, "mid linked to the root again", func() bool { return mid.upstreamState() == "connected" })
	waitFor(t, "the leaf reconnected to mid with the token it already had", func() bool {
		return leaf.upstreamState() == "connected" && mid.logs.count("Relay connected: relay_id=leaf") >= 1
	})
	if code, m := mid.admin("GET", "/api/admin/relays", nil); code != http.StatusOK || !jsonHas(m, "leaf") {
		t.Errorf("mid forgot the registration of leaf across its restart: %d %v", code, m)
	}
	waitFor(t, "the root's routes and chains were rebuilt", func() bool {
		got := toStrings(hostvar(t, root, "m-leaf", "secagent_relay_chain"))
		return len(got) == 2 && got[0] == "leaf" && got[1] == "mid"
	})
	connectMinion(t, leaf, "after-restart")
	waitFor(t, "a host.up of the leaf reaches the root with the exact chain", func() bool {
		return root.hookHas("UP after-restart status=connected chain=leaf,mid origin=leaf")
	})
	if r := root.exec("after-restart", execBody("id")); r.Code != http.StatusOK {
		t.Errorf("exec through the restarted middle relay = %d %v", r.Code, r.Body)
	}

	// ── a relay token revoked at the root stays refused after the ROOT restarts ──
	victimTok, victimRow := root.registerChildWithID("victim")
	if code, m := root.admin("POST", "/api/admin/relays/"+victimRow+"/revoke", nil); code != http.StatusOK {
		t.Fatalf("revoke: %d %v", code, m)
	}
	if got := dialRelayWith(t, root, victimTok); got != http.StatusUnauthorized {
		t.Fatalf("revoked token before the restart = %d, want 401", got)
	}
	connectedBefore = root.logs.count("Relay connected: relay_id=mid")
	root.restart()
	waitFor(t, "mid reconnected to the restarted root", func() bool {
		return mid.upstreamState() == "connected" && root.logs.count("Relay connected: relay_id=mid") >= 1
	})
	if got := dialRelayWith(t, root, victimTok); got != http.StatusUnauthorized {
		t.Errorf("the revoked relay token after the root restarted = %d, want 401 (blacklist and revoked flag must be persistent)", got)
	}
	waitFor(t, "the restarted root routes the leaf's hosts again", func() bool { return root.hasHost("m-leaf") && root.hasHost("after-restart") })
	if code, m := root.admin("GET", "/api/admin/relays", nil); code != http.StatusOK || !jsonHas(m, "victim") {
		t.Errorf("the revoked relay's row must survive the restart: %d %v", code, m)
	}
	assertNoSecrets(t, allLogs(root, mid, leaf), append(nodeSecrets(root, mid, leaf), victimTok)...)
}

func jsonHas(m map[string]any, s string) bool {
	b, _ := json.Marshal(m)
	return len(b) > 0 && strings.Contains(string(b), `"`+s+`"`)
}
