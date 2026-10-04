package integration

import (
	"encoding/base64"
	"net/http"
	"testing"
)

const becomeSecret = "S3cr3t-become-pass-9f31"

func execBody(cmd string) map[string]any {
	return map[string]any{
		"cmd": cmd, "timeout": 10, "become": true, "become_method": "sudo",
		"stdin": base64.StdEncoding.EncodeToString([]byte(becomeSecret)),
	}
}

// threeLevels starts root ← relay1 ← relay2 (pull links: every child opens its link).
func threeLevels(t *testing.T) (root, relay1, relay2 *node) {
	t.Helper()
	root = startNode(t, nodeSpec{ID: "root"})
	relay1 = startNode(t, nodeSpec{ID: "relay1", ParentURL: root.wssURL(), ParentToken: root.registerChild("relay1")})
	relay2 = startNode(t, nodeSpec{ID: "relay2", ParentURL: relay1.wssURL(), ParentToken: relay1.registerChild("relay2")})
	waitFor(t, "relay1 linked to root", func() bool { return relay1.upstreamState() == "connected" })
	waitFor(t, "relay2 linked to relay1", func() bool { return relay2.upstreamState() == "connected" })
	return
}

// (a) three levels: agents at every level, topology/agent_list propagation, an exec descending to
// the deepest agent and the result coming back up.
func TestChain_ThreeLevels_ExecDescendsAndResultAscends(t *testing.T) {
	t.Parallel()
	root, relay1, relay2 := threeLevels(t)
	mA := connectMinion(t, root, "host-root")
	mB := connectMinion(t, relay1, "host-l1")
	mC := connectMinion(t, relay2, "host-l2")

	// agent_list: each relay reports its DIRECT agents to its parent.
	waitFor(t, "relay1 learns host-l2 (agent_list from relay2)", func() bool { return relay1.hasHost("host-l2") })
	waitFor(t, "root learns host-l1 (agent_list from relay1)", func() bool { return root.hasHost("host-l1") })

	// (g) known limit before #126: host-l2 reached relay1 by agent_list, but an ancestor only learns
	// a DEEP host through the next topology_snapshot of the link below it.
	if root.hasHost("host-l2") {
		t.Fatal("known limit changed: the root already routes a deep host without a new snapshot — update this test and the docs")
	}
	if r := root.exec("host-l2", execBody("id")); r.Code == http.StatusOK {
		t.Fatalf("exec on an unknown deep host must fail before a new snapshot, got %v", r)
	}

	// A new snapshot (link re-established) makes the deep host routable at the root.
	root.closeRelay("relay1", 4012)
	waitFor(t, "root routes host-l2 after relay1's new topology_snapshot", func() bool { return root.hasHost("host-l2") })
	waitFor(t, "relay1 linked again", func() bool { return relay1.upstreamState() == "connected" })

	// exec: root → relay1 → relay2 → minion, result back up the same path.
	r := root.exec("host-l2", execBody("whoami"))
	if r.Code != http.StatusOK || r.Body["stdout"] != `ran "whoami" on host-l2` || r.Body["rc"] != float64(0) {
		t.Fatalf("deep exec = %d %v", r.Code, r.Body)
	}
	got := mC.received()
	if len(got) != 1 || got[0]["type"] != "exec" || got[0]["cmd"] != "whoami" ||
		got[0]["stdin"] != base64.StdEncoding.EncodeToString([]byte(becomeSecret)) || got[0]["become"] != true {
		t.Errorf("the deepest minion must receive the task with its stdin and become flag: %v", got)
	}
	if len(mA.received())+len(mB.received()) != 0 {
		t.Error("only the target minion may receive the task")
	}

	// the other levels work too
	if r := root.exec("host-l1", execBody("uname")); r.Code != http.StatusOK || r.Body["stdout"] != `ran "uname" on host-l1` {
		t.Errorf("exec on level 1 = %v", r)
	}
	if r := root.exec("host-root", execBody("date")); r.Code != http.StatusOK || r.Body["stdout"] != `ran "date" on host-root` {
		t.Errorf("exec on the root's own agent = %v", r)
	}
	if r := relay1.exec("host-l2", execBody("hostname")); r.Code != http.StatusOK || r.Body["stdout"] != `ran "hostname" on host-l2` {
		t.Errorf("exec from the intermediate relay = %v", r)
	}

	// (f) the become password, the admin / plugin tokens and the signing secrets never reach a log
	assertNoSecrets(t, allLogs(root, relay1, relay2), nodeSecrets(root, relay1, relay2)...)
}

// Scenario 5 of #129: after a cut the child reconnects by itself and the parent's view is
// re-synchronised, including agents that appeared while the link was down.
func TestChain_ReconnectResyncsInventory(t *testing.T) {
	t.Parallel()
	root := startNode(t, nodeSpec{ID: "root"})
	relay1 := startNode(t, nodeSpec{ID: "relay1", ParentURL: root.wssURL(), ParentToken: root.registerChild("relay1")})
	waitFor(t, "relay1 linked", func() bool { return relay1.upstreamState() == "connected" })
	connectMinion(t, relay1, "before-cut")
	waitFor(t, "root sees before-cut", func() bool { return root.hasHost("before-cut") })

	before := root.logs.count("Relay connected: relay_id=relay1")
	root.closeRelay("relay1", 4012)
	connectMinion(t, relay1, "during-cut") // may or may not be announced before the link is back
	waitFor(t, "relay1 reconnected", func() bool { return root.logs.count("Relay connected: relay_id=relay1") > before })
	waitFor(t, "inventory re-synchronised with both agents", func() bool { return root.hasHost("before-cut") && root.hasHost("during-cut") })
}
