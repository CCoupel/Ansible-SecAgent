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
	parallel(t)
	root, relay1, relay2 := threeLevels(t)
	mA := connectMinion(t, root, "host-root")
	mB := connectMinion(t, relay1, "host-l1")
	mC := connectMinion(t, relay2, "host-l2")

	// agent_list: each relay reports its DIRECT agents to its parent.
	waitFor(t, "relay1 learns host-l2 (agent_list from relay2)", func() bool { return relay1.hasHost("host-l2") })
	waitFor(t, "root learns host-l1 (agent_list from relay1)", func() bool { return root.hasHost("host-l1") })

	// (g) relay2 joined AFTER relay1's link to the root: relay1 re-sends a full snapshot that declares
	// it (a replacement), so the deep host becomes routable at the root with NO link cut. The
	// expected state is deterministic: wait for it by condition.
	waitFor(t, "the root routes host-l2 (late relay announced by a replacement snapshot)", func() bool { return root.hasHost("host-l2") })
	if n := root.logs.count("Relay connected: relay_id=relay1"); n != 1 {
		t.Errorf("relay1 reconnected %d times: the late relay must be learned without any link cut", n)
	}

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
	parallel(t)
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

// #173: the suspension is decided by the relay that holds the agent; the parent relays the refusal.
func TestChain_SuspendedAgentBehindChildRelayIsRefusedAtTheRoot(t *testing.T) {
	parallel(t)
	root := startNode(t, nodeSpec{ID: "root"})
	relay1 := startNode(t, nodeSpec{ID: "relay1", ParentURL: root.wssURL(), ParentToken: root.registerChild("relay1")})
	waitFor(t, "relay1 linked", func() bool { return relay1.upstreamState() == "connected" })
	m := connectMinion(t, relay1, "host-susp")
	waitFor(t, "root learns host-susp", func() bool { return root.hasHost("host-susp") })

	if r := root.exec("host-susp", execBody("id")); r.Code != http.StatusOK {
		t.Fatalf("baseline exec = %d %v", r.Code, r.Body)
	}
	if code, _ := relay1.admin("POST", "/api/admin/minions/host-susp/suspend", nil); code != http.StatusOK {
		t.Fatalf("suspend on relay1 = %d", code)
	}
	r := root.exec("host-susp", execBody("whoami"))
	if r.Code != http.StatusServiceUnavailable || r.Body["error"] != "agent_suspended" {
		t.Fatalf("exec on a suspended agent behind a child relay = %d %v, want 503 agent_suspended", r.Code, r.Body)
	}
	if got := m.received(); len(got) != 1 {
		t.Errorf("the suspended minion must not receive the task (baseline only): %v", got)
	}
	if code, _ := relay1.admin("POST", "/api/admin/minions/host-susp/resume", nil); code != http.StatusOK {
		t.Fatalf("resume = %d", code)
	}
	if r := root.exec("host-susp", execBody("id")); r.Code != http.StatusOK {
		t.Errorf("exec after resume = %d %v", r.Code, r.Body)
	}
}
