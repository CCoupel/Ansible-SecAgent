package integration

import (
	"net/http"
	"testing"
)

// (d) a live local agent always wins over a relay declaring the same hostname: the task, its
// stdin and the files go to the local minion, never down the tree.
func TestRouting_LiveLocalAgentBeatsRelayClaim(t *testing.T) {
	t.Parallel()
	root := startNode(t, nodeSpec{ID: "root"})
	relay1 := startNode(t, nodeSpec{ID: "relay1", ParentURL: root.wssURL(), ParentToken: root.registerChild("relay1")})
	waitFor(t, "relay1 linked", func() bool { return relay1.upstreamState() == "connected" })

	local := connectMinion(t, root, "dup-host")
	remote := connectMinion(t, relay1, "dup-host") // relay1 declares the same hostname to the root
	// the claim reaches the root (relay1's agent_list lists dup-host, root processes it several times)
	// the claim reaches the root: it is reported as a host.conflict against the LOCAL owner, once,
	// and the host is not re-routed (relay1's agent_list is accepted with this host excluded)
	waitFor(t, "root reports the claim as host.conflict", func() bool { return root.logs.count("host.conflict: hostname=dup-host") >= 1 })
	base := root.logs.count("agent_list: relay_id=relay1")
	waitFor(t, "more agent_list rounds processed", func() bool { return root.logs.count("agent_list: relay_id=relay1") >= base+5 })
	if n := root.logs.count("host.conflict: hostname=dup-host"); n != 1 {
		t.Errorf("host.conflict against the local owner emitted %d times, want once", n)
	}

	if root.hasHost("dup-host") {
		t.Error("the claim of a relay must not create a route for a host connected to this node")
	}

	r := root.exec("dup-host", execBody("id"))
	if r.Code != http.StatusOK || r.Body["stdout"] != `ran "id" on dup-host` {
		t.Fatalf("exec = %d %v", r.Code, r.Body)
	}
	if got := local.received(); len(got) != 1 || got[0]["stdin"] == nil {
		t.Errorf("the local agent must run the task with its stdin: %v", got)
	}
	if got := remote.received(); len(got) != 0 {
		t.Errorf("the relay's minion must never see the task nor its become_pass: %v", got)
	}
	// same rule for file transfers
	if code, _ := root.call("POST", "/api/fetch/dup-host", root.pluginToken(), map[string]any{"src": "/etc/hostname"}); code != http.StatusOK {
		t.Errorf("fetch = %d", code)
	}
	if got := remote.received(); len(got) != 0 {
		t.Errorf("the relay's minion must never see the fetch: %v", got)
	}
	if got := local.received(); len(got) != 2 || got[1]["type"] != "fetch_file" {
		t.Errorf("the local agent must serve the fetch: %v", got)
	}
}

// (d) two relays declaring the same host: the conflict is reported (host.conflict naming both
// owners) a bounded number of times — NOT at every agent_list round — and once only one relay
// still claims the host, tasks follow it.
func TestRouting_DuplicateClaimEmitsHostConflictWithoutStorm(t *testing.T) {
	t.Parallel()
	root := startNode(t, nodeSpec{ID: "root"})
	relayA := startNode(t, nodeSpec{ID: "relayA", ParentURL: root.wssURL(), ParentToken: root.registerChild("relayA")})
	relayB := startNode(t, nodeSpec{ID: "relayB", ParentURL: root.wssURL(), ParentToken: root.registerChild("relayB")})
	waitFor(t, "relays linked", func() bool { return relayA.upstreamState() == "connected" && relayB.upstreamState() == "connected" })

	atA := connectMinion(t, relayA, "roamer")
	waitFor(t, "root routes roamer via relayA", func() bool { return root.hasHost("roamer") })
	if root.logs.count("host.conflict:") != 0 {
		t.Fatal("no conflict expected with a single owner")
	}

	atB := connectMinion(t, relayB, "roamer") // relayB now declares the same host while relayA still does
	waitFor(t, "host.conflict reported", func() bool { return root.logs.count("host.conflict: hostname=roamer") >= 1 })
	if !root.logs.has("old=relayA new=relayB") && !root.logs.has("old=relayB new=relayA") {
		t.Errorf("the conflict must name both owners:\n%s", root.logs.String())
	}
	rounds := func(n int) {
		base := root.logs.count("agent_list: relay_id=relayA") + root.logs.count("agent_list: relay_id=relayB")
		waitFor(t, "more agent_list rounds processed", func() bool {
			return root.logs.count("agent_list: relay_id=relayA")+root.logs.count("agent_list: relay_id=relayB") >= base+n
		})
	}
	rounds(8)
	settled := root.logs.count("host.conflict: hostname=roamer")
	rounds(16)
	if now := root.logs.count("host.conflict: hostname=roamer"); now != settled || now > 2 {
		t.Errorf("host.conflict count went from %d to %d over 16 more rounds: want bounded (<=2, one per direction) and stable", settled, now)
	}

	_ = atA.conn.Close() // only relayB declares it now
	var r execResult
	waitFor(t, "tasks follow the surviving owner", func() bool {
		r = root.exec("roamer", execBody("id"))
		return r.Code == http.StatusOK
	})
	if len(atB.received()) != 1 || len(atA.received()) != 0 {
		t.Errorf("the task must go to relayB's minion only: A=%v B=%v", atA.received(), atB.received())
	}
}
