package integration

import (
	"net/http"
	"testing"
)

// (d) a live local agent always wins over a relay declaring the same hostname: the task, its
// stdin and the files go to the local minion, never down the tree.
func TestRouting_LiveLocalAgentBeatsRelayClaim(t *testing.T) {
	parallel(t)
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

	// (the host is enrolled on the root, so the inventory lists it anyway: the route table is the check)
	if n := root.dbScalar("SELECT COUNT(*) FROM relay_routing WHERE hostname = 'dup-host'"); n != "0" {
		t.Errorf("the claim of a relay must not create a route for a host connected to this node (routes: %s)", n)
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

// (d) two relays declaring the same host: host.conflict is emitted an EXACT number of times —
// once per change of owner as seen by each claimant — and never again at the following agent_list
// rounds. The steps are serialised (each waits for the previous one by condition), so the expected
// counts are exact, not bounds: a regression of one emission, in either direction, fails.
func TestRouting_DuplicateClaimEmitsHostConflictWithoutStorm(t *testing.T) {
	parallel(t)
	root := startNode(t, nodeSpec{ID: "root"})
	relayA := startNode(t, nodeSpec{ID: "relayA", ParentURL: root.wssURL(), ParentToken: root.registerChild("relayA")})
	relayB := startNode(t, nodeSpec{ID: "relayB", ParentURL: root.wssURL(), ParentToken: root.registerChild("relayB")})
	waitFor(t, "relays linked", func() bool { return relayA.upstreamState() == "connected" && relayB.upstreamState() == "connected" })

	conflicts := func() int { return root.logs.count("host.conflict: hostname=roamer") }
	// rounds waits until the root has processed n more agent_list messages from EACH relay: the
	// claims of both have been re-evaluated n times since the call
	rounds := func(n int) {
		t.Helper()
		a0, b0 := root.logs.count("agent_list: relay_id=relayA"), root.logs.count("agent_list: relay_id=relayB")
		waitFor(t, "more agent_list rounds from both relays", func() bool {
			return root.logs.count("agent_list: relay_id=relayA") >= a0+n && root.logs.count("agent_list: relay_id=relayB") >= b0+n
		})
	}

	// 1. A declares the host alone: it owns it, no conflict
	atA := connectMinion(t, relayA, "roamer")
	waitFor(t, "root routes roamer via relayA", func() bool { return root.hasHost("roamer") })
	rounds(4)
	if n := conflicts(); n != 0 {
		t.Fatalf("step 1: %d host.conflict with a single owner, want 0", n)
	}

	// 2. B declares it too while A still does: ONE conflict per claimant's view of the owner change
	// (relayA→relayB seen by B's claim, relayB→relayA seen by A's next claim) = exactly 2
	atB := connectMinion(t, relayB, "roamer")
	waitFor(t, "both directions reported", func() bool { return conflicts() >= 2 })
	rounds(16) // many more rounds with BOTH still claiming: nothing more may be emitted
	if n := conflicts(); n != 2 {
		t.Fatalf("step 2: %d host.conflict, want exactly 2", n)
	}
	if a, b := root.logs.count("old=relayA new=relayB"), root.logs.count("old=relayB new=relayA"); a != 1 || b != 1 {
		t.Errorf("step 2: relayA→relayB reported %d times and relayB→relayA %d times, want once each", a, b)
	}

	// 3. A stops claiming (its claim ended), B keeps claiming: nothing new
	_ = atA.conn.Close()
	waitFor(t, "relayA's list no longer holds the host", func() bool { return relayA.logs.count("Agent disconnected: hostname=roamer") >= 1 })
	rounds(16)
	if n := conflicts(); n != 2 {
		t.Fatalf("step 3: %d host.conflict after A stopped claiming, want still 2", n)
	}
	var r execResult
	waitFor(t, "tasks follow the only claimant", func() bool {
		r = root.exec("roamer", execBody("id"))
		return r.Code == http.StatusOK
	})
	if len(atB.received()) != 1 {
		t.Errorf("step 3: the task must go to relayB's minion, got %v", atB.received())
	}

	// 4. A claims again: its previous report was forgotten when its claim ended, so the change of
	// owner is reported ONE more time (relayB→relayA) — and B's kept memory suppresses the echo
	connectMinion(t, relayA, "roamer")
	waitFor(t, "the renewed claim is reported", func() bool { return conflicts() >= 3 })
	rounds(16)
	if n := conflicts(); n != 3 {
		t.Fatalf("step 4: %d host.conflict, want exactly 3", n)
	}
	if b := root.logs.count("old=relayB new=relayA"); b != 2 {
		t.Errorf("step 4: relayB→relayA reported %d times, want 2 (steps 2 and 4)", b)
	}
}

// (d) a conflict detected BELOW the root travels up the tree as an event: the root reports it too
// (hooks fire at every level), without the root ever seeing the two claimants.
func TestRouting_ConflictDetectedBelowIsReportedAtTheRoot(t *testing.T) {
	parallel(t)
	root := startNode(t, nodeSpec{ID: "root"})
	mid := startNode(t, nodeSpec{ID: "mid", ParentURL: root.wssURL(), ParentToken: root.registerChild("mid")})
	waitFor(t, "mid linked", func() bool { return mid.upstreamState() == "connected" })
	leafA := startNode(t, nodeSpec{ID: "leafA", ParentURL: mid.wssURL(), ParentToken: mid.registerChild("leafA")})
	leafB := startNode(t, nodeSpec{ID: "leafB", ParentURL: mid.wssURL(), ParentToken: mid.registerChild("leafB")})
	waitFor(t, "leaves linked", func() bool { return leafA.upstreamState() == "connected" && leafB.upstreamState() == "connected" })

	connectMinion(t, leafA, "twin")
	connectMinion(t, leafB, "twin") // the same host is declared by two leaves under mid
	waitFor(t, "mid detects the conflict", func() bool { return mid.logs.count("host.conflict: hostname=twin") >= 1 })
	waitFor(t, "the root is told about the conflict that happened below", func() bool { return root.logs.count("host.conflict: hostname=twin") >= 1 })
}
