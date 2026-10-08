package integration

// QA v3.0.4 R2 (d) — #180 over THREE levels. After the restart of the root (routes and flags are in
// memory only), the flag of an agent suspended two levels down is restored by the topology_snapshot that
// relay1 sends up, which must carry the flag of the agents of its DESCENDANTS (relay2's), not only its own.
// Mutant killed: buildSnapshot reporting `Suspended: false` for the agents of the descendants.

import (
	"net/http"
	"testing"
)

func TestSuspension_ThreeLevelsTheSnapshotRestoresTheFlagAfterTheRootRestarts(t *testing.T) {
	parallel(t)
	root := startNode(t, nodeSpec{ID: "root"})
	relay1 := startNode(t, nodeSpec{ID: "relay1", ParentURL: root.wssURL(), ParentToken: root.registerChild("relay1")})
	waitFor(t, "relay1 linked", func() bool { return relay1.upstreamState() == "connected" })
	relay2 := startNode(t, nodeSpec{ID: "relay2", ParentURL: relay1.wssURL(), ParentToken: relay1.registerChild("relay2")})
	waitFor(t, "relay2 linked", func() bool { return relay2.upstreamState() == "connected" })

	connectMinion(t, relay2, "deep-agent")
	connectMinion(t, relay2, "deep-other")
	waitFor(t, "root routes the agents two levels down", func() bool { return root.hasHost("deep-agent") && root.hasHost("deep-other") })

	if code, m := relay2.admin("POST", "/api/admin/minions/deep-agent/suspend", map[string]any{}); code != http.StatusOK {
		t.Fatalf("suspend: %d %v", code, m)
	}
	waitFor(t, "the flag crosses two links by event", func() bool { return suspendedAt(root, "deep-agent") })
	waitFor(t, "relay1 shows it too", func() bool { return suspendedAt(relay1, "deep-agent") })
	if suspendedAt(root, "deep-other") {
		t.Fatal("deep-other is not suspended")
	}

	root.restart() // routes and flags are in memory only: no event will be re-sent
	waitFor(t, "relay1 reconnected", func() bool { return relay1.upstreamState() == "connected" })
	waitFor(t, "the root routes the agents again", func() bool { return root.hasHost("deep-agent") && root.hasHost("deep-other") })
	waitFor(t, "the snapshot of relay1 restored the flag of its descendant's agent", func() bool { return suspendedAt(root, "deep-agent") })
	if suspendedAt(root, "deep-other") {
		t.Error("the flag must stay per agent: deep-other was never suspended")
	}

	// and the resume still travels up after the restart
	if code, _ := relay2.admin("POST", "/api/admin/minions/deep-agent/resume", map[string]any{}); code != http.StatusOK {
		t.Fatal("resume")
	}
	waitFor(t, "the flag disappears at the root", func() bool { return !suspendedAt(root, "deep-agent") })
}
