package integration

// `state link-trust reset` end to end: a relay pinned on root A cannot be re-pinned on root B (the
// persisted anchor wins and the start is refused); after the offline reset it accepts the new anchor and
// the links signed by root B, and keeps its agents.

import (
	"testing"
	"time"

	"secagent-server/cmd/secagent-server/internal/state"
)

func TestLinkTrustReset_AllowsRePinningOnANewRoot(t *testing.T) {
	parallel(t)
	rootA := startNode(t, nodeSpec{ID: "root"})
	relay1 := startNode(t, nodeSpec{ID: "relay1", ParentURL: rootA.wssURL(), ParentToken: rootA.registerChild("relay1")})
	waitFor(t, "relay1 linked", func() bool { return relay1.upstreamState() == "connected" })
	connectMinion(t, relay1, "agent-a")
	relay1.stop()

	// a rebuilt root (new key, same relay_id): relay1 pinned on it is refused at start
	rootB := startNode(t, nodeSpec{ID: "root2"})
	relay1.anchorTo(rootB)
	_, _ = relay1.startProcess(nil)
	if code, exited := relay1.waitExit(20 * time.Second); !exited || code == 0 {
		t.Fatalf("a different pinned key must refuse to start (exited=%v code=%d):\n%s", exited, code, relay1.logs.String())
	}

	// offline reset (the node is stopped: its lock is gone), then the new anchor is accepted
	res, err := state.ResetLinkTrust(state.LinkTrustResetOptions{Dir: relay1.stateDir, MasterKey: "integration-master-key-relay1", Operator: "test"})
	if err != nil || !res.Changed || res.BackupFile == "" {
		t.Fatalf("reset: %+v %v", res, err)
	}
	relay1.setEnv("REPEATER_UPSTREAM_URL", rootB.wssURL())
	relay1.setEnv("REPEATER_UPSTREAM_TOKEN", rootB.registerChild("relay1"))
	relay1.restart()
	waitFor(t, "relay1 re-pinned and linked to the new root", func() bool { return relay1.upstreamState() == "connected" })
	// its agent was kept, and a child signed by the NEW root is accepted by the re-pinned relay
	child := startNode(t, nodeSpec{ID: "relay2", ParentURL: relay1.wssURL(), ParentToken: relay1.registerChild("relay2")})
	waitFor(t, "a child of the re-pinned relay links", func() bool { return child.upstreamState() == "connected" })
	if _, ok := relay1.stateSection("agents")["agent-a"]; !ok {
		t.Error("the reset must keep the agents of the relay")
	}
	connectMinion(t, relay1, "agent-b")
	waitFor(t, "an agent of the re-pinned relay is routed at the new root", func() bool { return rootB.hasHost("agent-b") })
}
