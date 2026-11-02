package integration

import (
	"testing"
	"time"
)

// #225 — host.up for the hosts BEHIND A CHILD after a fail-over of the root.
//
// Root A (active) / B (passive) share one state and one hooks configuration; a pull child relay1 knows both
// addresses of the root; a leaf agent is connected to the CHILD only. The leaf triggers host.up on the master A
// (through the child's event_forward). A is killed, B takes over, the child reconnects to B and re-sends its
// topology_snapshot: B routes the leaf again, but the leaf itself NEVER reconnected.
//
// The question of the issue is whether B then runs a host.up hook for the leaf. The test states the CURRENT
// behaviour and the expected one separately, so that the result (red / green) is read from the test name:
//   - TestFailoverChildHosts_NewMasterRoutesTheLeafWithoutAnEvent (must be GREEN today): the route is rebuilt;
//   - TestFailoverChildHosts_NewMasterRunsHostUpForTheLeafFromSnapshot (decision D5/#225: RED until the
//     snapshot emits host.up with from_snapshot=true).
func childBehindFailoverRoot(t *testing.T) (a, b, child *node) {
	t.Helper()
	addrA, addrB := newNodeAddrs(t), newNodeAddrs(t)
	a = startNode(t, nodeSpec{ID: "root", Env: addrA.env(), Hooks: func(out string) string {
		return `{"hooks":[{"event":"host.up","actions":[{"type":"file","path":"` + out + `","append":"up {{hostname}}\n"}]}]}`
	}})
	tok := a.registerChild("relay1")
	b = a.sibling()
	b.launchSecondary(addrB.env())
	t.Cleanup(b.stop)
	waitFor(t, "the standby polls the lock", b.localStatusPolled)
	child = startNode(t, nodeSpec{ID: "relay1", ParentURL: "wss://" + addrA.ws + ",wss://" + addrB.ws, ParentToken: tok})
	waitFor(t, "the child is linked to the active root", func() bool { return child.upstreamState() == "connected" })
	connectMinion(t, child, "leaf-host")
	waitFor(t, "the active root routes the leaf host", func() bool { return a.hasHost("leaf-host") })
	waitFor(t, "the master ran host.up for the leaf behind the child", func() bool { return a.hookCount("up leaf-host") >= 1 })
	return a, b, child
}

func switchOverAndWaitForTheLeafRoute(t *testing.T, a, b, child *node) {
	t.Helper()
	a.killNow()
	if !b.awaitPromotion(30 * time.Second) {
		t.Fatalf("the passive root never took over; logs:\n%s", b.logs.String())
	}
	waitFor(t, "the child reconnected to the NEW master", func() bool {
		return b.logs.has("Relay connected: relay_id=relay1") && child.upstreamState() == "connected"
	})
	waitFor(t, "the new master routes the leaf host again", func() bool { return b.hasHost("leaf-host") })
}

// Fact established first: the route IS rebuilt from the snapshot (green today).
func TestFailoverChildHosts_NewMasterRoutesTheLeafWithoutAnEvent(t *testing.T) {
	parallel(t)
	a, b, child := childBehindFailoverRoot(t)
	before := b.hookCount("up leaf-host") // shared output file: what the old master already ran
	switchOverAndWaitForTheLeafRoute(t, a, b, child)
	t.Logf("host.up lines for the leaf: before the switch-over %d, after the route is rebuilt %d", before, b.hookCount("up leaf-host"))
}

// Decision #225 (plan D: from_snapshot=true): the new master runs a host.up hook for a host discovered by snapshot
// after the switch-over, flagged from_snapshot. RED until dev-relay Batch 2: today the count does not move.
func TestFailoverChildHosts_NewMasterRunsHostUpForTheLeafFromSnapshot(t *testing.T) {
	parallel(t)
	a, b, child := childBehindFailoverRoot(t)
	before := b.hookCount("up leaf-host")
	switchOverAndWaitForTheLeafRoute(t, a, b, child)
	// leave the hooks queue time to run what the snapshot would have emitted
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && b.hookCount("up leaf-host") <= before {
		time.Sleep(100 * time.Millisecond)
	}
	if got := b.hookCount("up leaf-host"); got <= before {
		t.Fatalf("the new master ran no host.up for the leaf behind the child after the switch-over (hook lines %d -> %d): the topology_snapshot rebuilt the route without an event (#225)", before, got)
	}
}
