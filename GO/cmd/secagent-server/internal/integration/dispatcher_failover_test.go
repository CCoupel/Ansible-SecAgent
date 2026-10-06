package integration

import (
	"net/http"
	"testing"
)

// #171 A2/A3/A4 with the REAL minion (dispatcher + address list [standby B, A]): the enrollment goes
// through the list (B listens on nothing: the first address is refused, the second is the master), a clean
// stop of the master makes B take over and the minion follows through its list WITHOUT enrolling again; the
// new master's inventory lists the agent; then a kill -9 of B hands over to a third instance on A's addresses.
func TestFailover_RealMinionFollowsTheMasterThroughItsAddressList(t *testing.T) {
	parallel(t)
	addrA, addrB := newNodeAddrs(t), newNodeAddrs(t)
	a := startNode(t, nodeSpec{ID: "root", Env: addrA.env()})
	b := a.sibling()
	b.launchSecondary(addrB.env())
	t.Cleanup(b.stop)

	const host = "real-minion"
	m := startMinionProc(t, host, enrollmentToken(t, a, host), addrB, addrA) // the first address is the standby
	m.waitConnections(1, "the minion enrolled through its list and is connected to the master A")
	waitFor(t, "A serves the agent", func() bool { return agentServed(a, host, 1) })
	if got := m.logs.count("[INIT] No JWT found — enrolling"); got != 1 {
		t.Fatalf("the minion must enroll once at its first start, enrolled %d times", got)
	}
	if !a.hasHost(host) {
		t.Fatal("the master's inventory must list the enrolled agent")
	}

	// SIGTERM-like clean stop of the master: B promotes, the minion reconnects through its list
	a.stop()
	if !b.awaitPromotion(waitLimit) {
		t.Fatalf("the standby never took over; logs:\n%s", b.logs.String())
	}
	m.waitConnections(2, "the minion reconnected after the clean stop of the master")
	waitFor(t, "the new master serves the agent", func() bool { return agentServed(b, host, 1) })
	if !b.hasHost(host) {
		t.Error("the new master's inventory must list the agent")
	}
	if r := b.exec(host, map[string]any{"cmd": "echo via-b", "timeout": 20}); r.Code != http.StatusOK {
		t.Fatalf("exec through the new master = %d %v", r.Code, r.Body)
	}

	// kill -9 of the new master: a third instance on A's (free again) addresses takes over after the staleness delay
	c := b.sibling()
	c.launchSecondary(addrA.env())
	t.Cleanup(c.stop)
	waitFor(t, "the third instance polls the lock", func() bool { return c.localStatusPolled() })
	b.killNow()
	if !c.awaitPromotion(waitLimit) {
		t.Fatalf("the third instance never took over after the kill -9; logs:\n%s", c.logs.String())
	}
	m.waitConnections(3, "the minion reconnected after the kill -9 of the master")
	waitFor(t, "the last master serves the agent", func() bool { return agentServed(c, host, 1) })
	if !c.hasHost(host) {
		t.Error("the last master's inventory must list the agent")
	}
	if r := c.exec(host, map[string]any{"cmd": "echo via-c", "timeout": 20}); r.Code != http.StatusOK {
		t.Fatalf("exec through the last master = %d %v", r.Code, r.Body)
	}
	// never enrolled again through the two take-overs (the one-shot token is consumed anyway)
	if got := m.logs.count("[INIT] No JWT found — enrolling"); got != 1 {
		t.Errorf("the minion enrolled %d times: reconnection must reuse its JWT", got)
	}
	if m.logs.has("[FATAL]") {
		t.Errorf("the minion logged a fatal error:\n%s", m.logs.String())
	}
}
