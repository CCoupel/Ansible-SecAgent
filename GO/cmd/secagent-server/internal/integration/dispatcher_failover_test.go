package integration

import (
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"secagent-server/cmd/secagent-server/internal/localstatus"
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

// #171 A5: a command is RUNNING on the minion when the master is killed (kill -9). The client of the dead
// master gets an error; the new master never re-sends it and the minion never runs it again: the marker
// of the command holds exactly one line, and a later command through the new master still works (barrier:
// the minion processed messages after its reconnection).
func TestFailover_InFlightExecAtKillIsNeverExecutedTwice(t *testing.T) {
	parallel(t)
	addrA, addrB := newNodeAddrs(t), newNodeAddrs(t)
	a := startNode(t, nodeSpec{ID: "root", Env: addrA.env()})
	b := a.sibling()
	b.launchSecondary(addrB.env())
	t.Cleanup(b.stop)

	const host = "inflight-minion"
	m := startMinionProc(t, host, enrollmentToken(t, a, host), addrA, addrB)
	m.waitConnections(1, "the minion is connected to the master A")
	waitFor(t, "A serves the agent", func() bool { return agentServed(a, host, 1) })
	waitFor(t, "the standby polls the lock", b.localStatusPolled)

	marker := filepath.Join(t.TempDir(), "runs")
	tok := a.pluginToken()
	type result struct {
		code int
		err  error
	}
	res := make(chan result, 1)
	go func() {
		code, _, err := a.callErr("POST", a.apiURL(), "/api/exec/"+host, tok,
			map[string]any{"cmd": "echo run >> " + marker + "; sleep 20", "timeout": 60})
		res <- result{code, err}
	}()
	waitFor(t, "the command started on the minion (marker written)", func() bool {
		b, _ := os.ReadFile(marker)
		return strings.Count(string(b), "run\n") >= 1
	})
	a.killNow()
	select {
	case r := <-res:
		if r.err == nil && r.code == http.StatusOK {
			t.Fatalf("the client of a killed master must get an error, got %d", r.code)
		}
	case <-time.After(waitLimit):
		t.Fatal("the client of the killed master never got an answer")
	}

	if !b.awaitPromotion(waitLimit) {
		t.Fatalf("the standby never took over; logs:\n%s", b.logs.String())
	}
	m.waitConnections(2, "the minion reconnected to the new master")
	waitFor(t, "the new master serves the agent", func() bool { return agentServed(b, host, 1) })
	// barrier: a command sent through the new master is executed, so the minion processed messages after
	// its reconnection; had the interrupted command been replayed it would have run by now
	marker2 := filepath.Join(t.TempDir(), "runs2")
	if r := b.exec(host, map[string]any{"cmd": "echo second >> " + marker2, "timeout": 20}); r.Code != http.StatusOK {
		t.Fatalf("exec through the new master = %d %v", r.Code, r.Body)
	}
	if got, _ := os.ReadFile(marker); strings.Count(string(got), "run\n") != 1 {
		t.Errorf("the interrupted command ran %d times, want exactly 1:\n%s", strings.Count(string(got), "run\n"), got)
	}
	if got, _ := os.ReadFile(marker2); strings.Count(string(got), "second\n") != 1 {
		t.Errorf("the command sent through the new master ran %d times, want 1", strings.Count(string(got), "second\n"))
	}
}

// #171 A8-(2), with real processes: two secondaries observe the SAME stale lock of a killed master at the
// same time and both try to take it. Exactly one becomes master; the other goes back to waiting (no port,
// no write, still a secondary, still running); the lock names the winner.
func TestFailover_TwoSecondariesCollidingOnAStaleLockOnlyOneTakesOver(t *testing.T) {
	parallel(t)
	a := startNode(t, nodeSpec{ID: "root"})
	b1, b2 := a.sibling(), a.sibling()
	gates := []string{filepath.Join(t.TempDir(), "gate1"), filepath.Join(t.TempDir(), "gate2")}
	b1.setEnv("NODE_LOCK_CREATE_GATE", gates[0])
	b2.setEnv("NODE_LOCK_CREATE_GATE", gates[1])
	b1.launchSecondary(nil)
	t.Cleanup(b1.stop)
	b2.launchSecondary(nil)
	t.Cleanup(b2.stop)
	waitFor(t, "both secondaries poll the lock", func() bool { return b1.localStatusPolled() && b2.localStatusPolled() })

	a.killNow() // the lock goes stale for both
	// both instances are held right before the exclusive creation of the lock, then released together:
	// a REAL collision on the creation, whatever the machine load
	waitFor(t, "both secondaries judged the lock stale and are about to create it", func() bool {
		for _, g := range gates {
			if _, err := os.Stat(g + ".reached"); err != nil {
				return false
			}
		}
		return true
	})
	for _, g := range gates {
		if err := os.WriteFile(g, []byte("go"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var winner, loser *node
	select {
	case r := <-b1.pendingReady:
		b1.ready, winner, loser = r, b1, b2
	case r := <-b2.pendingReady:
		b2.ready, winner, loser = r, b2, b1
	case <-time.After(waitLimit):
		t.Fatalf("no secondary took over; logs:\n%s\n%s", b1.logs.String(), b2.logs.String())
	}

	// let the loser poll the lock at least twice AFTER the winner is master (a poll is its only activity)
	last := func() int64 { f, _ := localstatus.Read(loser.statusPath); return f.LastCheckAt }
	base := last()
	waitFor(t, "the loser polled the lock after the take-over", func() bool { return last() > base })
	base = last()
	waitFor(t, "the loser polled the lock again", func() bool { return last() > base })

	if !winner.logs.has("promoted to master") {
		t.Errorf("the winner must log its promotion:\n%s", winner.logs.String())
	}
	if loser.logs.has("promoted to master") {
		t.Errorf("the loser was promoted too:\n%s", loser.logs.String())
	}
	select {
	case <-loser.pendingReady:
		t.Error("the loser reported listening addresses: two masters")
	case <-loser.exited:
		t.Errorf("the loser exited (code %d); it must keep waiting:\n%s", loser.exitCode, loser.logs.String())
	default:
	}
	if f, err := localstatus.Read(loser.statusPath); err != nil || f.Role != "secondary" {
		t.Errorf("the loser's status = %+v (%v), want a secondary", f, err)
	}
	if p := listeningPorts(t, loser.cmd.Process.Pid); len(p) != 0 {
		t.Errorf("the loser listens on %v: it must hold no port", p)
	}
	l, ok := readLock(winner.stateDir)
	m := regexp.MustCompile(`promoted to master \(instance_id=([0-9a-f]+)\)`).FindStringSubmatch(winner.logs.String())
	if !ok || m == nil || l.InstanceID != m[1] || l.Role != "master" {
		t.Errorf("the lock %+v (present=%v) must name the winner %v as master", l, ok, m)
	}
	if code, body := winner.admin("GET", "/api/admin/status", nil); code != http.StatusOK {
		t.Errorf("the winner must serve its admin API: %d %v", code, body)
	}
}
