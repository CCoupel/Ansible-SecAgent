package integration

// Active/passive tests with REAL processes (#163): two (or three) instances of the same node share
// one STATE_DIR. The children run the fast lock calibration (lockProfileFast: beat 400 ms, check
// 200 ms, master stale 7 s) so that a crash is recovered in seconds.

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"secagent-server/cmd/secagent-server/internal/localstatus"
	"secagent-server/internal/testnet"
)

// listeningPorts returns the TCP ports the process listens on (Linux: /proc).
func listeningPorts(t *testing.T, pid int) []int {
	t.Helper()
	inodes := map[string]bool{}
	fds, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid))
	if err != nil {
		t.Fatalf("read /proc/%d/fd: %v", pid, err)
	}
	for _, fd := range fds {
		l, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%s", pid, fd.Name()))
		if err == nil && strings.HasPrefix(l, "socket:[") {
			inodes[strings.TrimSuffix(strings.TrimPrefix(l, "socket:["), "]")] = true
		}
	}
	var ports []int
	for _, f := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		fh, err := os.Open(f)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(fh)
		sc.Scan() // header
		for sc.Scan() {
			cols := strings.Fields(sc.Text())
			if len(cols) < 10 || cols[3] != "0A" || !inodes[cols[9]] { // 0A = LISTEN
				continue
			}
			if i := strings.LastIndex(cols[1], ":"); i >= 0 {
				if p, err := strconv.ParseInt(cols[1][i+1:], 16, 32); err == nil {
					ports = append(ports, int(p))
				}
			}
		}
		_ = fh.Close()
	}
	sort.Ints(ports)
	return ports
}

func dirNames(t *testing.T, dir string) []string {
	t.Helper()
	es, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range es {
		out = append(out, e.Name())
	}
	sort.Strings(out)
	return out
}

// lockFile is the decoded content of relay.lock.
type lockFile struct {
	InstanceID string `json:"instance_id"`
	Role       string `json:"role"`
	Beat       uint64 `json:"beat"`
	Seq        uint64 `json:"write_seq"`
}

func readLock(dir string) (lockFile, bool) {
	raw, err := os.ReadFile(filepath.Join(dir, "relay.lock"))
	if err != nil {
		return lockFile{}, false
	}
	var l lockFile
	if json.Unmarshal([]byte(strings.TrimSpace(string(raw))), &l) != nil {
		return lockFile{}, false
	}
	return l, true
}

func stateWriteSeq(t *testing.T, dir string) uint64 {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "relay.state"))
	if err != nil {
		t.Fatal(err)
	}
	var e struct {
		Seq uint64 `json:"write_seq"`
	}
	if err := json.Unmarshal(raw, &e); err != nil {
		t.Fatal(err)
	}
	return e.Seq
}

func (n *node) status(t *testing.T) localstatus.File {
	t.Helper()
	f, err := localstatus.Read(n.statusPath)
	if err != nil {
		t.Fatalf("status file of %s: %v", n.id, err)
	}
	return f
}

func (n *node) healthy(t *testing.T) (bool, string) {
	t.Helper()
	return localstatus.Verdict(n.status(t), time.Now())
}

// freeAddr returns a loopback address nobody listens on right now.
func freeAddr(t *testing.T) string {
	t.Helper()
	return testnet.ClosedAddr(t) // outside the ephemeral range: nobody can take it before the node binds it
}

// A secondary opens NO socket, starts nothing and writes nothing in STATE_DIR but the lock itself;
// the master serves and both report a healthy local status.
func TestFailover_SecondaryHasNoPortAndWritesNothing(t *testing.T) {
	parallel(t)
	a := startNode(t, nodeSpec{ID: "root"})
	before := dirNames(t, a.stateDir)
	stateRaw, _ := os.ReadFile(filepath.Join(a.stateDir, "relay.state"))

	b := a.sibling()
	b.launchSecondary(nil)
	t.Cleanup(b.stop)
	waitFor(t, "the secondary polls the lock", func() bool {
		f, err := localstatus.Read(b.statusPath)
		return err == nil && f.Role == "secondary" && f.LastCheckAt > 0
	})
	time.Sleep(1500 * time.Millisecond) // several poll cycles

	if p := listeningPorts(t, b.cmd.Process.Pid); len(p) != 0 {
		t.Fatalf("a secondary must listen on NOTHING, it listens on %v", p)
	}
	if got := dirNames(t, a.stateDir); strings.Join(got, ",") != strings.Join(before, ",") {
		t.Errorf("STATE_DIR content changed while a secondary waited: %v -> %v", before, got)
	}
	if after, _ := os.ReadFile(filepath.Join(a.stateDir, "relay.state")); string(after) != string(stateRaw) {
		t.Error("relay.state was written while a secondary waited")
	}
	if b.logs.has("Listening") || b.logs.has("[LISTEN]") || b.logs.has("State loaded") {
		t.Errorf("a secondary must not start anything:\n%s", b.logs.String())
	}
	if ok, why := b.healthy(t); !ok {
		t.Errorf("healthy secondary reported unhealthy: %s", why)
	}
	if ok, why := a.healthy(t); !ok {
		t.Errorf("healthy master reported unhealthy: %s", why)
	}
	if st := a.status(t); st.Role != "master" || st.State != localstatus.StateReady || st.StateMode != localstatus.ModeReadWrite || st.WriteSeq == 0 {
		t.Errorf("master status = %+v, want master/ready/read_write with a write_seq", st)
	}
	if st := b.status(t); st.StateMode != localstatus.ModeReadOnly {
		t.Errorf("a secondary is read_only, got %+v", st)
	}
	if code, m := a.admin("GET", "/api/admin/status", nil); code != 200 || m["state_mode"] != "read_write" || m["role"] != "master" ||
		m["instance_id"] != a.status(t).InstanceID || m["write_seq"] == nil || m["last_beat_at"] == nil {
		t.Errorf("admin status of the master: %d %v", code, m)
	}
	if h := a.publicHealth(); !strings.Contains(h, "master") || !strings.Contains(h, a.status(t).InstanceID) {
		t.Errorf("/health must expose role and instance_id: %s", h)
	}
	if l, ok := readLock(a.stateDir); !ok || l.Role != "master" || l.InstanceID != a.status(t).InstanceID {
		t.Errorf("relay.lock = %+v", l)
	}
}

// SIGTERM: the lock is deleted and a waiting secondary takes over at once, ports serving — WITHOUT waiting
// for the lock to go stale. The staleness delay is set to 10 minutes on both instances: the only way the
// secondary can take over within the bound below is the RELEASED lock (no wall-clock threshold to
// tune against the machine load; the absolute < 10 s requirement is TestFailover_CleanStopTakeoverOnTheProductionCalibrationIsUnder10Seconds).
func TestFailover_CleanStopReleasesTheLockAndTheSecondaryTakesOverFast(t *testing.T) {
	parallel(t)
	a := startNode(t, nodeSpec{ID: "root", Env: []string{"NODE_LOCK_MASTER_STALE=10m"}})
	b := a.sibling()
	b.launchSecondary(nil)
	t.Cleanup(b.stop)
	waitFor(t, "the secondary polls the lock", func() bool {
		f, err := localstatus.Read(b.statusPath)
		return err == nil && f.LastCheckAt > 0
	})

	start := time.Now()
	a.stop()
	if code, ok := a.waitExit(waitLimit); !ok || code != 0 {
		t.Fatalf("clean stop: exit %d (exited=%v)", code, ok)
	}
	// a stale lock would need 10 minutes: promotion within waitLimit proves the lock was released
	if !b.awaitPromotion(waitLimit) {
		t.Fatalf("the secondary did not take over (the lock must be released by a clean stop; staleness is 10 min); logs:\n%s", b.logs.String())
	}
	t.Logf("takeover after %v", time.Since(start))
	if code, body := b.admin("GET", "/api/admin/status", nil); code != 200 {
		t.Errorf("the new master must serve its admin API: %d %v", code, body)
	}
	if ok, why := b.healthy(t); !ok {
		t.Errorf("new master unhealthy: %s", why)
	}
}

// kill -9: the secondary takes over after the staleness delay; the state is intact (an enrolled agent
// is still there) and the agent reconnects to the new master.
func TestFailover_Kill9TakeoverAfterTheStalenessDelayStateIntact(t *testing.T) {
	parallel(t)
	a := startNode(t, nodeSpec{ID: "root"})
	tok := a.enrollAgent("survivor")
	b := a.sibling()
	b.launchSecondary(nil)
	t.Cleanup(b.stop)
	waitFor(t, "the secondary polls the lock", func() bool {
		f, err := localstatus.Read(b.statusPath)
		return err == nil && f.LastCheckAt > 0
	})

	start := time.Now()
	a.killNow()
	if b.awaitPromotion(500 * time.Millisecond) {
		t.Fatal("the secondary must wait for the master lock to go stale, not take over at once")
	}
	if !b.awaitPromotion(30 * time.Second) {
		t.Fatalf("the secondary never took over; logs:\n%s", b.logs.String())
	}
	stale := lockProfileFast().MasterStale
	t.Logf("takeover after the crash: %v (master stale = %v)", time.Since(start), stale)
	if time.Since(start) < stale-time.Second {
		t.Errorf("took over after %v: too early for a %v staleness", time.Since(start), stale)
	}
	m := connectMinionWithToken(t, b, "survivor", tok) // same enrollment, no re-enrollment
	waitFor(t, "the agent is connected to the new master", func() bool { return b.hasHost("survivor") })
	_ = m
	if _, ok := b.stateSection("agents")["survivor"]; !ok {
		t.Error("the enrolled agent is missing from the state of the new master")
	}
}

// A frozen master (SIGSTOP) is evicted; when it wakes up (SIGCONT) its guard refuses, it closes its
// links with 1001 (never 4001), writes nothing and exits with the dedicated code 75.
func TestFailover_FrozenMasterWakesUpEvictedAndExits(t *testing.T) {
	parallel(t)
	a := startNode(t, nodeSpec{ID: "root"})
	m := connectMinion(t, a, "witness")
	b := a.sibling()
	b.launchSecondary(nil)
	t.Cleanup(b.stop)
	waitFor(t, "the secondary polls the lock", func() bool {
		f, err := localstatus.Read(b.statusPath)
		return err == nil && f.LastCheckAt > 0
	})

	a.freeze()
	if !b.awaitPromotion(30 * time.Second) {
		a.thaw()
		t.Fatalf("the secondary never took over the frozen master; logs:\n%s", b.logs.String())
	}
	seqAtTakeover := stateWriteSeq(t, a.stateDir)
	a.thaw()

	code, ok := a.waitExit(20 * time.Second)
	if !ok || code != 75 {
		t.Fatalf("the evicted master must exit with 75 (lock lost): code=%d exited=%v; logs:\n%s", code, ok, a.logs.String())
	}
	cc, closed := m.closeCode(5 * time.Second)
	if !closed {
		t.Fatal("the minion link of the evicted master was not closed")
	}
	if cc == 4001 {
		t.Fatal("close code 4001 (revoked: must not reconnect) forbids the minion to join the new master")
	}
	if cc != 1001 && cc != 4000 {
		t.Errorf("close code %d, want 1001 (Going Away) or 4000", cc)
	}
	if !a.logs.has("lock lost") {
		t.Errorf("the loss must be logged:\n%s", a.logs.String())
	}
	if st, err := localstatus.Read(a.statusPath); err != nil || st.State != localstatus.StateLost {
		t.Errorf("status of the evicted master = %+v %v, want lost", st, err)
	}
	if ok, _ := a.healthy(t); ok {
		t.Error("a process that lost the lock must be reported unhealthy by status --local")
	}
	if st := a.status(t); st.StateMode != localstatus.ModeReadOnly {
		t.Errorf("after the loss the mode is read_only, got %+v", st)
	}
	// nothing was written by the evicted master: the state still carries the new master's lineage
	if seq := stateWriteSeq(t, a.stateDir); seq < seqAtTakeover {
		t.Errorf("write_seq went backwards (%d -> %d)", seqAtTakeover, seq)
	}
	if ports := listeningPorts(t, b.cmd.Process.Pid); len(ports) == 0 {
		t.Error("the new master must be serving")
	}
}

// A lock deleted under a running master (the tampering / delayed deletion of case 5) is a loss:
// listeners closed, WebSockets closed with 1001, exit 75, and no hook action runs afterwards.
func TestLoss_LockDeletedUnderTheMasterClosesEverythingWith1001(t *testing.T) {
	parallel(t)
	a := startNode(t, nodeSpec{ID: "root"})
	m := connectMinion(t, a, "witness")
	pid := a.cmd.Process.Pid
	if err := os.Remove(filepath.Join(a.stateDir, "relay.lock")); err != nil {
		t.Fatal(err)
	}
	code, ok := a.waitExit(10 * time.Second)
	if !ok || code != 75 {
		t.Fatalf("exit code %d (exited=%v), want 75; logs:\n%s", code, ok, a.logs.String())
	}
	_ = pid
	cc, closed := m.closeCode(3 * time.Second)
	if !closed || cc == 4001 || (cc != 1001 && cc != 4000) {
		t.Fatalf("minion close: closed=%v code=%d, want 1001/4000 and never 4001", closed, cc)
	}
	// the API port no longer answers
	if _, err := net.DialTimeout("tcp", a.ready.API, time.Second); err == nil {
		t.Error("the listeners must be closed after the loss")
	}
}

// Replay protection: a secondary that read write_seq N in the lock refuses to become master on an
// older authentic copy of relay.state, and on an older relay.state.prev: SECURITY WARNING, non-zero
// exit, no port, lock released.
func TestReplay_OlderStateCopyIsRefusedByTheNewMaster(t *testing.T) {
	for name, tamper := range map[string]func(t *testing.T, dir, old string){
		"older copy of relay.state": func(t *testing.T, dir, old string) {
			if err := os.Rename(old, filepath.Join(dir, "relay.state")); err != nil {
				t.Fatal(err)
			}
		},
		"relay.state deleted, fallback on an older .prev": func(t *testing.T, dir, old string) {
			if err := os.Remove(filepath.Join(dir, "relay.state")); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(old, filepath.Join(dir, "relay.state.prev")); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			parallel(t)
			a := startNode(t, nodeSpec{ID: "root"})
			a.enrollAgent("h1")
			oldCopy := filepath.Join(t.TempDir(), "old-state")
			raw, _ := os.ReadFile(filepath.Join(a.stateDir, "relay.state"))
			if err := os.WriteFile(oldCopy, raw, 0o600); err != nil {
				t.Fatal(err)
			}
			oldSeq := stateWriteSeq(t, a.stateDir)
			a.enrollAgent("h2") // a newer write
			newSeq := stateWriteSeq(t, a.stateDir)
			if newSeq <= oldSeq {
				t.Fatalf("setup: write_seq %d -> %d", oldSeq, newSeq)
			}
			waitFor(t, "the lock publishes the state write_seq", func() bool {
				l, ok := readLock(a.stateDir)
				return ok && l.Seq >= newSeq
			})
			b := a.sibling()
			b.launchSecondary(nil)
			t.Cleanup(b.stop)
			waitFor(t, "the secondary has read the lock", func() bool {
				f, err := localstatus.Read(b.statusPath)
				return err == nil && f.LastCheckAt > 0
			})
			time.Sleep(600 * time.Millisecond) // a few polls: the secondary has seen write_seq newSeq

			tamper(t, a.stateDir, oldCopy) // the replay, while the master still runs
			a.killNow()

			code, ok := b.waitExit(40 * time.Second)
			if !ok || code == 0 {
				t.Fatalf("the new master must refuse to start on a replayed state: exit=%d exited=%v; logs:\n%s", code, ok, b.logs.String())
			}
			if !b.logs.has("[SECURITY WARNING]") {
				t.Errorf("a SECURITY WARNING is expected:\n%s", b.logs.String())
			}
			if b.logs.has("[LISTEN]") {
				t.Error("no port may have been opened")
			}
			if st, err := localstatus.Read(b.statusPath); err != nil || st.State != localstatus.StateFailed {
				t.Errorf("status = %+v %v, want failed", st, err)
			}
			if _, present := readLock(a.stateDir); present {
				t.Error("the lock must be released after a refused start (a healthy instance can then take over)")
			}
		})
	}
}

// Case 5 of #162 with three real processes: the master crashes, B judges the lock stale but its
// deletion is DELAYED (the seam) and lands on the lock C has meanwhile taken. During the overlap no
// acknowledged write may be lost, the evicted C exits with 75 after one check cycle, and exactly one
// instance (B) ends up listening.
func TestFailover_DelayedStaleDeletionErasesAFreshLockNoWriteIsLost(t *testing.T) {
	parallel(t)
	a := startNode(t, nodeSpec{ID: "root"})
	dir := t.TempDir()
	gateB, gateC := filepath.Join(dir, "gate-b"), filepath.Join(dir, "gate-c")
	b := a.sibling()
	b.launchSecondary([]string{"NODE_LOCK_REMOVE_GATE=" + gateB})
	t.Cleanup(b.stop)
	c := a.sibling()
	c.launchSecondary([]string{"NODE_LOCK_REMOVE_GATE=" + gateC})
	t.Cleanup(c.stop)
	for _, n := range []*node{b, c} {
		n := n
		waitFor(t, "secondary polls", func() bool {
			f, err := localstatus.Read(n.statusPath)
			return err == nil && f.LastCheckAt > 0
		})
	}
	a.killNow()

	// Both secondaries must have judged the dead master's lock stale (and be held right before its
	// deletion) BEFORE either proceeds: otherwise B, arriving late, would see C's fresh lock as
	// alive and never delete it (the ordering this test needs is a condition, not a delay).
	for _, g := range []string{gateB, gateC} {
		g := g
		waitFor(t, "an instance is held right before deleting the stale lock", func() bool {
			_, err := os.Stat(g + ".reached")
			return err == nil
		})
	}
	release := func(g string) {
		if err := os.WriteFile(g, []byte("go"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	release(gateC) // C deletes the stale lock, takes over and serves
	if !c.awaitPromotion(30 * time.Second) {
		t.Fatalf("C never took over; logs:\n%s", c.logs.String())
	}
	// hammer C with writes (admin authorize) until it is evicted; remember what it acknowledged.
	// B's deletion is released only once C has acknowledged a few writes (C is master and serving).
	acked := map[string]bool{}
	deadline := time.Now().Add(30 * time.Second)
	for i := 0; time.Now().Before(deadline); i++ {
		if _, ok := c.waitExit(0); ok {
			break
		}
		if len(acked) >= 5 {
			release(gateB) // B now erases the fresh lock of C
		}
		host := fmt.Sprintf("w%03d", i)
		code, _, err := c.callErr("POST", c.adminURL(), "/api/admin/authorize", c.adminTok,
			map[string]any{"hostname": host, "public_key_pem": "pem", "approved_by": "ci"})
		if err == nil && code < 300 {
			acked[host] = true
		}
		time.Sleep(25 * time.Millisecond)
	}
	if code, ok := c.waitExit(10 * time.Second); !ok || code != 75 {
		t.Fatalf("C (evicted by B's delayed deletion) must exit 75, got %d (exited=%v); logs:\n%s", code, ok, c.logs.String())
	}
	if !b.awaitPromotion(20 * time.Second) {
		t.Fatalf("B never became master; logs:\n%s", b.logs.String())
	}
	if len(acked) == 0 {
		t.Fatal("setup: C acknowledged no write")
	}
	keys := b.stateSection("authorized_keys")
	for host := range acked {
		if _, ok := keys[host]; !ok {
			t.Errorf("write %q was acknowledged by C then lost: it is not in the state of the new master", host)
		}
	}
	if conn, err := net.DialTimeout("tcp", c.ready.API, time.Second); err == nil {
		_ = conn.Close()
		t.Error("the evicted instance still accepts connections")
	}
	if p := listeningPorts(t, b.cmd.Process.Pid); len(p) == 0 {
		t.Error("exactly one instance (B) must be serving at the end")
	}
}

// A pull child declared with BOTH addresses of the root (REPEATER_UPSTREAM_URL list, #165) follows the
// master: when the active root dies and the passive one takes over, the child reconnects to it.
func TestFailover_PullChildReconnectsToTheNewMasterThroughItsAddressList(t *testing.T) {
	parallel(t)
	addrA, addrB := freeAddr(t), freeAddr(t)
	a := startNode(t, nodeSpec{ID: "root", Env: []string{"NODE_WS_ADDR=" + addrA}})
	tok := a.registerChild("relay1")
	b := a.sibling()
	b.launchSecondary([]string{"NODE_WS_ADDR=" + addrB})
	t.Cleanup(b.stop)
	child := startNode(t, nodeSpec{ID: "relay1", ParentURL: "wss://" + addrA + ",wss://" + addrB, ParentToken: tok})
	waitFor(t, "the child is linked to the active root", func() bool { return child.upstreamState() == "connected" })
	connectMinion(t, child, "leaf-host")
	waitFor(t, "the active root routes the leaf host", func() bool { return a.hasHost("leaf-host") })

	a.killNow()
	if !b.awaitPromotion(30 * time.Second) {
		t.Fatalf("the passive root never took over; logs:\n%s", b.logs.String())
	}
	waitFor(t, "the child reconnected to the NEW master (second address)", func() bool {
		return b.logs.has("Relay connected: relay_id=relay1") && child.upstreamState() == "connected"
	})
	waitFor(t, "the new master routes the leaf host again", func() bool { return b.hasHost("leaf-host") })
}

// A push child: the NEW master restarts the dialer from relay_nodes (it is in the shared state) and the
// link is re-established without any manual action.
func TestFailover_PushChildIsDialedByTheNewMaster(t *testing.T) {
	parallel(t)
	a := startNode(t, nodeSpec{ID: "root"})
	child := startNode(t, nodeSpec{ID: "relay1"})
	tok, _ := child.mintParentToken("root")
	code, m := a.admin("POST", "/api/admin/relays", map[string]any{"relay_id": "relay1", "mode": "push", "urls": []string{child.wssURL()}, "token": tok})
	if code != 201 {
		t.Fatalf("register push child: %d %v", code, m)
	}
	waitFor(t, "root dialer connected", func() bool { return a.pushState("relay1") == "connected" })
	b := a.sibling()
	b.launchSecondary(nil)
	t.Cleanup(b.stop)

	a.killNow()
	if !b.awaitPromotion(30 * time.Second) {
		t.Fatalf("the passive root never took over; logs:\n%s", b.logs.String())
	}
	waitFor(t, "the new master dialed the push child", func() bool { return b.pushState("relay1") == "connected" })
	waitFor(t, "the child sees its (new) parent", func() bool {
		u := child.health().Links.Upstream
		return u != nil && u.Mode == "push" && u.State == "connected"
	})
}

// A state that does not load refuses the start: the lock the instance already holds is released (a
// healthy instance can take over), the exit code is non-zero and no port was opened.
func TestStart_InvalidStateReleasesTheLockAndOpensNoPort(t *testing.T) {
	parallel(t)
	n := prepareNode(t, nodeSpec{ID: "node"})
	if err := os.WriteFile(filepath.Join(n.stateDir, "relay.state"), []byte(`{"not":"a state"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(filepath.Join(n.stateDir, "relay.state.prev"))
	code, out := n.runExpectingExit()
	if code == 0 || code == -1 {
		t.Fatalf("an invalid state must refuse the start (exit %d): %s", code, out)
	}
	if strings.Contains(out, "[LISTEN]") {
		t.Error("no port may open on an invalid state")
	}
	if _, present := readLock(n.stateDir); present {
		t.Error("the lock must be released after the failed start")
	}
	if f, err := localstatus.Read(n.statusPath); err != nil || f.State != localstatus.StateFailed {
		t.Errorf("status = %+v %v, want failed", f, err)
	}
}

// The TLS certificates are validated BEFORE the lock loop: a broken pair never even becomes a
// candidate (no relay.lock created) and nothing listens.
func TestStart_InvalidCertificateFailsBeforeTheLockLoop(t *testing.T) {
	parallel(t)
	n := prepareNode(t, nodeSpec{ID: "node"})
	bad := filepath.Join(t.TempDir(), "bad.pem")
	if err := os.WriteFile(bad, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	n.setEnv("TLS_CERT", bad)
	n.setEnv("TLS_KEY", bad)
	code, out := n.runExpectingExit()
	if code == 0 || code == -1 {
		t.Fatalf("an invalid certificate must refuse the start (exit %d): %s", code, out)
	}
	if _, present := readLock(n.stateDir); present {
		t.Error("the certificates are validated before the lock: no lock may have been created")
	}
	if strings.Contains(out, "waiting for the master lock") {
		t.Error("the lock loop must not start with an invalid certificate")
	}
}

// The requirement itself, on the PRODUCTION calibration (check 5 s, pause 1-2 s): after a SIGTERM the
// secondary is serving in under 10 s (cycle of control + pause of the candidate + state load).
func TestFailover_CleanStopTakeoverOnTheProductionCalibrationIsUnder10Seconds(t *testing.T) {
	parallel(t)
	prod := []string{"NODE_LOCK_PROFILE=default"}
	a := startNode(t, nodeSpec{ID: "root", Env: prod})
	b := a.sibling()
	b.launchSecondary(prod)
	t.Cleanup(b.stop)
	waitFor(t, "the secondary polled the lock at least once", func() bool {
		f, err := localstatus.Read(b.statusPath)
		return err == nil && f.LastCheckAt > 0
	})
	start := time.Now()
	a.stop()
	if !b.awaitPromotion(30 * time.Second) {
		t.Fatalf("the secondary never took over; logs:\n%s", b.logs.String())
	}
	took := time.Since(start)
	t.Logf("production calibration: takeover after %v", took)
	if took >= 10*time.Second {
		t.Errorf("takeover took %v, the requirement is < 10 s", took)
	}
}
