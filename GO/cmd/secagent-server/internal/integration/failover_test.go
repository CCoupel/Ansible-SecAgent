package integration

// Active/passive tests with REAL processes (#163): two (or three) instances of the same node share
// one STATE_DIR. The children run the fast lock calibration (lockProfileFast: beat 400 ms, check
// 200 ms, master stale 4 s) so that a crash is recovered in seconds.

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
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	a := l.Addr().String()
	_ = l.Close()
	return a
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
	if st := a.status(t); st.Role != "master" || st.State != localstatus.StateReady {
		t.Errorf("master status = %+v", st)
	}
	if h := a.publicHealth(); !strings.Contains(h, "master") || !strings.Contains(h, a.status(t).InstanceID) {
		t.Errorf("/health must expose role and instance_id: %s", h)
	}
	if l, ok := readLock(a.stateDir); !ok || l.Role != "master" || l.InstanceID != a.status(t).InstanceID {
		t.Errorf("relay.lock = %+v", l)
	}
}

// SIGTERM: the lock is deleted and a waiting secondary takes over in under 5 s, ports serving.
func TestFailover_CleanStopReleasesTheLockAndTheSecondaryTakesOverFast(t *testing.T) {
	parallel(t)
	a := startNode(t, nodeSpec{ID: "root"})
	b := a.sibling()
	b.launchSecondary(nil)
	t.Cleanup(b.stop)
	waitFor(t, "the secondary polls the lock", func() bool {
		f, err := localstatus.Read(b.statusPath)
		return err == nil && f.LastCheckAt > 0
	})

	start := time.Now()
	a.stop()
	if code, ok := a.waitExit(time.Second); !ok || code != 0 {
		t.Fatalf("clean stop: exit %d (exited=%v)", code, ok)
	}
	if !b.awaitPromotion(5 * time.Second) {
		t.Fatalf("the secondary did not take over within 5 s; logs:\n%s", b.logs.String())
	}
	t.Logf("takeover after %v", time.Since(start))
	if time.Since(start) > 5*time.Second {
		t.Errorf("takeover took %v, want < 5 s", time.Since(start))
	}
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
	t.Logf("takeover after the crash: %v (master stale = 4 s)", time.Since(start))
	if time.Since(start) < 3*time.Second {
		t.Errorf("took over after %v: too early for a 4 s staleness", time.Since(start))
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
