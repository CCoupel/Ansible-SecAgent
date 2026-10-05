package lock

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Two (then three) REAL processes on a real local file system: O_EXCL, fchmod on the descriptor,
// inode check, clean-shutdown deletion, takeover after a crash (SIGKILL).

const helperEnv = "LOCK_HELPER"

// realParams: the production protocol on a faster clock (the invariants still hold).
func realParams() Params {
	return Params{
		Beat: 400 * time.Millisecond, Check: 100 * time.Millisecond, SelfRetire: 1500 * time.Millisecond,
		MasterStale: 3 * time.Second, CandidateStale: 1500 * time.Millisecond,
		PauseMin: 500 * time.Millisecond, PauseMax: 600 * time.Millisecond, MaxWriteLatency: 400 * time.Millisecond,
	}
}

func TestMain(m *testing.M) {
	if os.Getenv(helperEnv) == "1" {
		runHelper()
		return
	}
	os.Exit(m.Run())
}

// runHelper is the child process: acquire, report, maintain, release on request.
func runHelper() {
	dir, name := os.Getenv("LOCK_HELPER_DIR"), os.Getenv("LOCK_HELPER_NAME")
	l, err := New(Config{Dir: dir, Host: name, Params: realParams(), OnLost: func(err error) { fmt.Printf("LOST %v\n", err) }})
	if err != nil {
		fmt.Printf("ERROR %v\n", err)
		os.Exit(2)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		sc := bufio.NewScanner(os.Stdin)
		for sc.Scan() {
			if strings.TrimSpace(sc.Text()) == "RELEASE" {
				cancel()
				return
			}
		}
	}()
	if err := l.Acquire(ctx); err != nil {
		os.Exit(0) // released while still a secondary
	}
	fmt.Printf("MASTER %s\n", l.InstanceID())
	go func() { _ = l.Maintain(ctx) }()
	<-ctx.Done()
	time.Sleep(50 * time.Millisecond) // let Maintain stop touching the lock
	if err := l.Release(); err != nil {
		fmt.Printf("ERROR %v\n", err)
		os.Exit(3)
	}
	fmt.Println("RELEASED")
}

type proc struct {
	cmd   *exec.Cmd
	stdin interface{ Write([]byte) (int, error) }
	lines chan string
	name  string
}

func startProc(t *testing.T, dir, name string) *proc {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=NONE")
	cmd.Env = append(os.Environ(), helperEnv+"=1", "LOCK_HELPER_DIR="+dir, "LOCK_HELPER_NAME="+name)
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	p := &proc{cmd: cmd, stdin: in, lines: make(chan string, 64), name: name}
	go func() {
		sc := bufio.NewScanner(out)
		for sc.Scan() {
			p.lines <- sc.Text()
		}
		close(p.lines)
	}()
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	return p
}

// expect waits for a line starting with prefix; "" prefix + wantNone=true asserts silence.
func (p *proc) expect(t *testing.T, prefix string, within time.Duration) string {
	t.Helper()
	deadline := time.After(within)
	for {
		select {
		case l, ok := <-p.lines:
			if !ok {
				t.Fatalf("%s: output closed while waiting for %q", p.name, prefix)
			}
			if strings.HasPrefix(l, prefix) {
				return l
			}
			if strings.HasPrefix(l, "ERROR") {
				t.Fatalf("%s: %s", p.name, l)
			}
		case <-deadline:
			t.Fatalf("%s: no %q within %v", p.name, prefix, within)
		}
	}
}

func (p *proc) assertNo(t *testing.T, prefix string, during time.Duration) {
	t.Helper()
	deadline := time.After(during)
	for {
		select {
		case l, ok := <-p.lines:
			if !ok {
				return
			}
			if strings.HasPrefix(l, prefix) {
				t.Fatalf("%s: unexpected %q", p.name, l)
			}
		case <-deadline:
			return
		}
	}
}

func readLock(t *testing.T, dir string) (content, os.FileMode, bool) {
	t.Helper()
	path := filepath.Join(dir, FileName)
	raw, err := os.ReadFile(path)
	if err != nil {
		return content{}, 0, false
	}
	fi, _ := os.Stat(path)
	c, _ := parseContent(raw)
	return c, fi.Mode().Perm(), true
}

func TestRealProcesses_ExclusiveCreateTakeoverOnReleaseAndOnCrash(t *testing.T) {
	if testing.Short() {
		t.Skip("real processes and real time")
	}
	dir := t.TempDir()
	p := realParams()

	a := startProc(t, dir, "A")
	idA := strings.TrimPrefix(a.expect(t, "MASTER ", 10*time.Second), "MASTER ")
	c, mode, ok := readLock(t, dir)
	if !ok || c.InstanceID != idA || c.Role != RoleMaster {
		t.Fatalf("lock after A's promotion: %+v present=%v", c, ok)
	}
	if mode != ModeMaster {
		t.Errorf("master lock mode %o, want %o (fchmod on the descriptor)", mode, ModeMaster)
	}
	if len(idA) != 32 {
		t.Errorf("instance id %q: want 128 random bits (32 hex)", idA)
	}

	// B races while A beats: it must stay a secondary for longer than the staleness delay
	b := startProc(t, dir, "B")
	b.assertNo(t, "MASTER", p.MasterStale+2*time.Second)
	if c, _, _ := readLock(t, dir); c.InstanceID != idA || c.Beat < 5 {
		t.Fatalf("A must still own a beating lock: %+v", c)
	}

	// clean shutdown of A: the lock is deleted and B takes over at once (no staleness wait)
	start := time.Now()
	if _, err := a.stdin.Write([]byte("RELEASE\n")); err != nil {
		t.Fatal(err)
	}
	a.expect(t, "RELEASED", 5*time.Second)
	idB := strings.TrimPrefix(b.expect(t, "MASTER ", 10*time.Second), "MASTER ")
	if took := time.Since(start); took > p.MasterStale {
		t.Errorf("takeover after a clean release took %v: it must not wait for the staleness delay (%v)", took, p.MasterStale)
	}
	if idB == idA {
		t.Fatal("two processes share an instance id")
	}
	if c, mode, _ := readLock(t, dir); c.InstanceID != idB || c.Role != RoleMaster || mode != ModeMaster {
		t.Fatalf("lock after B's promotion: %+v mode %o", c, mode)
	}

	// B crashes (SIGKILL): the lock stays; a new process takes over once the beat is stale
	if err := b.cmd.Process.Signal(syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	crashed := time.Now()
	cproc := startProc(t, dir, "C")
	idC := strings.TrimPrefix(cproc.expect(t, "MASTER ", p.MasterStale+10*time.Second), "MASTER ")
	took := time.Since(crashed)
	if took < p.MasterStale-time.Second { // C had to observe the frozen beat for ~MasterStale
		t.Errorf("C took over after %v: the dead master's lock was removed before it was stale (%v)", took, p.MasterStale)
	}
	if c, _, _ := readLock(t, dir); c.InstanceID != idC || c.Role != RoleMaster {
		t.Fatalf("lock after C's promotion: %+v", c)
	}
	// never two masters: B was killed, A released, only C beats
	before := func() uint64 { c, _, _ := readLock(t, dir); return c.Beat }()
	time.Sleep(2 * p.Beat)
	if after := func() uint64 { c, _, _ := readLock(t, dir); return c.Beat }(); after <= before {
		t.Errorf("the master's beat does not move (%d → %d)", before, after)
	}
}

// Four processes start at the same instant on an empty directory: O_EXCL + the re-read give
// exactly one master.
func TestRealProcesses_SimultaneousStartElectsExactlyOne(t *testing.T) {
	if testing.Short() {
		t.Skip("real processes and real time")
	}
	dir := t.TempDir()
	procs := make([]*proc, 4)
	for i := range procs {
		procs[i] = startProc(t, dir, fmt.Sprintf("P%d", i))
	}
	masters := map[string]string{}
	deadline := time.Now().Add(15 * time.Second)
	for len(masters) == 0 && time.Now().Before(deadline) {
		for _, p := range procs {
			select {
			case l := <-p.lines:
				if strings.HasPrefix(l, "MASTER ") {
					masters[p.name] = l
				}
			default:
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	if len(masters) != 1 {
		t.Fatalf("masters after the election: %v", masters)
	}
	// nobody else is promoted while the master beats
	end := time.Now().Add(3 * time.Second)
	for time.Now().Before(end) {
		for _, p := range procs {
			select {
			case l := <-p.lines:
				if strings.HasPrefix(l, "MASTER ") {
					masters[p.name] = l
				}
			default:
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	if len(masters) != 1 {
		t.Fatalf("a second master appeared: %v", masters)
	}
}
