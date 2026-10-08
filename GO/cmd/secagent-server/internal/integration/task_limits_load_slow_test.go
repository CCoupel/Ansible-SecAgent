//go:build slow

// Slow suite (~2.5 min, 3 000 real agent links): run with `-tags slow`, in its own CI job (slow-tests).

package integration

import (
	"debug/buildinfo"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ── load: 3 000 simulated agents (perf scope) ────────────────────────────────

// buildPlainNodeBinary compiles this very package's test binary WITHOUT -race, in a directory the test
// removes afterwards, and returns its path: the nodes of the load test run from it. The race detector
// multiplies the memory of a process several times (shadow memory, vector clocks): a -race node cannot
// tell whether the 2 GiB criterion is met. The rest of the test run keeps -race.
func buildPlainNodeBinary(t *testing.T) string {
	t.Helper()
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Fatalf("the go tool is needed to build the node binary without -race: %v", err)
	}
	out := filepath.Join(t.TempDir(), "integration-plain.test")
	cmd := exec.Command(goBin, "test", "-c", "-o", out, ".")
	cmd.Env = append(os.Environ(), "GOFLAGS=", "CGO_ENABLED=1")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building the node binary without -race: %v\n%s", err, b)
	}
	info, err := buildinfo.ReadFile(out)
	if err != nil {
		t.Fatalf("build info of the node binary: %v", err)
	}
	for _, s := range info.Settings {
		if s.Key == "-race" && s.Value == "true" {
			t.Fatal("the node binary of the load test was built with -race: the RSS criterion would be meaningless")
		}
	}
	return out
}

// rssSampler records the peak resident set of the node process (a child of the test binary: the
// harness runs every node as its own OS process, so /proc/<pid>/status is the node and nothing else).
// It samples VmRSS every 50 ms AND keeps the last VmHWM it could read: when the process dies under
// load its last values are still there, and the test says so instead of skipping.
type rssSampler struct {
	pid      int
	peak     atomic.Int64 // bytes
	samples  atomic.Int64
	stop     chan struct{}
	done     chan struct{}
	vanished atomic.Bool
}

func startRSSSampler(t *testing.T, pid int) *rssSampler {
	t.Helper()
	r := &rssSampler{pid: pid, stop: make(chan struct{}), done: make(chan struct{})}
	if _, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid)); err != nil {
		t.Fatalf("cannot read /proc/%d/status (not Linux, or the node is not running): %v", pid, err)
	}
	go func() {
		defer close(r.done)
		tick := time.NewTicker(50 * time.Millisecond)
		defer tick.Stop()
		for {
			if !r.sample() {
				r.vanished.Store(true)
				return
			}
			select {
			case <-r.stop:
				return
			case <-tick.C:
			}
		}
	}()
	return r
}

func (r *rssSampler) sample() bool {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", r.pid))
	if err != nil {
		return false
	}
	for _, l := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(l, "VmRSS:") || strings.HasPrefix(l, "VmHWM:") {
			if f := strings.Fields(l); len(f) >= 2 {
				if kb, err := strconv.ParseInt(f[1], 10, 64); err == nil && kb*1024 > r.peak.Load() {
					r.peak.Store(kb * 1024)
				}
			}
		}
	}
	r.samples.Add(1)
	return true
}

func (r *rssSampler) finish() (peak int64, vanished bool) {
	select {
	case <-r.done:
	default:
		close(r.stop)
		<-r.done
	}
	return r.peak.Load(), r.vanished.Load()
}

// A nominal playbook (forks 200) over 3 000 agents is never rejected with the DEFAULT limits; a
// saturation (1 000 tasks each producing 5 MiB) is refused cleanly and the process stays under 2 GiB.
func TestTaskLimits_Load3000AgentsNominalThenSaturation(t *testing.T) {
	requireTaskLimits(t)
	if testing.Short() {
		t.Skip("load test")
	}
	const agents, forks, saturating = 3000, 200, 1000
	n := startNode(t, nodeSpec{ID: "load", NodeBinary: buildPlainNodeBinary(t)}) // DEFAULT limits: that is the point; node built without -race
	rss := startRSSSampler(t, n.cmd.Process.Pid)
	n.pluginToken() // created once, before the concurrent execs (the lazy creation is not goroutine-safe)

	tokens := make([]string, agents)
	forEach(t, agents, 64, func(i int) error {
		tok, err := n.enrollAgentErr(fmt.Sprintf("load-%04d", i))
		tokens[i] = tok
		return err
	})
	var mode atomic.Int32 // 0 answer at once, 1 produce 5 MiB then wait for the release
	var release = make(chan struct{})
	minions := make([]*heldMinion, agents)
	forEach(t, agents, 64, func(i int) error {
		m, err := dialHeld(t, n, fmt.Sprintf("load-%04d", i), tokens[i])
		minions[i] = m
		if err != nil {
			return err
		}
		go func() { // a real agent: answers by itself
			seen := 0
			for {
				select {
				case <-m.closed:
					return
				case <-time.After(2 * time.Millisecond):
				}
				r := m.received()
				for ; seen < len(r); seen++ {
					id := r[seen]
					if mode.Load() == 1 {
						go func() { m.stream(id, 5, 1<<20); <-release; m.answer(id) }()
					} else {
						m.answer(id)
					}
				}
			}
		}()
		return nil
	})

	// nominal: 3 waves of `forks` concurrent execs on distinct hosts, never rejected
	var rejected atomic.Int32
	for wave := 0; wave < 3; wave++ {
		var wg sync.WaitGroup
		for i := 0; i < forks; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				if r := rawExec(n, fmt.Sprintf("load-%04d", wave*forks+i), 30); r.Err != nil || r.Code != http.StatusOK {
					rejected.Add(1)
					t.Errorf("nominal exec %d/%d: %+v", wave, i, r)
				}
			}(i)
		}
		wg.Wait()
	}
	if rejected.Load() != 0 {
		t.Fatalf("%d nominal exec(s) failed with the default limits", rejected.Load())
	}

	// saturation: 1 000 concurrent tasks, each one producing 5 MiB (5 GiB asked for, budget 1 GiB)
	mode.Store(1)
	var ok, busy, memory, other atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < saturating; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			r := rawExec(n, fmt.Sprintf("load-%04d", 1000+i), 60)
			switch {
			case r.Err != nil:
				other.Add(1)
			case r.Code == http.StatusOK:
				ok.Add(1)
			case r.Code == http.StatusTooManyRequests:
				busy.Add(1)
			case r.Code == http.StatusServiceUnavailable && r.Error == "memory_budget_exhausted":
				memory.Add(1)
			default:
				other.Add(1)
				t.Errorf("saturated exec %d: %+v", i, r)
			}
		}(i)
	}
	time.Sleep(20 * time.Second) // admitted tasks have streamed what they could, the others were refused
	close(release)
	wg.Wait()

	hwm, vanished := rss.finish()
	t.Logf("saturation: %d ok, %d 429, %d 503 memory, %d other; node peak RSS = %.0f MiB over %d samples (limit 2048)", ok.Load(), busy.Load(), memory.Load(), other.Load(), float64(hwm)/(1<<20), rss.samples.Load())
	if vanished {
		select {
		case <-n.exited:
		case <-time.After(5 * time.Second):
		}
		t.Errorf("the node process DISAPPEARED during the load (exit code %d): killed by the kernel (OOM) or crashed — the last RSS seen was %.0f MiB", n.exitCode, float64(hwm)/(1<<20))
	}
	if hwm == 0 {
		t.Fatal("no RSS sample: the memory criterion cannot be checked")
	}
	if other.Load() != 0 {
		t.Errorf("%d request(s) ended in anything but 200 / 429 / 503 memory_budget_exhausted: refusals must be clean", other.Load())
	}
	if memory.Load()+busy.Load() == 0 {
		t.Error("5 GiB asked for with a 1 GiB budget: some admissions must be refused")
	}
	if hwm > 2<<30 {
		t.Errorf("node peak RSS %.0f MiB exceeds 2 GiB under saturation", float64(hwm)/(1<<20))
	}
	// the node is healthy afterwards and the slots are back
	if r := rawExec(n, "load-2999", 30); r.Err != nil || r.Code != http.StatusOK {
		t.Errorf("after the saturation: %+v", r)
	}
}

// forEach runs fn(0..n-1) with `workers` goroutines and fails the test on the first error.
func forEach(t *testing.T, n, workers int, fn func(i int) error) {
	t.Helper()
	next := make(chan int)
	errs := make(chan error, n)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range next {
				if err := fn(i); err != nil {
					errs <- err
				}
			}
		}()
	}
	for i := 0; i < n; i++ {
		next <- i
	}
	close(next)
	wg.Wait()
	close(errs)
	if err := <-errs; err != nil {
		t.Fatal(err)
	}
}
