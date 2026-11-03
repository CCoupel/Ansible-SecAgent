// SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
// SPDX-License-Identifier: AGPL-3.0-or-later

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
	"runtime"
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
		go func() { // a real agent: answers by itself (woken by the arrival of a task, never polling)
			seen := 0
			for {
				select {
				case <-m.closed:
					return
				case <-m.arrival:
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

	// Harness delays follow the CPU available (#222): the fake agents, the 3 000 TLS links and the HTTP clients share
	// the cores with the node; on a small runner the HARNESS is slow before the server is. A reply is therefore
	// classified, and only a wrong SERVER answer fails the test (see classifyExec).
	f := loadFactor()
	nominalTimeout, saturationTimeout := 30*f, 60*f
	client := &http.Client{Timeout: time.Duration(saturationTimeout+60) * time.Second, Transport: &http.Transport{TLSClientConfig: tlsClientConfig(), MaxIdleConnsPerHost: 64}}
	t.Logf("NumCPU=%d: load factor %d, task timeouts %d s / %d s", runtime.NumCPU(), f, nominalTimeout, saturationTimeout)

	// nominal: 3 waves of `forks` concurrent execs on distinct hosts, never REFUSED by the server
	var nominal execTally
	for wave := 0; wave < 3; wave++ {
		var wg sync.WaitGroup
		for i := 0; i < forks; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				r := rawExecOn(client, n, fmt.Sprintf("load-%04d", wave*forks+i), nominalTimeout)
				if kind := nominal.add(r); kind == "other" || kind == "busy" || kind == "memory" {
					t.Errorf("nominal exec %d/%d refused by the server although the limits are not reached: %+v", wave, i, r)
				}
			}(i)
		}
		wg.Wait()
	}
	t.Logf("nominal: %s", nominal.String())
	if nominal.refused() != 0 {
		t.Fatalf("%d nominal exec(s) refused by the server with the default limits", nominal.refused())
	}
	if nominal.slow.Load() > 3*forks/4 { // 150 of 600 = 25 %: a node that answers nothing is not "a slow runner"
		t.Fatalf("%d of %d nominal execs ended by a harness timeout (> 25 %%): the node is not serving (%s)", nominal.slow.Load(), 3*forks, nominal.kinds())
	}

	// saturation: 1 000 concurrent tasks, each one producing 5 MiB (5 GiB asked for, budget 1 GiB)
	mode.Store(1)
	var sat execTally
	var wg sync.WaitGroup
	for i := 0; i < saturating; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			r := rawExecOn(client, n, fmt.Sprintf("load-%04d", 1000+i), saturationTimeout)
			if kind := sat.add(r); kind == "other" {
				t.Errorf("saturated exec %d: %+v", i, r)
			}
		}(i)
	}
	// the admitted tasks stream what they can while the others are refused: wait for the refusals to settle
	// (no new refusal for 2 s) instead of a fixed 20 s, bounded by the load factor
	settleBy := time.Now().Add(time.Duration(20*f) * time.Second)
	lastChange, last := time.Now(), int32(-1)
	for time.Now().Before(settleBy) {
		time.Sleep(250 * time.Millisecond)
		if cur := sat.busy.Load() + sat.memory.Load(); cur != last {
			last, lastChange = cur, time.Now()
		} else if cur > 0 && time.Since(lastChange) > 2*time.Second {
			break
		}
	}
	close(release)
	wg.Wait()

	hwm, vanished := rss.finish()
	t.Logf("saturation: %s; node peak RSS = %.0f MiB over %d samples (limit 2048)", sat.String(), float64(hwm)/(1<<20), rss.samples.Load())
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
	// B45: a transport error can also be the server refusing connections (file descriptors, accept queue), not only a
	// slow harness: bound it under saturation too (a quarter of the requests, like the nominal guard), and show the kinds
	t.Logf("harness-slow by kind: nominal %s ; saturation %s", nominal.kinds(), sat.kinds())
	if sat.slow.Load() > saturating/4 {
		t.Errorf("%d of %d saturating execs ended by a harness timeout / transport error (> 25 %%): the node is not serving (%s)", sat.slow.Load(), saturating, sat.kinds())
	}
	if sat.other.Load() != 0 {
		t.Errorf("%d request(s) ended in anything but 200 / 429 / 503 memory_budget_exhausted / a harness timeout: refusals must be clean", sat.other.Load())
	}
	if sat.memory.Load()+sat.busy.Load() == 0 {
		t.Error("5 GiB asked for with a 1 GiB budget: some admissions must be refused (the global limit / the budget is not applied)")
	}
	if hwm > 2<<30 {
		t.Errorf("node peak RSS %.0f MiB exceeds 2 GiB under saturation", float64(hwm)/(1<<20))
	}
	// the node is healthy afterwards and the slots are back (M11): a harness delay may cost an attempt, never the
	// check — the node must answer 200 within a bounded number of spaced attempts, whatever the CPU available
	if lastReply, ok := requireHealthyAfter(func() execReply { return rawExecOn(client, n, "load-2999", nominalTimeout) }, healthyAfterAttempts, time.Duration(2*f)*time.Second, t.Logf); !ok {
		t.Errorf("the node is not healthy after the saturation: no 200 in %d attempts, last answer %+v (a blocked node, slots not given back, refused connections)", healthyAfterAttempts, lastReply)
	}
	// B46: a node that survived by luck would still have said so in its logs
	for _, bad := range []string{"panic:", "too many open files", "fatal error:"} {
		if n.logs.has(bad) {
			t.Errorf("the node log contains %q after the load", bad)
		}
	}
}

// loadFactor scales the harness delays to the CPU available: 1 from 8 cores up, 2 on a 4 vCPU runner, 4 on 2 cores
// (capped at 6). runtime.NumCPU honours the CPU affinity (taskset), as the CI runner's cgroup limits do not matter
// to the test process itself but to the node it spawns on the same cores.
func loadFactor() int {
	c := runtime.NumCPU()
	if c < 1 {
		c = 1
	}
	f := (8 + c - 1) / c
	if f < 1 {
		f = 1
	}
	if f > 6 {
		f = 6
	}
	return f
}

// execTally classifies the answers of the exec requests of the load test (#222).
//
//	ok      200
//	busy    429 (agent_busy / too_many_tasks): a SERVER refusal
//	memory  503 memory_budget_exhausted: a SERVER refusal
//	slow    the HARNESS was too slow: a client-side timeout / transport error, or a 504 task_timeout / 503
//	        agent_disconnected (the fake agent, starved of CPU, did not answer or lost its link in time)
//	other   any other code: a wrong server answer
type execTally struct {
	ok, busy, memory, slow, other atomic.Int32
	mu                            sync.Mutex
	why                           map[string]int // harness-slow answers by kind (timeout, reset, EOF, refused, 504, 503)
}

func (c *execTally) note(kind string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.why == nil {
		c.why = map[string]int{}
	}
	c.why[kind]++
}

func (c *execTally) kinds() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return fmt.Sprint(c.why)
}

// transportKind names a client-side error without its text (which carries addresses).
func transportKind(err error) string {
	msg := strings.ToLower(err.Error())
	for _, k := range []string{"timeout", "deadline", "connection reset", "eof", "refused", "too many open files", "broken pipe"} {
		if strings.Contains(msg, k) {
			return k
		}
	}
	return "other-transport"
}

func (c *execTally) add(r execReply) string {
	switch {
	case r.Err != nil:
		c.slow.Add(1)
		c.note(transportKind(r.Err))
		return "slow"
	case r.Code == http.StatusOK:
		c.ok.Add(1)
		return "ok"
	case r.Code == http.StatusTooManyRequests:
		c.busy.Add(1)
		return "busy"
	case r.Code == http.StatusServiceUnavailable && r.Error == "memory_budget_exhausted":
		c.memory.Add(1)
		return "memory"
	case r.Code == http.StatusGatewayTimeout && r.Error == "task_timeout", r.Code == http.StatusServiceUnavailable && r.Error == "agent_disconnected":
		c.slow.Add(1)
		c.note(fmt.Sprintf("%d %s", r.Code, r.Error))
		return "slow"
	}
	c.other.Add(1)
	return "other"
}

// refused is the number of SERVER refusals (the nominal load must have none).
func (c *execTally) refused() int32 { return c.busy.Load() + c.memory.Load() + c.other.Load() }

func (c *execTally) String() string {
	return fmt.Sprintf("%d ok, %d 429, %d 503 memory, %d harness-slow, %d other", c.ok.Load(), c.busy.Load(), c.memory.Load(), c.slow.Load(), c.other.Load())
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
