package integration

// #179 (L2) on REAL nodes: limits of concurrency and global stdout budget on the exec path.
//
//	MAX_TASKS_PER_AGENT       (default 10)     → 429 {"error":"agent_busy"} + Retry-After, nothing sent to the agent
//	MAX_TASKS_INFLIGHT        (default ≥ 1000) → 429 {"error":"too_many_tasks"} + Retry-After
//	MAX_STDOUT_BUFFER_TOTAL   (default 1 GiB)  → 503 {"error":"memory_budget_exhausted"} (refusal at admission)
//
// The tests are ARMED by one switch, specTaskLimits179: dev-relay sets it to true in the commit of the
// limits (before that, nothing is limited and the assertions below cannot hold).

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

const specTaskLimits179 = false // dev-relay: true when #179 lands

func requireTaskLimits(t *testing.T) {
	t.Helper()
	if !specTaskLimits179 {
		t.Skip("PENDING #179: no admission limit yet (set specTaskLimits179 = true when #179 lands)")
	}
}

// ── a minion that does not answer on its own ─────────────────────────────────

type heldMinion struct {
	host   string
	conn   *websocket.Conn
	wmu    sync.Mutex
	mu     sync.Mutex
	tasks  []string // task ids received, in order
	closed chan struct{}
}

func dialHeld(tb testing.TB, n *node, host, token string) (*heldMinion, error) {
	h := http.Header{"Authorization": {"Bearer " + token}}
	d := websocket.Dialer{TLSClientConfig: tlsClientConfig(), HandshakeTimeout: 20 * time.Second}
	conn, _, err := d.Dial(n.wssURL()+"/ws/agent", h)
	if err != nil {
		return nil, err
	}
	m := &heldMinion{host: host, conn: conn, closed: make(chan struct{})}
	go func() {
		defer close(m.closed)
		for {
			var msg map[string]any
			if err := conn.ReadJSON(&msg); err != nil {
				return
			}
			if id, _ := msg["task_id"].(string); id != "" && msg["type"] == "exec" {
				m.mu.Lock()
				m.tasks = append(m.tasks, id)
				m.mu.Unlock()
			}
		}
	}()
	tb.Cleanup(func() { _ = conn.Close() })
	return m, nil
}

func (m *heldMinion) received() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.tasks...)
}

func (m *heldMinion) write(v any) {
	m.wmu.Lock()
	defer m.wmu.Unlock()
	_ = m.conn.WriteJSON(v)
}

func (m *heldMinion) answer(id string) {
	m.write(map[string]any{"task_id": id, "type": "result", "rc": 0})
}

// stream sends chunks × size bytes of stdout for the task (kept in the server's buffer until the result).
func (m *heldMinion) stream(id string, chunks, size int) {
	c := strings.Repeat("x", size)
	for i := 0; i < chunks; i++ {
		m.write(map[string]any{"task_id": id, "type": "stdout", "chunk": c})
	}
}

func heldMinions(t *testing.T, n *node, hosts ...string) map[string]*heldMinion {
	t.Helper()
	out := map[string]*heldMinion{}
	for _, h := range hosts {
		m, err := dialHeld(t, n, h, n.enrollAgent(h))
		if err != nil {
			t.Fatalf("minion %s: %v", h, err)
		}
		out[h] = m
	}
	return out
}

// ── blocking exec ────────────────────────────────────────────────────────────

// longHTTP is built on first use: the TLS material of the harness exists only once a node was started.
var (
	longHTTPOnce sync.Once
	longHTTPc    *http.Client
)

func longHTTP() *http.Client {
	longHTTPOnce.Do(func() {
		longHTTPc = &http.Client{Timeout: 90 * time.Second, Transport: &http.Transport{TLSClientConfig: tlsClientConfig(), MaxIdleConnsPerHost: 64}}
	})
	return longHTTPc
}

type execReply struct {
	Code       int
	RetryAfter string
	Error      string
	Err        error
}

func rawExec(n *node, host string, timeout int) execReply {
	body, _ := json.Marshal(map[string]any{"cmd": "true", "timeout": timeout})
	req, err := http.NewRequest("POST", n.apiURL()+"/api/exec/"+host, bytes.NewReader(body))
	if err != nil {
		return execReply{Err: err}
	}
	req.Header.Set("Authorization", "Bearer "+n.pluginToken())
	req.Header.Set("Content-Type", "application/json")
	resp, err := longHTTP().Do(req)
	if err != nil {
		return execReply{Err: err}
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	e, _ := m["error"].(string)
	return execReply{Code: resp.StatusCode, RetryAfter: resp.Header.Get("Retry-After"), Error: e}
}

// startExecs launches count blocking execs on host in the background; results arrive on the channel.
func startExecs(n *node, host string, count, timeout int) <-chan execReply {
	ch := make(chan execReply, count)
	for i := 0; i < count; i++ {
		go func() { ch <- rawExec(n, host, timeout) }()
	}
	return ch
}

func waitReceived(t *testing.T, m *heldMinion, want int) {
	t.Helper()
	waitFor(t, fmt.Sprintf("%s received %d task(s)", m.host, want), func() bool { return len(m.received()) >= want })
}

func expectRejection(t *testing.T, r execReply, code int, errName string) {
	t.Helper()
	if r.Err != nil {
		t.Fatalf("exec: %v", r.Err)
	}
	if r.Code != code || r.Error != errName {
		t.Fatalf("exec = %d %q, want %d %q", r.Code, r.Error, code, errName)
	}
	if code == http.StatusTooManyRequests {
		if s, err := strconv.Atoi(r.RetryAfter); err != nil || s < 1 {
			t.Errorf("a 429 carries a positive Retry-After (seconds), got %q", r.RetryAfter)
		}
	}
}

// ── per agent ────────────────────────────────────────────────────────────────

func TestTaskLimits_PerAgentLimitRejectsWith429AndSendsNothingToTheAgent(t *testing.T) {
	requireTaskLimits(t)
	parallel(t)
	n := startNode(t, nodeSpec{ID: "root", Env: []string{"MAX_TASKS_PER_AGENT=2", "MAX_TASKS_INFLIGHT=100"}})
	m := heldMinions(t, n, "host-a", "host-b")
	a, b := m["host-a"], m["host-b"]

	first := startExecs(n, "host-a", 2, 60)
	waitReceived(t, a, 2)

	expectRejection(t, rawExec(n, "host-a", 5), http.StatusTooManyRequests, "agent_busy")
	time.Sleep(150 * time.Millisecond)
	if got := len(a.received()); got != 2 {
		t.Errorf("host-a received %d tasks: a rejected request must send NOTHING to the agent", got)
	}

	// the limit is per agent: host-b is untouched
	other := startExecs(n, "host-b", 1, 60)
	waitReceived(t, b, 1)

	// a result frees exactly one slot
	a.answer(a.received()[0])
	if r := <-first; r.Code != http.StatusOK {
		t.Fatalf("answered exec: %+v", r)
	}
	third := startExecs(n, "host-a", 1, 60)
	waitReceived(t, a, 3) // admitted again

	for _, id := range a.received()[1:] {
		a.answer(id)
	}
	b.answer(b.received()[0])
	for _, ch := range []<-chan execReply{first, third, other} {
		select {
		case r := <-ch:
			if r.Code != http.StatusOK {
				t.Errorf("cleanup exec: %+v", r)
			}
		case <-time.After(10 * time.Second):
		}
	}
}

// ── global ───────────────────────────────────────────────────────────────────

func TestTaskLimits_GlobalLimitRejectsWith429(t *testing.T) {
	requireTaskLimits(t)
	parallel(t)
	n := startNode(t, nodeSpec{ID: "root", Env: []string{"MAX_TASKS_PER_AGENT=10", "MAX_TASKS_INFLIGHT=3"}})
	m := heldMinions(t, n, "h1", "h2", "h3", "h4")
	var pending []<-chan execReply
	for _, h := range []string{"h1", "h2", "h3"} {
		pending = append(pending, startExecs(n, h, 1, 60))
		waitReceived(t, m[h], 1)
	}
	expectRejection(t, rawExec(n, "h4", 5), http.StatusTooManyRequests, "too_many_tasks")
	if len(m["h4"].received()) != 0 {
		t.Error("a rejected request must send nothing to the agent")
	}
	for _, h := range []string{"h1", "h2", "h3"} {
		m[h].answer(m[h].received()[0])
	}
	for _, ch := range pending {
		<-ch
	}
	// everything released: the fourth agent is served
	ok := startExecs(n, "h4", 1, 60)
	waitReceived(t, m["h4"], 1)
	m["h4"].answer(m["h4"].received()[0])
	if r := <-ok; r.Code != http.StatusOK {
		t.Errorf("after the release: %+v", r)
	}
}

// Every path that ends a task frees its GLOBAL slot (a leak would end in a permanent 429).
func TestTaskLimits_EveryEndOfTaskFreesItsSlot(t *testing.T) {
	requireTaskLimits(t)
	for _, path := range []string{"result", "timeout", "disconnection", "revocation"} {
		t.Run(path, func(t *testing.T) {
			parallel(t)
			n := startNode(t, nodeSpec{ID: "root", Env: []string{"MAX_TASKS_INFLIGHT=1", "MAX_TASKS_PER_AGENT=1"}})
			tokA := n.enrollAgent("host-a")
			a, err := dialHeld(t, n, "host-a", tokA)
			if err != nil {
				t.Fatal(err)
			}
			b := heldMinions(t, n, "host-b")["host-b"]

			timeout := 60
			if path == "timeout" {
				timeout = 1 // + 5 s of margin on the server side
			}
			ended := startExecs(n, "host-a", 1, timeout)
			waitReceived(t, a, 1)
			expectRejection(t, rawExec(n, "host-b", 5), http.StatusTooManyRequests, "too_many_tasks") // the slot is really taken

			switch path {
			case "result":
				a.answer(a.received()[0])
			case "disconnection":
				_ = a.conn.Close()
			case "revocation":
				if code, _ := n.admin("POST", "/api/admin/revoke/host-a", nil); code != http.StatusOK {
					t.Fatalf("revoke: %d", code)
				}
			case "timeout":
			}
			select {
			case <-ended:
			case <-time.After(30 * time.Second):
				t.Fatal("the exec never ended")
			}

			// the slot is back: another agent is served
			next := startExecs(n, "host-b", 1, 60)
			waitFor(t, "host-b served after "+path, func() bool { return len(b.received()) >= 1 })
			b.answer(b.received()[0])
			if r := <-next; r.Code != http.StatusOK {
				t.Fatalf("after %s: %+v", path, r)
			}
		})
	}
}

// ── memory budget ────────────────────────────────────────────────────────────

func TestTaskLimits_StdoutBudgetRefusesAtAdmissionWith503AndIsReleased(t *testing.T) {
	requireTaskLimits(t)
	parallel(t)
	const mib = 1 << 20
	// 12 MiB: two tasks holding 4 MiB leave 4 MiB, below the 5 MiB a task may still produce
	n := startNode(t, nodeSpec{ID: "root", Env: []string{"MAX_STDOUT_BUFFER_TOTAL=" + strconv.Itoa(12*mib), "MAX_TASKS_INFLIGHT=100"}})
	m := heldMinions(t, n, "h1", "h2", "h3")
	var pending []<-chan execReply
	for _, h := range []string{"h1", "h2"} {
		pending = append(pending, startExecs(n, h, 1, 60))
		waitReceived(t, m[h], 1)
		m[h].stream(m[h].received()[0], 4, mib)
	}
	time.Sleep(500 * time.Millisecond) // the server has buffered the chunks
	expectRejection(t, rawExec(n, "h3", 5), http.StatusServiceUnavailable, "memory_budget_exhausted")
	if len(m["h3"].received()) != 0 {
		t.Error("a task refused for memory must send nothing to the agent")
	}
	for _, h := range []string{"h1", "h2"} {
		m[h].answer(m[h].received()[0])
	}
	for _, ch := range pending {
		<-ch
	}
	ok := startExecs(n, "h3", 1, 60) // buffers released: admitted again
	waitReceived(t, m["h3"], 1)
	m["h3"].answer(m["h3"].received()[0])
	if r := <-ok; r.Code != http.StatusOK {
		t.Errorf("after the release of the budget: %+v", r)
	}
}

// ── load: 3 000 simulated agents (perf scope) ────────────────────────────────

// vmHWM returns the peak resident set of the node process, in bytes.
func vmHWM(t *testing.T, pid int) int64 {
	t.Helper()
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		t.Skipf("cannot read /proc/%d/status: %v", pid, err)
	}
	for _, l := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(l, "VmHWM:") {
			f := strings.Fields(l)
			kb, _ := strconv.ParseInt(f[1], 10, 64)
			return kb * 1024
		}
	}
	return 0
}

// A nominal playbook (forks 200) over 3 000 agents is never rejected with the DEFAULT limits; a
// saturation (1 000 tasks each producing 5 MiB) is refused cleanly and the process stays under 2 GiB.
func TestTaskLimits_Load3000AgentsNominalThenSaturation(t *testing.T) {
	requireTaskLimits(t)
	if testing.Short() {
		t.Skip("load test")
	}
	parallel(t)
	const agents, forks, saturating = 3000, 200, 1000
	n := startNode(t, nodeSpec{ID: "load"}) // DEFAULT limits: that is the point

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

	hwm := vmHWM(t, n.cmd.Process.Pid)
	t.Logf("saturation: %d ok, %d 429, %d 503 memory, %d other; node VmHWM = %.0f MiB (limit 2048)", ok.Load(), busy.Load(), memory.Load(), other.Load(), float64(hwm)/(1<<20))
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
