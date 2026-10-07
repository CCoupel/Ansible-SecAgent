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
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

const specTaskLimits179 = true // dev-relay: true when #179 lands

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
