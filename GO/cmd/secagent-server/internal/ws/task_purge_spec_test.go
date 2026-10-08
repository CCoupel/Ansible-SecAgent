package ws

// #179 (L2) — every path that ends a task releases its slot: result, timeout, disconnection,
// revocation, loss of the master lock (#163). "Compteurs revenus à 0 après résultat, timeout,
// déconnexion, révocation et perte du verrou (un test par chemin, -race)" — issue #179.
//
// The accounting seen by the tests is specAccounting(): TODAY it reads the maps of the package
// (pendingTasks, taskHostnames, stdoutBuffers) — so these tests already guard the existing purge
// paths; once L2 adds the counters, dev-relay wires them in task_purge_spec_wire_test.go
// (specCounters) and EVERY test asserts them as well, which is what catches a forgotten decrement.
//
// A purge must also run EXACTLY once: a result that arrives twice, or after a timeout, must not
// release a slot that belongs to another task (counter below the real number, i.e. an agent that
// ends up over its limit).

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// specCounters is set by dev-relay's wiring file once the admission counters exist.
type specCountersImpl struct {
	InFlight    func(host string) int // tasks in flight of one agent
	InFlightAll func() int            // tasks in flight in the process (local + relayed)
	StdoutBytes func() int64          // bytes held by the stdout buffers (the memory budget)
}

var specCounters *specCountersImpl

// specAdmit registers a task like the exec handlers do. Today: RegisterFuture. L2 changes the
// signature (typed admission errors): dev-relay adapts this ONE function in the wiring file.
var specAdmit = func(taskID, host string) error {
	_, err := RegisterFuture(taskID, host)
	return err
}

type accounting struct {
	perHost map[string]int
	total   int
	stdout  int64
}

func specAccounting() accounting {
	a := accounting{perHost: map[string]int{}}
	taskHostMu.RLock()
	for _, h := range taskHostnames {
		a.perHost[h]++
	}
	taskHostMu.RUnlock()
	tasksMu.RLock()
	a.total = len(pendingTasks)
	tasksMu.RUnlock()
	buffersMu.RLock()
	for _, b := range stdoutBuffers {
		a.stdout += int64(b.Len())
	}
	buffersMu.RUnlock()
	return a
}

// expectInFlight asserts the maps AND (when wired) the counters, with a bounded wait: some paths
// (disconnection, lock loss) release asynchronously, from the read loop of the connection.
func expectInFlight(t *testing.T, what string, perHost map[string]int, stdoutBytes int64) {
	t.Helper()
	total := 0
	for _, n := range perHost {
		total += n
	}
	check := func() string {
		a := specAccounting()
		for h, want := range perHost {
			if a.perHost[h] != want {
				return fmt.Sprintf("host %s: %d task(s) in flight in the maps, want %d", h, a.perHost[h], want)
			}
		}
		if a.total != total {
			return fmt.Sprintf("%d pending futures in the maps, want %d", a.total, total)
		}
		if a.stdout != stdoutBytes {
			return fmt.Sprintf("%d stdout bytes held in the maps, want %d", a.stdout, stdoutBytes)
		}
		if c := specCounters; c != nil {
			for h, want := range perHost {
				if got := c.InFlight(h); got != want {
					return fmt.Sprintf("counter of %s = %d, want %d (a purge path forgot its decrement, or ran twice)", h, got, want)
				}
			}
			if got := c.InFlightAll(); got != total {
				return fmt.Sprintf("global counter = %d, want %d", got, total)
			}
			if got := c.StdoutBytes(); got != stdoutBytes {
				return fmt.Sprintf("stdout budget counter = %d bytes, want %d", got, stdoutBytes)
			}
		}
		return ""
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if check() == "" {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Errorf("%s: %s", what, check())
}

// agentSession connects a real agent link through AgentHandler and returns the client side.
func agentSession(t *testing.T, host string) *websocket.Conn {
	t.Helper()
	withAgentSecret(t)
	SetAgentJTICheckFunc(func(string, string, bool) error { return nil })
	t.Cleanup(func() { SetAgentJTICheckFunc(nil) })
	srv := httptest.NewServer(http.HandlerFunc(AgentHandler))
	t.Cleanup(srv.Close)
	h := http.Header{"Authorization": {"Bearer " + makeTestJWT("agent-secret", host, time.Now().Add(time.Hour))}}
	c, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), h)
	if err != nil {
		t.Fatalf("dial %s: %v", host, err)
	}
	t.Cleanup(func() { _ = c.Close() })
	if !awaitCondition(3*time.Second, func() bool { _, e := GetConnection(host); return e == nil }) {
		t.Fatalf("agent %s not registered", host)
	}
	return c
}

func admit(t *testing.T, host string, ids ...string) {
	t.Helper()
	for _, id := range ids {
		if err := specAdmit(id, host); err != nil {
			t.Fatalf("admission of %s on %s refused: %v", id, host, err)
		}
	}
}

func sendStdout(t *testing.T, c *websocket.Conn, id string, n int) {
	t.Helper()
	if err := c.WriteJSON(Message{TaskID: id, Type: "stdout", Chunk: strings.Repeat("x", n)}); err != nil {
		t.Fatal(err)
	}
}

// each path, with two other tasks (same agent and another agent) that must NOT be released
func TestTaskPurge_EachPathReleasesExactlyTheTasksOfItsTarget(t *testing.T) {
	paths := []struct {
		name string
		run  func(t *testing.T, host string, c *websocket.Conn)
	}{
		{"result", func(t *testing.T, host string, c *websocket.Conn) {
			_ = c.WriteJSON(Message{TaskID: "t1", Type: "result", RC: 0})
		}},
		{"timeout", func(t *testing.T, host string, c *websocket.Conn) { UnregisterFuture("t1") }},
		{"disconnection", func(t *testing.T, host string, c *websocket.Conn) { _ = c.Close() }},
		{"revocation", func(t *testing.T, host string, c *websocket.Conn) { CloseAgent(host, WSCloseRevoked, "token_revoked") }},
		{"loss of the master lock", func(t *testing.T, host string, c *websocket.Conn) { CloseAllLinks(1001, "master lock lost") }},
	}
	for _, p := range paths {
		t.Run(p.name, func(t *testing.T) {
			resetState()
			c := agentSession(t, "host-a")
			// a second agent: its tasks must survive anything that happens to host-a
			RegisterConnection("host-b", &AgentConnection{Hostname: "host-b"})
			t.Cleanup(func() { UnregisterConnection("host-b") })

			admit(t, "host-a", "t1", "t2")
			admit(t, "host-b", "t3")
			sendStdout(t, c, "t1", 1000)
			sendStdout(t, c, "t2", 500)
			expectInFlight(t, "setup", map[string]int{"host-a": 2, "host-b": 1}, 1500)

			p.run(t, "host-a", c)

			switch p.name {
			case "result", "timeout": // ends ONE task (t1): its sibling t2 and host-b's t3 stay in flight
				expectInFlight(t, p.name, map[string]int{"host-a": 1, "host-b": 1}, 500)
			case "loss of the master lock": // every REAL link is closed: host-a's tasks go (host-b has no socket in this test: its task stays)
				expectInFlight(t, p.name, map[string]int{"host-a": 0, "host-b": 1}, 0)
			default: // the agent is gone: all ITS tasks go, nobody else's
				expectInFlight(t, p.name, map[string]int{"host-a": 0, "host-b": 1}, 0)
			}
		})
	}
}

// a purge runs once: a late or duplicated result must not release the slot of another task
func TestTaskPurge_APurgeRunsOnceNeverTwice(t *testing.T) {
	resetState()
	c := agentSession(t, "host-a")
	admit(t, "host-a", "t1", "t2")
	sendStdout(t, c, "t2", 300)

	_ = c.WriteJSON(Message{TaskID: "t1", Type: "result"})
	expectInFlight(t, "first result", map[string]int{"host-a": 1}, 300)
	_ = c.WriteJSON(Message{TaskID: "t1", Type: "result"}) // duplicate
	UnregisterFuture("t1")                                 // the timeout of the same task, late
	UnregisterFuture("t1")
	_ = c.WriteJSON(Message{TaskID: "never-admitted", Type: "result"})
	// a barrier: a message after the duplicates, processed in order by the same read loop
	sendStdout(t, c, "t2", 0)
	time.Sleep(50 * time.Millisecond)
	expectInFlight(t, "duplicates and late purges", map[string]int{"host-a": 1}, 300)
}

// a slot is not leaked by a task that never got an answer before its agent reconnected
func TestTaskPurge_AReconnectionStartsFromAnEmptyAccount(t *testing.T) {
	resetState()
	c := agentSession(t, "host-a")
	admit(t, "host-a", "t1", "t2", "t3")
	_ = c.Close()
	expectInFlight(t, "after the link dropped", map[string]int{"host-a": 0}, 0)

	c2 := agentSession(t, "host-a")
	admit(t, "host-a", "t4")
	expectInFlight(t, "after reconnection", map[string]int{"host-a": 1}, 0)
	_ = c2.WriteJSON(Message{TaskID: "t4", Type: "result"})
	expectInFlight(t, "after the result", map[string]int{"host-a": 0}, 0)
}
