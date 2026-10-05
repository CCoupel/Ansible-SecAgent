package forward

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/websocket"

	"secagent-server/cmd/secagent-server/internal/repeater"
	"secagent-server/cmd/secagent-server/internal/storage"
	"secagent-server/cmd/secagent-server/internal/ws"
)

const fwdSecret = "forward-test-secret"
const wait = 5 * time.Second

func TestMain(m *testing.M) {
	ws.SetJWTSecretsFunc(func() (string, string, time.Time) { return fwdSecret, "", time.Time{} })
	ws.SetRelayJTIBlacklistFunc(func(string) (bool, error) { return false, nil })
	ws.SetRelayRevokedFunc(func(string) (bool, error) { return false, nil })
	os.Exit(m.Run())
}

func relayJWT(t *testing.T, id string) string {
	t.Helper()
	raw, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": id, "role": "relay", "jti": "fwd-" + id,
		"iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(),
	}).SignedString([]byte(fwdSecret))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// childRelay connects a mock child relay (id) to a /ws/relay handler: a "relay" in the ws
// registry that the Forwarder can dispatch to. Returns the client side of the link.
func childRelay(t *testing.T, id string) *websocket.Conn {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(ws.RelayHandler))
	t.Cleanup(srv.Close)
	h := http.Header{}
	h.Set("Authorization", "Bearer "+relayJWT(t, id))
	c, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http")+"/ws/relay", h)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	deadline := time.Now().Add(wait)
	for !ws.IsRelayConnected(id) {
		if time.Now().After(deadline) {
			t.Fatalf("relay %s not registered", id)
		}
		time.Sleep(5 * time.Millisecond)
	}
	return c
}

// localAgent registers a directly connected minion whose "agent side" answers every task
// with the given result and records the messages it received.
type localAgent struct {
	mu   sync.Mutex
	msgs []map[string]any
}

func connectAgent(t *testing.T, hostname string, rc int, stdout, data string) *localAgent {
	t.Helper()
	la := &localAgent{}
	up := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		ws.RegisterConnection(hostname, &ws.AgentConnection{Hostname: hostname, Conn: c})
		select {} // keep the handler (and the hijacked conn) alive until the test ends
	}))
	client, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ws.UnregisterConnection(hostname); _ = client.Close(); srv.Close() })
	go func() {
		for {
			var m map[string]any
			if err := client.ReadJSON(&m); err != nil {
				return
			}
			la.mu.Lock()
			la.msgs = append(la.msgs, m)
			la.mu.Unlock()
			id, _ := m["task_id"].(string)
			ws.HandleMessage(ws.Message{TaskID: id, Type: "result", RC: rc, Stdout: stdout, Data: data}, hostname)
		}
	}()
	deadline := time.Now().Add(wait)
	for {
		if _, err := ws.GetConnection(hostname); err == nil {
			return la
		}
		if time.Now().After(deadline) {
			t.Fatal("agent not registered")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func (a *localAgent) received() []map[string]any {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]map[string]any(nil), a.msgs...)
}

// run executes Forwarder.Handle on msg and returns the task_result sent back to the parent.
func run(t *testing.T, f *Forwarder, msg ws.RelayMessage) ws.RelayMessage {
	t.Helper()
	raw, _ := json.Marshal(msg)
	var got ws.RelayMessage
	var n int
	f.Handle(context.Background(), raw, func(v any) error {
		b, _ := json.Marshal(v)
		n++
		return json.Unmarshal(b, &got)
	})
	if n != 1 || got.Type != "task_result" || got.TaskID != msg.TaskID {
		t.Fatalf("expected exactly one task_result for %s, got n=%d %+v", msg.TaskID, n, got)
	}
	return got
}

func routeStore(t *testing.T) *storage.Store {
	t.Helper()
	s, err := storage.NewStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func addRoute(t *testing.T, s *storage.Store, host, declaring string, chain ...string) {
	t.Helper()
	for _, id := range append([]string{declaring}, chain...) {
		_ = s.UpsertRelayNode(storage.RelayNode{ID: "u-" + id, RelayID: id, Mode: "pull", Status: "connected", CreatedAt: 1})
	}
	if _, err := s.UpsertRelayRoute(host, declaring, chain); err != nil {
		t.Fatal(err)
	}
}

// ── local agent ──────────────────────────────────────────────────────────────

func TestForward_ExecOnLocalAgent(t *testing.T) {
	agent := connectAgent(t, "minion-1", 0, "hello", "")
	f := &Forwarder{NextHop: func(string) (string, error) { return "", nil }}
	res := run(t, f, ws.RelayMessage{Type: "task_dispatch", TaskID: "t-exec", Hostname: "minion-1",
		Cmd: "echo hello", Timeout: 5, Become: true, BecomeMethod: "sudo", Stdin: "c2VjcmV0"})
	if res.Error != "" || res.RC != 0 || res.Stdout != "hello" {
		t.Errorf("result = %+v", res)
	}
	got := agent.received()
	if len(got) != 1 || got[0]["type"] != "exec" || got[0]["cmd"] != "echo hello" ||
		got[0]["become"] != true || got[0]["stdin"] != "c2VjcmV0" || got[0]["become_method"] != "sudo" {
		t.Errorf("agent got %v", got)
	}
}

func TestForward_FileUploadAndFetchOnLocalAgent(t *testing.T) {
	agent := connectAgent(t, "minion-2", 0, "", "ZGF0YQ==")
	f := &Forwarder{}
	up := run(t, f, ws.RelayMessage{Type: "file_upload", TaskID: "t-up", Hostname: "minion-2", Dest: "/tmp/x", Data: "ZGF0YQ=="})
	if up.Error != "" || up.RC != 0 {
		t.Errorf("upload result = %+v", up)
	}
	fe := run(t, f, ws.RelayMessage{Type: "file_fetch", TaskID: "t-fe", Hostname: "minion-2", Src: "/etc/hostname"})
	if fe.Error != "" || fe.Data != "ZGF0YQ==" {
		t.Errorf("fetch result = %+v", fe)
	}
	got := agent.received()
	if len(got) != 2 || got[0]["type"] != "put_file" || got[0]["mode"] != "0644" || got[1]["type"] != "fetch_file" {
		t.Errorf("agent got %v", got)
	}
}

// ── child → minion, end to end through the Uplink ────────────────────────────

// The parent sends a task_dispatch down the WSS link; the child's Uplink hands it to the
// Forwarder, which runs it on the minion and answers with a task_result on the same link.
func TestForward_ParentToMinionThroughUplink(t *testing.T) {
	connectAgent(t, "minion-3", 7, "from-minion", "")
	results := make(chan map[string]any, 4)
	up := websocket.Upgrader{}
	parent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		// parent side: send the task first, then collect what the child answers
		_ = c.WriteJSON(map[string]any{"type": "task_dispatch", "task_id": "t-chain", "hostname": "minion-3", "cmd": "id", "timeout": 5})
		for {
			var m map[string]any
			if err := c.ReadJSON(&m); err != nil {
				return
			}
			results <- m
		}
	}))
	defer parent.Close()

	f := &Forwarder{NextHop: func(string) (string, error) { return "", nil }}
	uplink := repeater.NewUplink("dmz1", repeater.Options{OnTask: f.Handle, PingInterval: time.Hour, AgentListInterval: time.Hour})
	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(parent.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = uplink.Serve(ctx, conn) }()

	deadline := time.After(wait)
	for {
		select {
		case m := <-results:
			if m["type"] != "task_result" {
				continue // topology_snapshot, agent_list
			}
			if m["task_id"] != "t-chain" || m["rc"] != float64(7) || m["stdout"] != "from-minion" {
				t.Errorf("task_result = %v", m)
			}
			return
		case <-deadline:
			t.Fatal("no task_result came back up the link")
		}
	}
}

// ── downstream relay ─────────────────────────────────────────────────────────

func TestForward_RelaysToDirectChildNotToDeclaringRelay(t *testing.T) {
	s := routeStore(t)
	// deep-host lives under zone-a, which is reached through dmz1 (next hop = chain[0])
	addRoute(t, s, "deep-host", "zone-a", "dmz1", "zone-a")
	dmz1 := childRelay(t, "dmz1")
	f := &Forwarder{NextHop: s.GetNextHopForHostname}

	done := make(chan ws.RelayMessage, 1)
	go func() {
		done <- run(t, f, ws.RelayMessage{Type: "task_dispatch", TaskID: "t-deep", Hostname: "deep-host",
			Cmd: "uptime", Timeout: 5, Become: true, Stdin: "cGFzcw=="})
	}()

	var got ws.RelayMessage
	_ = dmz1.SetReadDeadline(time.Now().Add(wait))
	if err := dmz1.ReadJSON(&got); err != nil {
		t.Fatalf("dmz1 never received the task: %v", err)
	}
	if got.Type != "task_dispatch" || got.TaskID != "t-deep" || got.Hostname != "deep-host" ||
		got.Cmd != "uptime" || got.Stdin != "cGFzcw==" || !got.Become {
		t.Errorf("dmz1 received %+v", got)
	}
	if err := dmz1.WriteJSON(ws.RelayMessage{Type: "task_result", TaskID: "t-deep", RC: 3, Stdout: "up 3 days"}); err != nil {
		t.Fatal(err)
	}
	select {
	case res := <-done:
		if res.RC != 3 || res.Stdout != "up 3 days" || res.Error != "" {
			t.Errorf("result = %+v", res)
		}
	case <-time.After(wait):
		t.Fatal("no result")
	}
	if ws.IsRelayConnected("zone-a") {
		t.Error("zone-a must never be dispatched to directly")
	}
}

func TestForward_LiveAgentBeatsRoutingTable(t *testing.T) {
	s := routeStore(t)
	addRoute(t, s, "contested", "dmz9", "dmz9") // a relay claims the host…
	dmz9 := childRelay(t, "dmz9")
	agent := connectAgent(t, "contested", 0, "local-run", "") // …but it is connected here
	f := &Forwarder{NextHop: s.GetNextHopForHostname}
	res := run(t, f, ws.RelayMessage{Type: "task_dispatch", TaskID: "t-contested", Hostname: "contested", Cmd: "id", Timeout: 5, Stdin: "c2VjcmV0"})
	if res.Stdout != "local-run" {
		t.Errorf("result = %+v, want the local agent", res)
	}
	if len(agent.received()) != 1 {
		t.Error("the local agent must have run the task")
	}
	_ = dmz9.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	var leaked ws.RelayMessage
	if err := dmz9.ReadJSON(&leaked); err == nil {
		t.Errorf("task (and stdin) leaked to the claiming relay: %+v", leaked)
	}
}

func TestForward_ErrorsAreReportedUpstream(t *testing.T) {
	s := routeStore(t)
	addRoute(t, s, "orphan", "dmz-off", "dmz-off") // routed via a relay that is not connected
	f := &Forwarder{NextHop: s.GetNextHopForHostname}
	tests := []struct {
		name string
		msg  ws.RelayMessage
		want string
	}{
		{"unknown host", ws.RelayMessage{Type: "task_dispatch", TaskID: "e1", Hostname: "nobody", Cmd: "id"}, ErrHostNotFound},
		{"next hop offline", ws.RelayMessage{Type: "task_dispatch", TaskID: "e2", Hostname: "orphan", Cmd: "id"}, ErrRelayOffline},
		{"unsupported type", ws.RelayMessage{Type: "agent_list", TaskID: "e3", Hostname: "x"}, ErrInvalidTask},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if res := run(t, f, tt.msg); res.Error != tt.want {
				t.Errorf("error = %q, want %q", res.Error, tt.want)
			}
		})
	}
	t.Run("route lookup failure", func(t *testing.T) {
		bad := &Forwarder{NextHop: func(string) (string, error) { return "", context.DeadlineExceeded }}
		if res := run(t, bad, ws.RelayMessage{Type: "task_dispatch", TaskID: "e4", Hostname: "x", Cmd: "id"}); res.Error != ErrRouteLookup {
			t.Errorf("error = %q", res.Error)
		}
	})
	t.Run("missing hostname is dropped with an invalid_task reply", func(t *testing.T) {
		var got ws.RelayMessage
		raw, _ := json.Marshal(ws.RelayMessage{Type: "task_dispatch", TaskID: "e5"})
		f.Handle(context.Background(), raw, func(v any) error {
			b, _ := json.Marshal(v)
			return json.Unmarshal(b, &got)
		})
		if got.TaskID != "e5" || got.Error != ErrInvalidTask {
			t.Errorf("reply = %+v", got)
		}
	})
	t.Run("garbage without task_id gets no reply", func(t *testing.T) {
		called := false
		f.Handle(context.Background(), json.RawMessage(`{not json`), func(any) error { called = true; return nil })
		if called {
			t.Error("no reply expected without a task_id")
		}
	})
}

func TestForward_ContextCancelStopsWaiting(t *testing.T) {
	s := routeStore(t)
	addRoute(t, s, "slow-host", "dmz2", "dmz2")
	childRelay(t, "dmz2") // never answers
	f := &Forwarder{NextHop: s.GetNextHopForHostname}
	ctx, cancel := context.WithCancel(context.Background())
	out := make(chan ws.RelayMessage, 1)
	go func() {
		raw, _ := json.Marshal(ws.RelayMessage{Type: "task_dispatch", TaskID: "t-cancel", Hostname: "slow-host", Cmd: "sleep", Timeout: 30})
		f.Handle(ctx, raw, func(v any) error {
			b, _ := json.Marshal(v)
			var m ws.RelayMessage
			_ = json.Unmarshal(b, &m)
			out <- m
			return nil
		})
	}()
	cancel()
	select {
	case m := <-out:
		if m.Error != "context_cancelled" {
			t.Errorf("error = %q", m.Error)
		}
	case <-time.After(wait):
		t.Fatal("Handle did not return after cancel")
	}
}

// #173: the relay that holds the agent decides; the refusal travels up in task_result.error.
func TestForward_SuspendedLocalAgentRefusesAndLiftIsImmediate(t *testing.T) {
	agent := connectAgent(t, "susp-1", 0, "ran", "")
	var suspended bool
	var failure error
	f := &Forwarder{
		NextHop:   func(string) (string, error) { return "", nil },
		Suspended: func(string) (bool, error) { return suspended, failure },
	}
	msg := ws.RelayMessage{Type: "task_dispatch", TaskID: "t-susp", Hostname: "susp-1", Cmd: "id", Timeout: 5, Stdin: "c2VjcmV0"}

	suspended = true
	for _, typ := range []string{"task_dispatch", "file_upload", "file_fetch"} {
		m := msg
		m.Type, m.TaskID = typ, "t-"+typ
		if res := run(t, f, m); res.Error != ErrAgentSuspended {
			t.Errorf("%s: error = %q, want %q", typ, res.Error, ErrAgentSuspended)
		}
	}
	failure = errors.New("db down")
	suspended = false
	if res := run(t, f, msg); res.Error != ErrAgentStateUnavailable {
		t.Errorf("unreadable state: error = %q, want %q (fail closed)", res.Error, ErrAgentStateUnavailable)
	}

	failure = nil
	msg.TaskID = "t-after"
	if res := run(t, f, msg); res.Error != "" || res.Stdout != "ran" {
		t.Errorf("after resume: %+v", res)
	}
	if got := agent.received(); len(got) != 1 || got[0]["task_id"] != "t-after" {
		t.Errorf("only the post-resume task may reach the agent: %v", got)
	}
}
