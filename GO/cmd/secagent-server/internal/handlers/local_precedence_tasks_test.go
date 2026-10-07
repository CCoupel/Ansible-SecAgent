package handlers

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"secagent-server/cmd/secagent-server/internal/auth"
	"secagent-server/cmd/secagent-server/internal/link"
	"secagent-server/cmd/secagent-server/internal/ws"
)

// Precedence rule (#127): an agent connected to THIS node always wins over relay_routing.
// A relay that declares such a host (even an online one) must never receive the task, the
// file content, the fetch request nor the stdin / become_pass of an exec.

const precSecret = "precedence-test-secret"

// precAgent is a locally connected minion that records what it receives and answers rc=0.
type precAgent struct {
	mu   sync.Mutex
	msgs []map[string]any
}

func (a *precAgent) received() []map[string]any {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]map[string]any(nil), a.msgs...)
}

func connectPrecAgent(t *testing.T, hostname string) *precAgent {
	t.Helper()
	a := &precAgent{}
	up := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		ws.RegisterConnection(hostname, &ws.AgentConnection{Hostname: hostname, Conn: c})
		select {}
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
			a.mu.Lock()
			a.msgs = append(a.msgs, m)
			a.mu.Unlock()
			id, _ := m["task_id"].(string)
			ws.HandleMessage(ws.Message{TaskID: id, Type: "result", Stdout: "local-ok",
				Data: base64.StdEncoding.EncodeToString([]byte("local-file"))}, hostname)
		}
	}()
	waitUntil(t, "agent registered", func() bool { _, err := ws.GetConnection(hostname); return err == nil })
	return a
}

func waitUntil(t *testing.T, what string, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !fn() {
		if time.Now().After(deadline) {
			t.Fatalf("timeout waiting for: %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// spyRelay is an ONLINE relay (real /ws/relay link) that records every task it is sent and
// answers each with an error so that a regression fails fast instead of hanging.
type spyRelay struct {
	id     string
	mu     sync.Mutex
	tasks  []ws.RelayMessage
	probed chan struct{}
	probe  string
}

func newSpyRelay(t *testing.T, id string) *spyRelay {
	t.Helper()
	m := useLinkRoot(t) // this node is the root "central"; the spy presents a relay-child link token
	ws.SetRelayJTIBlacklistFunc(func(string) (bool, error) { return false, nil })
	ws.SetRelayRevokedFunc(func(string) (bool, error) { return false, nil })
	t.Cleanup(func() {
		ws.SetRelayJTIBlacklistFunc(nil)
		ws.SetRelayRevokedFunc(nil)
	})
	minted, err := m.Mint(context.Background(), link.MintRequest{Role: auth.RoleRelayChild, Sub: id, Aud: testRootID, TTL: time.Hour, CreatedBy: "test"})
	if err != nil {
		t.Fatal(err)
	}
	raw := minted.Token
	srv := httptest.NewServer(http.HandlerFunc(ws.RelayHandler))
	h := http.Header{}
	h.Set("Authorization", "Bearer "+raw)
	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http")+"/ws/relay", h)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close(); srv.Close() })

	s := &spyRelay{id: id, probed: make(chan struct{}), probe: "probe-" + id}
	go func() {
		for {
			var m ws.RelayMessage
			if err := conn.ReadJSON(&m); err != nil {
				return
			}
			switch m.Type {
			case "task_dispatch", "file_upload", "file_fetch", "task_forward":
			default:
				continue
			}
			if m.TaskID == s.probe {
				close(s.probed)
				continue
			}
			s.mu.Lock()
			s.tasks = append(s.tasks, m)
			s.mu.Unlock()
			_ = conn.WriteJSON(ws.RelayMessage{Type: "task_result", TaskID: m.TaskID, Error: "spy_relay_received_task"})
		}
	}()
	waitUntil(t, "spy relay registered", func() bool { return ws.IsRelayConnected(id) })
	return s
}

// assertNothingReceived proves the relay saw no task: a probe sent on the same ordered link
// after the request must arrive, and nothing may have arrived before it.
func (s *spyRelay) assertNothingReceived(t *testing.T) {
	t.Helper()
	if _, err := ws.DispatchToRelay(s.id, ws.RelayMessage{Type: "task_dispatch", TaskID: s.probe, Hostname: "probe"}); err != nil {
		t.Fatalf("probe dispatch: %v", err)
	}
	defer ws.UnregisterRelayTaskFuture(s.probe)
	select {
	case <-s.probed:
	case <-time.After(5 * time.Second):
		t.Fatal("probe never reached the spy relay")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, m := range s.tasks {
		t.Errorf("claiming relay received a task it must never see: type=%s host=%s stdin=%q dest=%q data_len=%d src=%q",
			m.Type, m.Hostname, m.Stdin, m.Dest, len(m.Data), m.Src)
	}
}

func precRequest(t *testing.T, withAuth func(*http.Request) *http.Request, handler http.HandlerFunc,
	method, path, host string, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	b, _ := json.Marshal(body)
	req := withAuth(httptest.NewRequest(method, path, bytes.NewReader(b)))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("hostname", host)
	w := httptest.NewRecorder()
	handler(w, req)
	return w
}

func precSetup(t *testing.T, host string) (*precAgent, *spyRelay, func(*http.Request) *http.Request) {
	t.Helper()
	s, withAuth := setupProxyTest(t)
	seedProxyRelay(t, s, "dmz-claims", "", []string{host})
	spy := newSpyRelay(t, "dmz-claims")
	agent := connectPrecAgent(t, host)
	return agent, spy, withAuth
}

func TestLocalPrecedence_UploadGoesToLocalAgentNotClaimingRelay(t *testing.T) {
	host := "prec-upload-host"
	agent, spy, withAuth := precSetup(t, host)
	content := base64.StdEncoding.EncodeToString([]byte("sensitive file content"))

	w := precRequest(t, withAuth, UploadFile, "POST", "/api/upload/"+host, host,
		map[string]any{"dest": "/etc/app.conf", "data": content, "mode": "0600"})
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	got := agent.received()
	if len(got) != 1 || got[0]["type"] != "put_file" || got[0]["dest"] != "/etc/app.conf" || got[0]["data"] != content {
		t.Errorf("local agent must receive the file: %v", got)
	}
	spy.assertNothingReceived(t)
}

func TestLocalPrecedence_FetchGoesToLocalAgentNotClaimingRelay(t *testing.T) {
	host := "prec-fetch-host"
	agent, spy, withAuth := precSetup(t, host)

	w := precRequest(t, withAuth, FetchFile, "POST", "/api/fetch/"+host, host, map[string]any{"src": "/etc/shadow"})
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if want := base64.StdEncoding.EncodeToString([]byte("local-file")); resp["data"] != want {
		t.Errorf("fetch data = %v, want the local agent's file", resp["data"])
	}
	got := agent.received()
	if len(got) != 1 || got[0]["type"] != "fetch_file" || got[0]["src"] != "/etc/shadow" {
		t.Errorf("local agent must receive the fetch request: %v", got)
	}
	spy.assertNothingReceived(t)
}

func TestLocalPrecedence_ExecStdinAndBecomeStayOnLocalAgent(t *testing.T) {
	host := "prec-exec-host"
	agent, spy, withAuth := precSetup(t, host)
	stdin := base64.StdEncoding.EncodeToString([]byte("become-password-secret"))

	w := precRequest(t, withAuth, ExecCommand, "POST", "/api/exec/"+host, host,
		map[string]any{"cmd": "id", "timeout": 5, "stdin": stdin, "become": true, "become_method": "sudo"})
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	got := agent.received()
	if len(got) != 1 || got[0]["type"] != "exec" || got[0]["stdin"] != stdin || got[0]["become"] != true {
		t.Errorf("local agent must receive the exec with its stdin: %v", got)
	}
	spy.assertNothingReceived(t)
}
