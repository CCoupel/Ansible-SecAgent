package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"secagent-server/cmd/secagent-server/internal/ws"
)

// connectLocalAgent registers a live /ws/agent connection that answers every task with stdout.
func connectLocalAgent(t *testing.T, hostname, stdout string) {
	t.Helper()
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
			id, _ := m["task_id"].(string)
			ws.HandleMessage(ws.Message{TaskID: id, Type: "result", Stdout: stdout}, hostname)
		}
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := ws.GetConnection(hostname); err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("agent not registered")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// A relay declaring a host that is connected to this node must not divert its tasks:
// the live agent connection wins over relay_routing (the claiming relay is even offline here,
// which would have produced relay_offline before).
func TestExecCommand_LocalAgentWinsOverRoutingTable(t *testing.T) {
	s, withAuth := setupProxyTest(t)
	seedProxyRelay(t, s, "dmz-claims", "", []string{"contested-host"})
	connectLocalAgent(t, "contested-host", "ran-locally")

	body, _ := json.Marshal(map[string]interface{}{"cmd": "id", "timeout": 5})
	req := withAuth(httptest.NewRequest("POST", "/api/exec/contested-host", bytes.NewReader(body)))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("hostname", "contested-host")
	w := httptest.NewRecorder()
	ExecCommand(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["stdout"] != "ran-locally" {
		t.Errorf("response = %v, want the local agent's output", resp)
	}
}

func TestIsLocalAgent(t *testing.T) {
	if isLocalAgent("nobody-here") {
		t.Error("unknown host must not be local")
	}
	connectLocalAgent(t, "here", "x")
	if !isLocalAgent("here") {
		t.Error("connected host must be local")
	}
}
