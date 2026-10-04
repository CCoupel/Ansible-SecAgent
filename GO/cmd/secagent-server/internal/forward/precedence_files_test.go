package forward

import (
	"encoding/base64"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"secagent-server/cmd/secagent-server/internal/ws"
)

// claimingRelaySpy reads everything a (claiming) relay link receives, answers each task with an
// error so a regression fails fast, and can prove — with an ordered probe — that nothing arrived.
type claimingRelaySpy struct {
	id     string
	probe  string
	probed chan struct{}
	mu     sync.Mutex
	tasks  []ws.RelayMessage
}

func spyOn(t *testing.T, id string, conn *websocket.Conn) *claimingRelaySpy {
	t.Helper()
	s := &claimingRelaySpy{id: id, probe: "probe-" + id, probed: make(chan struct{})}
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
	return s
}

func (s *claimingRelaySpy) assertNothingReceived(t *testing.T) {
	t.Helper()
	if _, err := ws.DispatchToRelay(s.id, ws.RelayMessage{Type: "task_dispatch", TaskID: s.probe, Hostname: "probe"}); err != nil {
		t.Fatalf("probe dispatch: %v", err)
	}
	defer ws.UnregisterRelayTaskFuture(s.probe)
	select {
	case <-s.probed:
	case <-time.After(wait):
		t.Fatal("probe never reached the claiming relay")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, m := range s.tasks {
		t.Errorf("claiming relay received a task it must never see: type=%s host=%s dest=%q data_len=%d src=%q",
			m.Type, m.Hostname, m.Dest, len(m.Data), m.Src)
	}
}

// A live agent beats the routing table for file transfers too: the relay declaring the host
// never gets the file content nor the fetch request.
func TestForward_LiveAgentBeatsRoutingTable_FileUpload(t *testing.T) {
	s := routeStore(t)
	addRoute(t, s, "contested-up", "dmz8", "dmz8")
	spy := spyOn(t, "dmz8", childRelay(t, "dmz8"))
	agent := connectAgent(t, "contested-up", 0, "", "")
	f := &Forwarder{NextHop: s.GetNextHopForHostname}
	content := base64.StdEncoding.EncodeToString([]byte("secret file"))

	res := run(t, f, ws.RelayMessage{Type: "file_upload", TaskID: "t-up", Hostname: "contested-up", Dest: "/etc/x", Data: content, Mode: "0600"})
	if res.Error != "" {
		t.Errorf("result = %+v, want success from the local agent", res)
	}
	got := agent.received()
	if len(got) != 1 || got[0]["type"] != "put_file" || got[0]["data"] != content {
		t.Errorf("local agent must receive the file: %v", got)
	}
	spy.assertNothingReceived(t)
}

func TestForward_LiveAgentBeatsRoutingTable_FileFetch(t *testing.T) {
	s := routeStore(t)
	addRoute(t, s, "contested-fetch", "dmz7", "dmz7")
	spy := spyOn(t, "dmz7", childRelay(t, "dmz7"))
	agent := connectAgent(t, "contested-fetch", 0, "", "bG9jYWw=")
	f := &Forwarder{NextHop: s.GetNextHopForHostname}

	res := run(t, f, ws.RelayMessage{Type: "file_fetch", TaskID: "t-fetch", Hostname: "contested-fetch", Src: "/etc/shadow"})
	if res.Error != "" || res.Data != "bG9jYWw=" {
		t.Errorf("result = %+v, want the local agent's data", res)
	}
	got := agent.received()
	if len(got) != 1 || got[0]["type"] != "fetch_file" || got[0]["src"] != "/etc/shadow" {
		t.Errorf("local agent must receive the fetch request: %v", got)
	}
	spy.assertNothingReceived(t)
}

// Exec: stdin / become_pass must stay on the local agent (online claiming relay variant).
func TestForward_LiveAgentBeatsRoutingTable_ExecStdinNeverReachesRelay(t *testing.T) {
	s := routeStore(t)
	addRoute(t, s, "contested-exec", "dmz6", "dmz6")
	spy := spyOn(t, "dmz6", childRelay(t, "dmz6"))
	agent := connectAgent(t, "contested-exec", 0, "local-run", "")
	f := &Forwarder{NextHop: s.GetNextHopForHostname}

	res := run(t, f, ws.RelayMessage{Type: "task_forward", TaskID: "t-exec", Hostname: "contested-exec", Cmd: "id", Timeout: 5, Stdin: "c2VjcmV0", Become: true})
	if res.Stdout != "local-run" {
		t.Errorf("result = %+v, want the local agent", res)
	}
	got := agent.received()
	if len(got) != 1 || got[0]["stdin"] != "c2VjcmV0" {
		t.Errorf("local agent must receive stdin: %v", got)
	}
	spy.assertNothingReceived(t)
}
