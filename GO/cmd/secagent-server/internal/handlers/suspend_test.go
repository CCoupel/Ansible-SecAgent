package handlers

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// #173: a suspended agent receives nothing, whatever the endpoint; lifting the suspension is
// immediate (no reconnection); an unreadable state refuses (fail closed).

type suspendCase struct {
	name    string
	handler http.HandlerFunc
	path    string
	body    map[string]any
	msgType string
}

func suspendCases(host string) []suspendCase {
	data := base64.StdEncoding.EncodeToString([]byte("content"))
	return []suspendCase{
		{"exec", ExecCommand, "/api/exec/" + host, map[string]any{"cmd": "id", "timeout": 5}, "exec"},
		{"upload", UploadFile, "/api/upload/" + host, map[string]any{"dest": "/tmp/f", "data": data, "mode": "0600"}, "put_file"},
		{"fetch", FetchFile, "/api/fetch/" + host, map[string]any{"src": "/etc/hostname"}, "fetch_file"},
	}
}

func TestSuspend_RefusesExecUploadFetchThenResumeIsImmediate(t *testing.T) {
	host := "susp-host"
	agent, _, withAuth := precSetup(t, host)
	if _, err := adminStore.RegisterAgent(context.Background(), host, "pem", "jti-susp"); err != nil {
		t.Fatal(err)
	}
	if ok, err := adminStore.SetSuspended(context.Background(), host, true); err != nil || !ok {
		t.Fatalf("suspend: %v %v", ok, err)
	}

	for _, c := range suspendCases(host) {
		w := precRequest(t, withAuth, c.handler, "POST", c.path, host, c.body)
		var resp map[string]string
		_ = json.Unmarshal(w.Body.Bytes(), &resp)
		if w.Code != http.StatusServiceUnavailable || resp["error"] != "agent_suspended" {
			t.Errorf("%s on a suspended agent: %d %s, want 503 agent_suspended", c.name, w.Code, w.Body.String())
		}
	}

	// resume: accepted again WITHOUT reconnecting; the agent only ever saw these three tasks
	// (messages are delivered in order: nothing was sent during the suspension)
	if _, err := adminStore.SetSuspended(context.Background(), host, false); err != nil {
		t.Fatal(err)
	}
	for _, c := range suspendCases(host) {
		w := precRequest(t, withAuth, c.handler, "POST", c.path, host, c.body)
		if w.Code != http.StatusOK {
			t.Fatalf("%s after resume: %d %s", c.name, w.Code, w.Body.String())
		}
	}
	got := agent.received()
	if len(got) != 3 || got[0]["type"] != "exec" || got[1]["type"] != "put_file" || got[2]["type"] != "fetch_file" {
		t.Errorf("the agent must have received only the 3 post-resume tasks, got %v", got)
	}
}

func TestSuspend_OtherAgentsAreUnaffected(t *testing.T) {
	agent, _, withAuth := precSetup(t, "susp-other")
	if _, err := adminStore.RegisterAgent(context.Background(), "susp-other", "pem", "j1"); err != nil {
		t.Fatal(err)
	}
	if _, err := adminStore.RegisterAgent(context.Background(), "susp-victim", "pem", "j2"); err != nil {
		t.Fatal(err)
	}
	if _, err := adminStore.SetSuspended(context.Background(), "susp-victim", true); err != nil {
		t.Fatal(err)
	}
	w := precRequest(t, withAuth, ExecCommand, "POST", "/api/exec/susp-other", "susp-other", map[string]any{"cmd": "id", "timeout": 5})
	if w.Code != http.StatusOK || len(agent.received()) != 1 {
		t.Errorf("a non-suspended agent must run its task: %d %s", w.Code, w.Body.String())
	}
}

func TestSuspend_StoreFailureRefusesFailClosed(t *testing.T) {
	host := "susp-failclosed"
	agent, _, withAuth := precSetup(t, host)
	if _, err := adminStore.RegisterAgent(context.Background(), host, "pem", "j"); err != nil {
		t.Fatal(err)
	}
	if err := adminStore.Close(); err != nil { // the state can no longer be read
		t.Fatal(err)
	}
	for _, c := range suspendCases(host) {
		w := precRequest(t, withAuth, c.handler, "POST", c.path, host, c.body)
		// the plugin token lookup uses the same store: it fails first (500) or the check refuses (503);
		// either way nothing may reach the agent
		if w.Code == http.StatusOK {
			t.Errorf("%s accepted with an unreadable store", c.name)
		}
	}
	if got := agent.received(); len(got) != 0 {
		t.Errorf("nothing must be sent to the agent: %v", got)
	}
}

func TestAgentSuspended_NoStoreIsAnError(t *testing.T) {
	prev := adminStore
	adminStore = nil
	defer func() { adminStore = prev }()
	if _, err := AgentSuspended("h"); err == nil {
		t.Error("without a store the answer must be an error (refuse)")
	}
}

func TestWriteProxyExecError_RelaysSuspensionRefusal(t *testing.T) {
	for _, code := range []string{ErrAgentSuspended, ErrAgentStateUnavailable} {
		w := httptest.NewRecorder()
		writeProxyExecError(w, errString(code), "h", "t")
		var resp map[string]string
		_ = json.Unmarshal(w.Body.Bytes(), &resp)
		if w.Code != http.StatusServiceUnavailable || resp["error"] != code {
			t.Errorf("%s relayed as %d %s", code, w.Code, w.Body.String())
		}
	}
}

type errString string

func (e errString) Error() string { return string(e) }

// The check itself, isolated from the plugin token lookup: an unreadable state answers 503
// agent_state_unavailable and never "not suspended".
func TestRefuseIfSuspended_UnreadableStateIsRefused(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	if !refuseIfSuspended(w, "h", "t", "exec") {
		t.Fatal("an unreadable suspension state must refuse")
	}
	if w.Code != http.StatusServiceUnavailable || w.Body.String() == "" {
		t.Errorf("got %d %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["error"] != ErrAgentStateUnavailable {
		t.Errorf("error = %q, want %q", resp["error"], ErrAgentStateUnavailable)
	}
}

func TestInventory_ListsSuspendedAgentWithFlag(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)
	ctx := context.Background()
	for _, h := range []string{"inv-ok", "inv-susp"} {
		if _, err := s.RegisterAgent(ctx, h, "pem", "j-"+h); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.SetSuspended(ctx, "inv-susp", true); err != nil {
		t.Fatal(err)
	}
	inv := buildInventory(inventoryOptions{})
	if hv, ok := inv.Meta.Hostvars["inv-susp"]; !ok || !hv.Suspended {
		t.Errorf("suspended agent must be listed with Suspended=true: %+v ok=%v", hv, ok)
	}
	if hv := inv.Meta.Hostvars["inv-ok"]; hv.Suspended {
		t.Error("a normal agent must not be flagged")
	}
	raw, _ := json.Marshal(inv.Meta.Hostvars["inv-ok"])
	if string(raw) == "" || json.Valid(raw) == false {
		t.Fatal("hostvars must marshal")
	}
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	if _, present := m["secagent_suspended"]; present {
		t.Error("secagent_suspended must be omitted for a non-suspended agent")
	}
}

// A caller-supplied task_id / hostname is logged with %q: it can not forge a log line.
func TestExecLogsQuoteCallerSuppliedIdentifiers(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)
	if _, err := s.RegisterAgent(context.Background(), "h", "pem", "j"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetSuspended(context.Background(), "h", true); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer // capture only what the call under test logs
	prev := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(prev)
	evil := "t1\n[SECURITY WARNING] forged line"
	refuseIfSuspended(httptest.NewRecorder(), "h", evil, "exec")
	out := buf.String()
	if strings.Count(strings.TrimSuffix(out, "\n"), "\n") != 0 || !strings.Contains(out, `task_id="t1\n[SECURITY WARNING] forged line"`) {
		t.Errorf("the task_id must be quoted on ONE line: %q", out)
	}
}
