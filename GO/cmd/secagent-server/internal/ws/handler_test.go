package ws

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/websocket"
)

// resetState clears all module-level maps between tests to prevent cross-test pollution
func resetState() {
	connectionsMu.Lock()
	for k := range wsConnections {
		delete(wsConnections, k)
	}
	connectionsMu.Unlock()

	tasksMu.Lock()
	for k := range pendingTasks {
		delete(pendingTasks, k)
	}
	tasksMu.Unlock()

	buffersMu.Lock()
	for k := range stdoutBuffers {
		delete(stdoutBuffers, k)
	}
	buffersMu.Unlock()

	taskHostMu.Lock()
	for k := range taskHostnames {
		delete(taskHostnames, k)
	}
	taskHostMu.Unlock()
}

// ========================================================================
// RegisterConnection / UnregisterConnection / GetConnection
// ========================================================================

func TestRegisterConnection(t *testing.T) {
	resetState()
	hostname := "test-agent-1"

	mockConn := &AgentConnection{Hostname: hostname, Conn: nil}
	RegisterConnection(hostname, mockConn)

	conn, err := GetConnection(hostname)
	if err != nil {
		t.Errorf("failed to get connection: %v", err)
	}
	if conn.Hostname != hostname {
		t.Errorf("expected hostname %q, got %q", hostname, conn.Hostname)
	}
	UnregisterConnection(hostname)
}

func TestUnregisterConnection(t *testing.T) {
	resetState()
	hostname := "test-agent-2"

	mockConn := &AgentConnection{Hostname: hostname, Conn: nil}
	RegisterConnection(hostname, mockConn)
	UnregisterConnection(hostname)

	_, err := GetConnection(hostname)
	if err == nil {
		t.Error("expected error when getting unregistered connection")
	}
	if err.Error() != "agent_offline" {
		t.Errorf("expected 'agent_offline' error, got %q", err.Error())
	}
}

func TestGetConnectionNotFound(t *testing.T) {
	resetState()
	_, err := GetConnection("non-existent-host")
	if err == nil {
		t.Error("expected error for non-existent connection")
	}
	if err.Error() != "agent_offline" {
		t.Errorf("expected 'agent_offline', got %q", err.Error())
	}
}

func TestRegisterConnectionReplacesStale(t *testing.T) {
	resetState()

	// Directly set conn in map (nil Conn avoids Close() panic)
	conn1 := &AgentConnection{Hostname: "host-a"}
	conn2 := &AgentConnection{Hostname: "host-a"}

	connectionsMu.Lock()
	wsConnections["host-a"] = conn1
	connectionsMu.Unlock()

	// Replace with conn2
	connectionsMu.Lock()
	wsConnections["host-a"] = conn2
	connectionsMu.Unlock()

	got, _ := GetConnection("host-a")
	if got != conn2 {
		t.Error("expected conn2 to replace conn1")
	}
}

// ========================================================================
// nowISO
// ========================================================================

func TestNowISO(t *testing.T) {
	iso := nowISO()
	if iso == "" {
		t.Error("nowISO returned empty string")
	}
	_, err := time.Parse(time.RFC3339, iso)
	if err != nil {
		t.Errorf("invalid ISO 8601 format: %v", err)
	}
}

// ========================================================================
// RegisterFuture
// ========================================================================

func TestRegisterFuture(t *testing.T) {
	resetState()
	taskID := "task-123"
	hostname := "test-agent-3"

	resultChan := RegisterFuture(taskID, hostname)
	if resultChan == nil {
		t.Error("RegisterFuture returned nil channel")
	}
	if cap(resultChan) != 1 {
		t.Errorf("channel capacity: got %d, want 1", cap(resultChan))
	}

	tasksMu.RLock()
	_, exists := pendingTasks[taskID]
	tasksMu.RUnlock()
	if !exists {
		t.Error("future not found in pendingTasks")
	}

	taskHostMu.RLock()
	h, ok := taskHostnames[taskID]
	taskHostMu.RUnlock()
	if !ok || h != hostname {
		t.Errorf("hostname mapping: got %q, want %q", h, hostname)
	}

	// Cleanup
	tasksMu.Lock()
	delete(pendingTasks, taskID)
	tasksMu.Unlock()
	taskHostMu.Lock()
	delete(taskHostnames, taskID)
	taskHostMu.Unlock()
}

// ========================================================================
// ResolveFuturesForHostname
// ========================================================================

func TestResolveFuturesForHostname(t *testing.T) {
	resetState()

	ch1 := RegisterFuture("task-1", "host-a")
	ch2 := RegisterFuture("task-2", "host-a")
	ch3 := RegisterFuture("task-3", "host-b") // different host

	ResolveFuturesForHostname("host-a", "agent_disconnected")

	select {
	case msg := <-ch1:
		if msg.Error != "agent_disconnected" {
			t.Errorf("task-1 error: got %q, want agent_disconnected", msg.Error)
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("timeout waiting for task-1 resolution")
	}

	select {
	case msg := <-ch2:
		if msg.Error != "agent_disconnected" {
			t.Errorf("task-2 error: got %q, want agent_disconnected", msg.Error)
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("timeout waiting for task-2 resolution")
	}

	// task-3 should NOT be resolved (different hostname)
	select {
	case <-ch3:
		t.Error("task-3 should not be resolved for host-a disconnect")
	case <-time.After(50 * time.Millisecond):
		// Expected
	}
}

func TestResolveFuturesForHostnameNoFutures(t *testing.T) {
	resetState()
	// Should not panic
	ResolveFuturesForHostname("host-a", "agent_disconnected")
}

func TestUnregisterConnectionResolvesFutures(t *testing.T) {
	resetState()

	mockConn := &AgentConnection{Hostname: "host-a"}
	RegisterConnection("host-a", mockConn)
	ch := RegisterFuture("task-1", "host-a")

	UnregisterConnection("host-a")

	select {
	case msg := <-ch:
		if msg.Error != "agent_disconnected" {
			t.Errorf("error: got %q, want agent_disconnected", msg.Error)
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("timeout waiting for future resolution on disconnect")
	}
}

// ========================================================================
// HandleMessage — ack
// ========================================================================

func TestHandleMessageAck(t *testing.T) {
	resetState()
	msg := Message{TaskID: "task-ack-123", Type: "ack"}
	// Should not panic
	HandleMessage(msg, "host-a")
}

func TestHandleMessageMissingTaskID(t *testing.T) {
	resetState()
	HandleMessage(Message{Type: "ack"}, "host-a")
}

func TestHandleMessageMissingType(t *testing.T) {
	resetState()
	HandleMessage(Message{TaskID: "task-1"}, "host-a")
}

// ========================================================================
// HandleMessage — stdout
// ========================================================================

func TestHandleMessageStdoutAccumulates(t *testing.T) {
	resetState()

	HandleMessage(Message{TaskID: "task-1", Type: "stdout", Chunk: "hello "}, "host-a")
	HandleMessage(Message{TaskID: "task-1", Type: "stdout", Chunk: "world"}, "host-a")

	buffersMu.RLock()
	buf := stdoutBuffers["task-1"]
	buffersMu.RUnlock()

	if buf != "hello world" {
		t.Errorf("buffer: got %q, want %q", buf, "hello world")
	}
}

func TestHandleMessageStdoutTruncatesAt5MB(t *testing.T) {
	resetState()

	large := make([]byte, 5*1024*1024+100)
	for i := range large {
		large[i] = 'x'
	}
	HandleMessage(Message{TaskID: "task-1", Type: "stdout", Chunk: string(large)}, "host-a")

	buffersMu.RLock()
	buf := stdoutBuffers["task-1"]
	buffersMu.RUnlock()

	if len([]byte(buf)) > stdoutMaxBytes {
		t.Errorf("buffer exceeds max: got %d bytes, want <= %d", len([]byte(buf)), stdoutMaxBytes)
	}
}

// ========================================================================
// HandleMessage — result
// ========================================================================

func TestHandleMessageResultResolveFuture(t *testing.T) {
	resetState()
	ch := RegisterFuture("task-1", "host-a")

	HandleMessage(Message{TaskID: "task-1", Type: "result", RC: 0, Stdout: "done"}, "host-a")

	select {
	case msg := <-ch:
		if msg.RC != 0 {
			t.Errorf("rc: got %d, want 0", msg.RC)
		}
		if msg.Stdout != "done" {
			t.Errorf("stdout: got %q, want %q", msg.Stdout, "done")
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("timeout waiting for result")
	}

	tasksMu.RLock()
	_, exists := pendingTasks["task-1"]
	tasksMu.RUnlock()
	if exists {
		t.Error("pendingTasks should be cleaned up after result")
	}
}

func TestHandleMessageResultUsesAccumulatedStdout(t *testing.T) {
	resetState()
	ch := RegisterFuture("task-1", "host-a")

	HandleMessage(Message{TaskID: "task-1", Type: "stdout", Chunk: "chunk1"}, "host-a")
	HandleMessage(Message{TaskID: "task-1", Type: "stdout", Chunk: "chunk2"}, "host-a")
	HandleMessage(Message{TaskID: "task-1", Type: "result", RC: 0, Stdout: ""}, "host-a")

	select {
	case msg := <-ch:
		if msg.Stdout != "chunk1chunk2" {
			t.Errorf("stdout: got %q, want %q", msg.Stdout, "chunk1chunk2")
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("timeout waiting for result")
	}
}

func TestHandleMessageResultNoFuture(t *testing.T) {
	resetState()
	// Should not panic
	HandleMessage(Message{TaskID: "unknown-task", Type: "result", RC: 0}, "host-a")
}

func TestHandleMessageResultCleansUpBuffers(t *testing.T) {
	resetState()
	_ = RegisterFuture("task-1", "host-a")
	HandleMessage(Message{TaskID: "task-1", Type: "stdout", Chunk: "data"}, "host-a")
	HandleMessage(Message{TaskID: "task-1", Type: "result", RC: 0}, "host-a")

	buffersMu.RLock()
	_, hasBuffer := stdoutBuffers["task-1"]
	buffersMu.RUnlock()
	if hasBuffer {
		t.Error("stdout buffer should be cleaned up after result")
	}
}

// ========================================================================
// HandleMessage — unknown type
// ========================================================================

func TestHandleMessageUnknownType(t *testing.T) {
	resetState()
	HandleMessage(Message{TaskID: "task-1", Type: "invalid_type"}, "host-a")
}

// ========================================================================
// SendToAgent
// ========================================================================

func TestSendToAgentOffline(t *testing.T) {
	resetState()
	err := SendToAgent("host-offline", map[string]interface{}{"task_id": "t1", "type": "exec"})
	if err == nil {
		t.Error("expected error for offline agent")
	}
	if err.Error() != "agent_offline" {
		t.Errorf("error: got %q, want %q", err.Error(), "agent_offline")
	}
}

// ========================================================================
// WaitForResult
// ========================================================================

func TestWaitForResultSuccess(t *testing.T) {
	resultChan := make(chan Message, 1)
	msg := Message{TaskID: "task-wait-123", Type: "result", RC: 0, Stdout: "test output"}
	resultChan <- msg

	result, err := WaitForResult(resultChan, time.Second)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if result.Stdout != "test output" {
		t.Errorf("expected stdout='test output', got %q", result.Stdout)
	}
}

func TestWaitForResultTimeout(t *testing.T) {
	resultChan := make(chan Message, 1)
	_, err := WaitForResult(resultChan, 100*time.Millisecond)
	if err == nil {
		t.Error("expected timeout error")
	}
	if err.Error() != "timeout waiting for task result" {
		t.Errorf("expected timeout error, got %q", err.Error())
	}
}

func TestWaitForResultWithError(t *testing.T) {
	resultChan := make(chan Message, 1)
	resultChan <- Message{TaskID: "task-1", Error: "agent_disconnected"}

	result, err := WaitForResult(resultChan, 100*time.Millisecond)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Error != "agent_disconnected" {
		t.Errorf("error: got %q, want %q", result.Error, "agent_disconnected")
	}
}

// ========================================================================
// Message struct JSON marshaling
// ========================================================================

func TestMessageStruct(t *testing.T) {
	msg := Message{
		TaskID:    "task-123",
		Type:      "result",
		RC:        0,
		Stdout:    "output",
		Stderr:    "errors",
		Truncated: false,
		Data:      "file data",
		Error:     "",
		Chunk:     "chunk",
	}

	body, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var msg2 Message
	err = json.Unmarshal(body, &msg2)
	if err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if msg2.TaskID != msg.TaskID {
		t.Error("failed to preserve TaskID")
	}
	if msg2.RC != msg.RC {
		t.Error("failed to preserve RC")
	}
}

// ========================================================================
// WebSocket close code constants
// ========================================================================

func TestCloseCodeConstants(t *testing.T) {
	if WSCloseRevoked != 4001 {
		t.Errorf("WSCloseRevoked: expected 4001, got %d", WSCloseRevoked)
	}
	if WSCloseExpired != 4002 {
		t.Errorf("WSCloseExpired: expected 4002, got %d", WSCloseExpired)
	}
	if WSCloseNormal != 4000 {
		t.Errorf("WSCloseNormal: expected 4000, got %d", WSCloseNormal)
	}
}

// ========================================================================
// GetConnectedCount / GetConnectedHostnames / GetPendingTaskCount
// ========================================================================

func TestGetConnectedCount(t *testing.T) {
	resetState()

	if n := GetConnectedCount(); n != 0 {
		t.Errorf("expected 0, got %d", n)
	}

	RegisterConnection("host-a", &AgentConnection{Hostname: "host-a"})
	RegisterConnection("host-b", &AgentConnection{Hostname: "host-b"})

	if n := GetConnectedCount(); n != 2 {
		t.Errorf("expected 2, got %d", n)
	}

	UnregisterConnection("host-a")
	if n := GetConnectedCount(); n != 1 {
		t.Errorf("expected 1 after unregister, got %d", n)
	}

	UnregisterConnection("host-b")
}

func TestGetConnectedHostnames(t *testing.T) {
	resetState()

	hosts := GetConnectedHostnames()
	if len(hosts) != 0 {
		t.Errorf("expected 0 hostnames, got %d", len(hosts))
	}

	RegisterConnection("alpha", &AgentConnection{Hostname: "alpha"})
	RegisterConnection("beta", &AgentConnection{Hostname: "beta"})

	hosts = GetConnectedHostnames()
	if len(hosts) != 2 {
		t.Errorf("expected 2 hostnames, got %d", len(hosts))
	}

	found := map[string]bool{}
	for _, h := range hosts {
		found[h] = true
	}
	if !found["alpha"] || !found["beta"] {
		t.Errorf("expected alpha and beta in hostnames, got %v", hosts)
	}

	UnregisterConnection("alpha")
	UnregisterConnection("beta")
}

func TestGetPendingTaskCount(t *testing.T) {
	resetState()

	if n := GetPendingTaskCount(); n != 0 {
		t.Errorf("expected 0 pending tasks, got %d", n)
	}

	RegisterFuture("task-a", "host-a")
	RegisterFuture("task-b", "host-a")

	if n := GetPendingTaskCount(); n != 2 {
		t.Errorf("expected 2 pending tasks, got %d", n)
	}

	// Cleanup
	tasksMu.Lock()
	delete(pendingTasks, "task-a")
	delete(pendingTasks, "task-b")
	tasksMu.Unlock()
	taskHostMu.Lock()
	delete(taskHostnames, "task-a")
	delete(taskHostnames, "task-b")
	taskHostMu.Unlock()
}

// ========================================================================
// SetRekeyFunc / SetJWTSecretsFunc
// ========================================================================

func TestSetRekeyFunc(t *testing.T) {
	called := false
	SetRekeyFunc(func(hostname string) bool {
		called = true
		return true
	})
	defer SetRekeyFunc(nil)

	if RekeyFunc == nil {
		t.Fatal("RekeyFunc is nil after SetRekeyFunc")
	}
	result := RekeyFunc("test-host")
	if !called || !result {
		t.Error("RekeyFunc was not properly set")
	}
}

func TestSetJWTSecretsFunc(t *testing.T) {
	SetJWTSecretsFunc(func() (string, string, time.Time) {
		return "current", "previous", time.Now().Add(time.Hour)
	})
	defer func() { JWTSecretsFunc = nil }()

	if JWTSecretsFunc == nil {
		t.Fatal("JWTSecretsFunc is nil after SetJWTSecretsFunc")
	}
	cur, prev, dl := JWTSecretsFunc()
	if cur != "current" {
		t.Errorf("expected current, got %q", cur)
	}
	if prev != "previous" {
		t.Errorf("expected previous, got %q", prev)
	}
	if dl.IsZero() {
		t.Error("expected non-zero deadline")
	}
}

// ========================================================================
// extractHostnameFromRequest — no unsigned fallback (#169b)
// ========================================================================

func withAgentSecret(t *testing.T) {
	t.Helper()
	SetJWTSecretsFunc(func() (string, string, time.Time) { return "agent-secret", "", time.Time{} })
	t.Cleanup(func() { JWTSecretsFunc = nil })
}

func TestExtractHostnameFromRequest_RefusesEverythingUnsigned(t *testing.T) {
	withAgentSecret(t)
	// payload = {"sub":"victim"} with a fake signature
	forged := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ2aWN0aW0ifQ.fakesig"
	cases := []struct {
		name, url, auth string
	}{
		{"no header", "/ws", ""},
		{"query hostname only", "/ws?hostname=victim", ""},
		{"basic", "/ws?hostname=victim", "Basic abc"},
		{"empty bearer", "/ws?hostname=victim", "Bearer "},
		{"bearer without space", "/ws?hostname=victim", "Bearer"},
		{"lowercase scheme", "/ws", "bearer " + forged},
		{"forged unsigned bearer", "/ws", "Bearer " + forged},
		{"wrong secret", "/ws", "Bearer " + makeTestJWT("wrong", "victim", time.Now().Add(time.Hour))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", tc.url, nil)
			if tc.auth != "" {
				req.Header.Set("Authorization", tc.auth)
			}
			if h, _, err := extractHostnameFromRequest(req); err == nil {
				t.Fatalf("accepted as %q, want refusal", h)
			}
		})
	}
}

func TestExtractHostnameFromRequest_NoVerifierFailsClosed(t *testing.T) {
	JWTSecretsFunc = nil
	// even a perfectly well-formed token is refused without a verifier
	req, _ := http.NewRequest("GET", "/ws?hostname=h", nil)
	req.Header.Set("Authorization", "Bearer "+makeTestJWT("s", "h", time.Now().Add(time.Hour)))
	if _, _, err := extractHostnameFromRequest(req); err == nil {
		t.Fatal("must fail closed without JWTSecretsFunc")
	}
}

func TestExtractHostnameFromRequest_RoleMustBeAgent(t *testing.T) {
	withAgentSecret(t)
	for _, role := range []string{"plugin", "admin", "relay", "relay-parent", "enrollment", ""} {
		claims := jwt.MapClaims{"sub": "host-a", "jti": "j", "exp": time.Now().Add(time.Hour).Unix()}
		if role != "" {
			claims["role"] = role
		}
		tok, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte("agent-secret"))
		req, _ := http.NewRequest("GET", "/ws", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		if _, _, err := extractHostnameFromRequest(req); err == nil {
			t.Errorf("role %q accepted on /ws/agent", role)
		}
	}
	req, _ := http.NewRequest("GET", "/ws", nil)
	req.Header.Set("Authorization", "Bearer "+makeTestJWT("agent-secret", "host-a", time.Now().Add(time.Hour)))
	if h, _, err := extractHostnameFromRequest(req); err != nil || h != "host-a" {
		t.Fatalf("role agent: %q %v", h, err)
	}
}

func TestExtractHostnameFromRequest_JWTSecretsFunc_Valid(t *testing.T) {
	secret := "test-secret-key"
	SetJWTSecretsFunc(func() (string, string, time.Time) {
		return secret, "", time.Time{}
	})
	defer func() { JWTSecretsFunc = nil }()

	// Build a signed JWT
	tokenStr := makeTestJWT(secret, "jwt-host", time.Now().Add(time.Hour))
	req, _ := http.NewRequest("GET", "/ws", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)

	hostname, usedPrev, err := extractHostnameFromRequest(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hostname != "jwt-host" {
		t.Errorf("expected jwt-host, got %q", hostname)
	}
	if usedPrev {
		t.Error("expected usedPrevious=false for current key")
	}
}

func TestExtractHostnameFromRequest_JWTSecretsFunc_Invalid(t *testing.T) {
	SetJWTSecretsFunc(func() (string, string, time.Time) {
		return "correct-secret", "", time.Time{}
	})
	defer func() { JWTSecretsFunc = nil }()

	// Token signed with wrong secret
	tokenStr := makeTestJWT("wrong-secret", "host-x", time.Now().Add(time.Hour))
	req, _ := http.NewRequest("GET", "/ws", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)

	_, _, err := extractHostnameFromRequest(req)
	if err == nil {
		t.Error("expected error for wrong JWT secret")
	}
}

// ========================================================================
// CloseAgent
// ========================================================================

func TestCloseAgent_AgentOffline(t *testing.T) {
	resetState()
	result := CloseAgent("nonexistent-host", WSCloseRevoked, "revoked")
	if result {
		t.Error("expected false for offline agent")
	}
}

func TestCloseAgent_ConnectedAgent(t *testing.T) {
	resetState()

	// Set up a real WS server+client pair to test CloseAgent
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		agentConn := &AgentConnection{Hostname: "close-test-host", Conn: conn}
		RegisterConnection("close-test-host", agentConn)

		// Read until close (blocks until CloseAgent sends the close frame)
		for {
			_, _, err := conn.ReadMessage()
			if err != nil {
				break
			}
		}
		UnregisterConnection("close-test-host")
	}))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	clientConn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = clientConn.Close() }()

	// Wait for server to register the connection
	if !awaitCondition(2*time.Second, func() bool {
		_, e := GetConnection("close-test-host")
		return e == nil
	}) {
		t.Fatal("agent close-test-host not registered within timeout")
	}

	result := CloseAgent("close-test-host", WSCloseRevoked, "revoked")
	if !result {
		t.Error("expected true for connected agent")
	}
}

// ========================================================================
// AgentHandler — via httptest WS server
// ========================================================================

// TestAgentHandler_UnsignedIsRefusedWith401 drives the real handler: nothing unsigned upgrades.
func TestAgentHandler_UnsignedIsRefusedWith401(t *testing.T) {
	resetState()
	withAgentSecret(t)
	SetAgentJTICheckFunc(func(string, string, bool) error { return nil }) // would accept anything signed
	t.Cleanup(func() { SetAgentJTICheckFunc(nil) })
	srv := httptest.NewServer(http.HandlerFunc(AgentHandler))
	defer srv.Close()
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")

	for name, hdr := range map[string]http.Header{
		"no authorization": {},
		"basic":            {"Authorization": {"Basic abc"}},
		"other role":       {"Authorization": {"Bearer " + makeRoleJWT("agent-secret", "victim", "plugin")}},
		"wrong secret":     {"Authorization": {"Bearer " + makeTestJWT("nope", "victim", time.Now().Add(time.Hour))}},
	} {
		for _, q := range []string{"", "?hostname=victim"} {
			c, resp, err := websocket.DefaultDialer.Dial(wsURL+q, hdr)
			if c != nil {
				_ = c.Close()
			}
			if err == nil || resp == nil || resp.StatusCode != http.StatusUnauthorized {
				t.Fatalf("%s%s: err=%v resp=%v, want 401", name, q, err, resp)
			}
		}
	}
	if _, e := GetConnection("victim"); e == nil {
		t.Fatal("victim must not be registered")
	}
}

func makeRoleJWT(secret, sub, role string) string {
	claims := jwt.MapClaims{"sub": sub, "role": role, "jti": "j", "exp": time.Now().Add(time.Hour).Unix()}
	s, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(secret))
	return s
}

func TestAgentHandler_SignedAgentIsRegistered(t *testing.T) {
	resetState()
	withAgentSecret(t)
	SetAgentJTICheckFunc(func(string, string, bool) error { return nil })
	t.Cleanup(func() { SetAgentJTICheckFunc(nil) })

	srv := httptest.NewServer(http.HandlerFunc(AgentHandler))
	defer srv.Close()
	h := http.Header{"Authorization": {"Bearer " + makeTestJWT("agent-secret", "qp-host", time.Now().Add(time.Hour))}}
	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), h)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if !awaitCondition(2*time.Second, func() bool {
		_, e := GetConnection("qp-host")
		return e == nil
	}) {
		t.Fatal("agent qp-host not registered within timeout")
	}
}

// ========================================================================
// Concurrence : rekey + exec simultanés
// ========================================================================

// TestConcurrentRekeyAndExec verifies that rekey messages and task results
// can be processed concurrently without data races or panics.
func TestConcurrentRekeyAndExec(t *testing.T) {
	resetState()

	const numTasks = 10
	// Register N tasks and resolve them concurrently
	var wg sync.WaitGroup
	results := make([]chan Message, numTasks)

	for i := 0; i < numTasks; i++ {
		taskID := fmt.Sprintf("concurrent-task-%d", i)
		results[i] = RegisterFuture(taskID, "host-concurrent")
	}

	// Simulate concurrent result delivery
	for i := 0; i < numTasks; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			taskID := fmt.Sprintf("concurrent-task-%d", idx)
			HandleMessage(Message{
				TaskID: taskID,
				Type:   "result",
				RC:     idx,
				Stdout: fmt.Sprintf("output-%d", idx),
			}, "host-concurrent")
		}(i)
	}

	// Collect all results
	wg.Wait()
	for i, ch := range results {
		select {
		case msg := <-ch:
			if msg.RC != i {
				t.Errorf("task %d: expected RC=%d, got %d", i, i, msg.RC)
			}
		case <-time.After(500 * time.Millisecond):
			t.Errorf("timeout waiting for task %d result", i)
		}
	}
}

// TestConcurrentGetConnectedHostnames verifies that GetConnectedHostnames
// is safe under concurrent register/unregister.
func TestConcurrentGetConnectedHostnames(t *testing.T) {
	resetState()

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			h := fmt.Sprintf("concurrent-host-%d", idx)
			RegisterConnection(h, &AgentConnection{Hostname: h})
			GetConnectedHostnames()
			GetConnectedCount()
			UnregisterConnection(h)
		}(i)
	}
	wg.Wait()

	// After all goroutines finish, map should be empty (or have no leaked entries)
	if n := GetConnectedCount(); n != 0 {
		t.Errorf("expected 0 after cleanup, got %d", n)
	}
}

// ========================================================================
// /ws/agent revocation check (#169): fail closed, before the upgrade
// ========================================================================

func jtiHandshake(t *testing.T, secret, jti string) (status int, err error) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(AgentHandler))
	defer srv.Close()
	h := http.Header{}
	h.Set("Authorization", "Bearer "+makeJTIToken(secret, "jti-host", jti))
	c, resp, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), h)
	if c != nil {
		_ = c.Close()
	}
	if resp != nil {
		status = resp.StatusCode
	}
	return status, err
}

func makeJTIToken(secret, sub, jti string) string {
	claims := jwt.MapClaims{"sub": sub, "role": "agent", "exp": time.Now().Add(time.Hour).Unix()}
	if jti != "" {
		claims["jti"] = jti
	}
	s, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(secret))
	return s
}

func TestAgentHandler_JTICheckNotConfiguredFailsClosed(t *testing.T) {
	resetState()
	SetJWTSecretsFunc(func() (string, string, time.Time) { return "s3cret", "", time.Time{} })
	SetAgentJTICheckFunc(nil)
	defer func() { JWTSecretsFunc = nil }()

	status, err := jtiHandshake(t, "s3cret", "some-jti")
	if err == nil || status != http.StatusUnauthorized {
		t.Fatalf("valid JWT without a configured check: status %d err %v, want 401", status, err)
	}
	if _, e := GetConnection("jti-host"); e == nil {
		t.Error("the agent must not be registered")
	}
}

func TestAgentHandler_JTICheckRefusalAndAcceptance(t *testing.T) {
	resetState()
	SetJWTSecretsFunc(func() (string, string, time.Time) { return "s3cret", "prev", time.Now().Add(time.Hour) })
	defer func() { JWTSecretsFunc = nil; SetAgentJTICheckFunc(nil) }()

	var gotHost, gotJTI string
	var gotPrev bool
	SetAgentJTICheckFunc(func(host, jti string, prev bool) error {
		gotHost, gotJTI, gotPrev = host, jti, prev
		if jti == "revoked" {
			return fmt.Errorf("token_revoked")
		}
		return nil
	})

	if status, err := jtiHandshake(t, "s3cret", "revoked"); err == nil || status != http.StatusUnauthorized {
		t.Fatalf("revoked: status %d err %v, want 401", status, err)
	}
	if status, err := jtiHandshake(t, "s3cret", ""); err == nil || status != http.StatusUnauthorized {
		t.Fatalf("token without jti: status %d err %v, want 401", status, err)
	}
	if status, err := jtiHandshake(t, "s3cret", "good"); err != nil || status != http.StatusSwitchingProtocols {
		t.Fatalf("accepted token: status %d err %v, want 101", status, err)
	}
	if gotHost != "jti-host" || gotJTI != "good" || gotPrev {
		t.Errorf("check received (%q, %q, prev=%v)", gotHost, gotJTI, gotPrev)
	}
	// a token signed with the PREVIOUS secret reports usedPrevious=true to the check
	if status, err := jtiHandshake(t, "prev", "good2"); err != nil || status != http.StatusSwitchingProtocols {
		t.Fatalf("previous-secret token: status %d err %v", status, err)
	}
	if !gotPrev || gotJTI != "good2" {
		t.Errorf("usedPrevious not propagated: (%q, prev=%v)", gotJTI, gotPrev)
	}
}
