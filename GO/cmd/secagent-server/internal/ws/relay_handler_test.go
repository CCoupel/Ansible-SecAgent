package ws

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/websocket"
)

// ── Test helpers ─────────────────────────────────────────────────────────────

const relayTestSecret = "relay-test-jwt-secret"

// makeRelayJWT creates a signed JWT with the given relay_id and role.
func makeRelayJWT(relayID, role string) string {
	claims := jwt.MapClaims{
		"sub":  relayID,
		"role": role,
		"jti":  "test-jti-" + relayID,
		"iat":  time.Now().Unix(),
		"exp":  time.Now().Add(time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	raw, _ := token.SignedString([]byte(relayTestSecret))
	return raw
}

// routingHook is the per-test replacement for RelayRoutingBulkUpsertFunc.
// RelayRoutingBulkUpsertFunc itself is assigned exactly once (TestMain), before
// any server goroutine exists, to routingDispatch. Tests only swap routingHook
// under routingHookMu, so a handler goroutine left over from a previous test
// (hijacked WebSocket, not awaited by httptest.Server.Close) can never race
// with the test setup.
var (
	routingHookMu sync.RWMutex
	routingHook   func(relayID string, hostnames []string) error
)

func routingDispatch(relayID string, hostnames []string) error {
	routingHookMu.RLock()
	fn := routingHook
	routingHookMu.RUnlock()
	if fn == nil {
		return nil
	}
	return fn(relayID, hostnames)
}

// defaultNoBlacklist is the TestMain-installed blacklist check: nothing is revoked.
func defaultNoBlacklist(string) (bool, error) { return false, nil }

func TestMain(m *testing.M) {
	RelayRoutingBulkUpsertFunc = routingDispatch
	// /ws/relay fails closed without a JTI blacklist check: install the permissive default once.
	SetRelayJTIBlacklistFunc(defaultNoBlacklist)
	os.Exit(m.Run())
}

// setRoutingHook installs fn as the routing hook for the current test and
// restores the previous hook on cleanup.
func setRoutingHook(t *testing.T, fn func(relayID string, hostnames []string) error) {
	t.Helper()
	routingHookMu.Lock()
	prev := routingHook
	routingHook = fn
	routingHookMu.Unlock()
	t.Cleanup(func() {
		routingHookMu.Lock()
		routingHook = prev
		routingHookMu.Unlock()
	})
}

// awaitCondition polls fn until it returns true or timeout expires.
// It is used wherever the test must observe an asynchronous server-side state
// change without a fixed sleep.
func awaitCondition(timeout time.Duration, fn func() bool) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if fn() {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return fn()
}

// awaitRelayConnected polls IsRelayConnected until the relay is registered or the
// timeout expires. It is used after dialRelay to avoid a race: the WebSocket
// upgrade completes on the client side (dialRelay returns) before the server
// goroutine has called registerRelayConnection. Without this wait the check is
// racy and can fail under CI scheduling pressure even though the code is correct.
func awaitRelayConnected(t *testing.T, relayID string, timeout time.Duration) bool {
	t.Helper()
	return awaitCondition(timeout, func() bool { return IsRelayConnected(relayID) })
}

// setupRelayTestServer starts a test HTTP server with RelayHandler and configures JWT.
func setupRelayTestServer(t *testing.T) *httptest.Server {
	t.Helper()

	// Configure JWT validation
	origFn := JWTSecretsFunc
	JWTSecretsFunc = func() (string, string, time.Time) {
		return relayTestSecret, "", time.Time{}
	}
	t.Cleanup(func() {
		JWTSecretsFunc = origFn
		resetRelayState()
	})

	return httptest.NewServer(http.HandlerFunc(RelayHandler))
}

// dialRelay opens a WebSocket connection to the test server using the given JWT.
func dialRelay(t *testing.T, srv *httptest.Server, jwtToken string) *websocket.Conn {
	t.Helper()
	url := "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws/relay"
	header := http.Header{}
	if jwtToken != "" {
		header.Set("Authorization", "Bearer "+jwtToken)
	}
	conn, resp, err := websocket.DefaultDialer.Dial(url, header)
	if err != nil {
		if resp != nil {
			t.Fatalf("dial failed (HTTP %d): %v", resp.StatusCode, err)
		}
		t.Fatalf("dial failed: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// dialRelayExpectFail opens a WS connection expecting an HTTP error (not 101).
func dialRelayExpectFail(t *testing.T, srv *httptest.Server, jwtToken string) int {
	t.Helper()
	url := "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws/relay"
	header := http.Header{}
	if jwtToken != "" {
		header.Set("Authorization", "Bearer "+jwtToken)
	}
	_, resp, err := websocket.DefaultDialer.Dial(url, header)
	if err == nil {
		t.Fatal("expected connection to fail, but it succeeded")
	}
	if resp == nil {
		t.Fatalf("expected HTTP error response, got nil (err=%v)", err)
	}
	return resp.StatusCode
}

// ── Auth tests ─────────────────────────────────────────────────────────────

func TestRelayHandler_RejectNoToken(t *testing.T) {
	srv := setupRelayTestServer(t)
	defer srv.Close()

	code := dialRelayExpectFail(t, srv, "")
	if code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", code)
	}
}

func TestRelayHandler_RejectAgentRole(t *testing.T) {
	srv := setupRelayTestServer(t)
	defer srv.Close()

	// A JWT with role=agent should be rejected for /ws/relay
	agentJWT := makeRelayJWT("host-1", "agent")
	code := dialRelayExpectFail(t, srv, agentJWT)
	if code != http.StatusUnauthorized {
		t.Errorf("expected 401 for agent role, got %d", code)
	}
}

func TestRelayHandler_RejectAdminRole(t *testing.T) {
	srv := setupRelayTestServer(t)
	defer srv.Close()

	adminJWT := makeRelayJWT("admin", "admin")
	code := dialRelayExpectFail(t, srv, adminJWT)
	if code != http.StatusUnauthorized {
		t.Errorf("expected 401 for admin role, got %d", code)
	}
}

func TestRelayHandler_RejectWrongSecret(t *testing.T) {
	srv := setupRelayTestServer(t)
	defer srv.Close()

	// Token signed with a different secret
	claims := jwt.MapClaims{
		"sub":  "dmz1",
		"role": "relay",
		"jti":  "test-jti",
		"iat":  time.Now().Unix(),
		"exp":  time.Now().Add(time.Hour).Unix(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	raw, _ := tok.SignedString([]byte("wrong-secret"))

	code := dialRelayExpectFail(t, srv, raw)
	if code != http.StatusUnauthorized {
		t.Errorf("expected 401 for wrong secret, got %d", code)
	}
}

func TestRelayHandler_AcceptRelayRole(t *testing.T) {
	srv := setupRelayTestServer(t)
	defer srv.Close()

	relayJWT := makeRelayJWT("dmz1", "relay")
	conn := dialRelay(t, srv, relayJWT)
	if conn == nil {
		t.Fatal("expected successful connection")
	}
	if !awaitRelayConnected(t, "dmz1", 2*time.Second) {
		t.Error("expected relay to be registered after connect")
	}
}

// ── relay_hello / relay_ack ───────────────────────────────────────────────────

func TestRelayHandler_HelloAck(t *testing.T) {
	srv := setupRelayTestServer(t)
	defer srv.Close()

	conn := dialRelay(t, srv, makeRelayJWT("dmz-hello", "relay"))

	// Send relay_hello
	hello := RelayMessage{Type: "relay_hello", RelayID: "dmz-hello", Version: "1.0"}
	if err := conn.WriteJSON(hello); err != nil {
		t.Fatalf("WriteJSON hello: %v", err)
	}

	// Expect relay_ack
	var ack RelayMessage
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	if err := conn.ReadJSON(&ack); err != nil {
		t.Fatalf("ReadJSON ack: %v", err)
	}
	if ack.Type != "relay_ack" {
		t.Errorf("expected type=relay_ack, got %q", ack.Type)
	}
	if ack.Status != "ok" {
		t.Errorf("expected status=ok, got %q", ack.Status)
	}
}

// ── agent_list / agent_list_ack ───────────────────────────────────────────────

func TestRelayHandler_AgentList(t *testing.T) {
	srv := setupRelayTestServer(t)
	defer srv.Close()

	// Inject routing update function
	var capturedRelayID string
	var capturedHostnames []string
	var routingMu sync.Mutex
	setRoutingHook(t, func(relayID string, hostnames []string) error {
		if relayID != "dmz-agents" || len(hostnames) == 0 {
			return nil // ignore stale calls from other tests / disconnect cleanup
		}
		routingMu.Lock()
		capturedRelayID = relayID
		capturedHostnames = append([]string{}, hostnames...)
		routingMu.Unlock()
		return nil
	})

	conn := dialRelay(t, srv, makeRelayJWT("dmz-agents", "relay"))

	msg := RelayMessage{
		Type: "agent_list",
		Agents: []RelayAgentInfo{
			{Hostname: "host-a", Status: "connected"},
			{Hostname: "host-b", Status: "connected"},
			{Hostname: "host-c", Status: "disconnected"},
		},
	}
	if err := conn.WriteJSON(msg); err != nil {
		t.Fatalf("WriteJSON agent_list: %v", err)
	}

	// Expect agent_list_ack
	var ack RelayMessage
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	if err := conn.ReadJSON(&ack); err != nil {
		t.Fatalf("ReadJSON ack: %v", err)
	}
	if ack.Type != "agent_list_ack" {
		t.Errorf("expected type=agent_list_ack, got %q", ack.Type)
	}
	if ack.Count != 3 {
		t.Errorf("expected count=3, got %d", ack.Count)
	}

	// Verify routing update was called
	if !awaitCondition(2*time.Second, func() bool {
		routingMu.Lock()
		defer routingMu.Unlock()
		return capturedRelayID != ""
	}) {
		t.Fatal("routing update not called after agent_list")
	}
	routingMu.Lock()
	defer routingMu.Unlock()
	if capturedRelayID != "dmz-agents" {
		t.Errorf("expected relay_id=dmz-agents in routing update, got %q", capturedRelayID)
	}
	if len(capturedHostnames) != 3 {
		t.Errorf("expected 3 hostnames in routing update, got %d", len(capturedHostnames))
	}
}

func TestRelayHandler_AgentList_EmptyList(t *testing.T) {
	srv := setupRelayTestServer(t)
	defer srv.Close()

	var callCount int
	var callMu sync.Mutex
	setRoutingHook(t, func(relayID string, hostnames []string) error {
		if relayID != "dmz-empty" {
			return nil
		}
		callMu.Lock()
		callCount++
		callMu.Unlock()
		return nil
	})

	conn := dialRelay(t, srv, makeRelayJWT("dmz-empty", "relay"))

	msg := RelayMessage{Type: "agent_list", Agents: []RelayAgentInfo{}}
	if err := conn.WriteJSON(msg); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}

	var ack RelayMessage
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	if err := conn.ReadJSON(&ack); err != nil {
		t.Fatalf("ReadJSON ack: %v", err)
	}

	if ack.Type != "agent_list_ack" {
		t.Errorf("expected agent_list_ack, got %q", ack.Type)
	}
}

// ── heartbeat / heartbeat_ack ─────────────────────────────────────────────────

func TestRelayHandler_Heartbeat(t *testing.T) {
	srv := setupRelayTestServer(t)
	defer srv.Close()

	conn := dialRelay(t, srv, makeRelayJWT("dmz-hb", "relay"))

	hb := RelayMessage{Type: "heartbeat", Timestamp: time.Now().UTC().Format(time.RFC3339)}
	if err := conn.WriteJSON(hb); err != nil {
		t.Fatalf("WriteJSON heartbeat: %v", err)
	}

	var ack RelayMessage
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	if err := conn.ReadJSON(&ack); err != nil {
		t.Fatalf("ReadJSON heartbeat_ack: %v", err)
	}
	if ack.Type != "heartbeat_ack" {
		t.Errorf("expected heartbeat_ack, got %q", ack.Type)
	}
	if ack.Timestamp == "" {
		t.Error("expected timestamp in heartbeat_ack")
	}
}

// ── task_result resolution ─────────────────────────────────────────────────────

func TestRelayHandler_TaskResult(t *testing.T) {
	srv := setupRelayTestServer(t)
	defer srv.Close()

	conn := dialRelay(t, srv, makeRelayJWT("dmz-task", "relay"))

	// Register a pending future for task-999
	ch := RegisterRelayTaskFuture("task-999")
	defer UnregisterRelayTaskFuture("task-999")

	// Simulate relay returning task result
	result := RelayMessage{
		Type:   "task_result",
		TaskID: "task-999",
		RC:     0,
		Stdout: "hello world",
		Stderr: "",
	}
	if err := conn.WriteJSON(result); err != nil {
		t.Fatalf("WriteJSON task_result: %v", err)
	}

	select {
	case got := <-ch:
		if got.TaskID != "task-999" {
			t.Errorf("expected task_id=task-999, got %q", got.TaskID)
		}
		if got.RC != 0 {
			t.Errorf("expected rc=0, got %d", got.RC)
		}
		if got.Stdout != "hello world" {
			t.Errorf("expected stdout=hello world, got %q", got.Stdout)
		}
	case <-time.After(2 * time.Second):
		t.Error("timeout waiting for task_result")
	}
}

// ── disconnect cleanup ─────────────────────────────────────────────────────────

func TestRelayHandler_DisconnectCleansRouting(t *testing.T) {
	srv := setupRelayTestServer(t)
	defer srv.Close()

	var cleanupCalled bool
	var cleanupMu sync.Mutex
	setRoutingHook(t, func(relayID string, hostnames []string) error {
		if relayID == "dmz-disco" && len(hostnames) == 0 {
			cleanupMu.Lock()
			cleanupCalled = true
			cleanupMu.Unlock()
		}
		return nil
	})

	conn := dialRelay(t, srv, makeRelayJWT("dmz-disco", "relay"))
	if !awaitRelayConnected(t, "dmz-disco", 2*time.Second) {
		t.Fatal("expected relay registered after connect")
	}

	// Close the client-side connection
	_ = conn.Close()

	// Wait for server-side deregistration (delete from map comes first in
	// unregisterRelayConnection, so IsRelayConnected becomes false before the
	// routing cleanup is called).
	if !awaitCondition(2*time.Second, func() bool { return !IsRelayConnected("dmz-disco") }) {
		t.Error("expected relay unregistered after disconnect")
	}

	// Wait for routing cleanup: RelayRoutingBulkUpsertFunc is called AFTER the
	// map delete, so cleanupCalled may be false when IsRelayConnected first
	// returns false — poll to avoid that race.
	if !awaitCondition(2*time.Second, func() bool {
		cleanupMu.Lock()
		defer cleanupMu.Unlock()
		return cleanupCalled
	}) {
		t.Error("expected routing cleanup called on disconnect")
	}
}

func TestRelayHandler_DisconnectResolvesPendingTasks(t *testing.T) {
	srv := setupRelayTestServer(t)
	defer srv.Close()

	conn := dialRelay(t, srv, makeRelayJWT("dmz-pending", "relay"))

	// Register a pending future
	ch := RegisterRelayTaskFuture("task-abandoned")

	// Close connection — should resolve future with error
	if err := conn.Close(); err != nil {
		t.Fatalf("conn.Close: %v", err)
	}

	select {
	case got := <-ch:
		if got.Error != "relay_disconnected" {
			t.Errorf("expected error=relay_disconnected, got %q", got.Error)
		}
	case <-time.After(2 * time.Second):
		t.Error("timeout waiting for abandoned task resolution")
	}
}

// ── GetConnectedRelayCount ────────────────────────────────────────────────────

func TestGetConnectedRelayCount(t *testing.T) {
	resetRelayState()
	if n := GetConnectedRelayCount(); n != 0 {
		t.Errorf("expected 0 connected relays, got %d", n)
	}
}

// ── JSON wire format ──────────────────────────────────────────────────────────

func TestRelayMessage_JSON_RoundTrip(t *testing.T) {
	orig := RelayMessage{
		Type:    "agent_list",
		RelayID: "dmz1",
		Agents: []RelayAgentInfo{
			{Hostname: "host-a", Status: "connected"},
		},
	}
	data, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded RelayMessage
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.Type != orig.Type {
		t.Errorf("type mismatch: %q vs %q", decoded.Type, orig.Type)
	}
	if len(decoded.Agents) != 1 || decoded.Agents[0].Hostname != "host-a" {
		t.Errorf("agents mismatch: %+v", decoded.Agents)
	}
}
