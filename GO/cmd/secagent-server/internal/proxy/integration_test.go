// integration_test.go — Phase 12 — Tests d'intégration topologie DMZ simulée
//
// Implements PLAN_PHASE12.md §12.10 — Issue #119
//
// Five scenarios covering the full proxy/relay topology (v3.0 — push mode removed #123):
//
//  1. TestProxyModeExecRouting      — pull mode: real WS relay goroutine, real ws.DispatchToRelay
//  2. TestProxyInventoryAggregation — two WS relays × 3 agents = 6 in aggregated inventory
//  3. TestProxyHostNotFound         — unknown hostname → ErrHostNotFound sentinel
//  4. TestProxyRelayDisconnect      — WS relay disconnect clears routing table
//  5. TestProxyChaining             — pull mode + is_proxy flag stored in DB, exec successful
//
// All tests run in-memory (no external infrastructure required):
//   - Pull-mode tests: httptest.Server + gorilla/websocket relay goroutines
//   - Storage: storage.NewStore(":memory:")
//
// Non-regression: additive tests only — no modifications to existing *_test.go files.
package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/websocket"

	"secagent-server/cmd/secagent-server/internal/storage"
	"secagent-server/cmd/secagent-server/internal/ws"
)

// ── Integration test helpers ──────────────────────────────────────────────────

// intRelayServer starts an httptest.Server serving ws.RelayHandler, wires the
// relay → storage integration functions, and registers cleanup.
//
// Must be called with a unique store per test to avoid cross-test DB pollution.
func intRelayServer(t *testing.T, store *storage.Store) *httptest.Server {
	t.Helper()

	setWSHooks(t, wsHooks{
		routing: store.BulkUpsertRelayRouting,
		status:  store.UpdateRelayStatus,
		isProxy: store.SetRelayIsProxy,
	})

	srv := httptest.NewServer(http.HandlerFunc(ws.RelayHandler))
	t.Cleanup(srv.Close)

	return srv
}

// intRelayJWT signs a relay JWT accepted by ws.JWTSecretsFunc (set once in TestMain).
func intRelayJWT(t *testing.T, relayID string) string {
	t.Helper()
	claims := jwt.MapClaims{
		"sub": relayID, "role": "relay", "jti": "int-jti-" + relayID,
		"iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(),
	}
	raw, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(intJWTSecret))
	if err != nil {
		t.Fatalf("sign relay JWT: %v", err)
	}
	return raw
}

// intDialRelay dials a /ws/relay connection authenticated with a signed relay JWT.
// isProxy=true sets the query param that makes the relay announce itself as a proxy.
func intDialRelay(t *testing.T, srv *httptest.Server, relayID string, isProxy bool) *websocket.Conn {
	t.Helper()
	u := "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws/relay"
	if isProxy {
		u += "?is_proxy=true"
	}
	hdr := http.Header{}
	hdr.Set("Authorization", "Bearer "+intRelayJWT(t, relayID))
	conn, resp, err := websocket.DefaultDialer.Dial(u, hdr)
	if err != nil {
		status := 0
		if resp != nil {
			status = resp.StatusCode
		}
		t.Fatalf("intDialRelay %s: HTTP %d: %v", relayID, status, err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// intSeedPullRelay inserts a pull-mode relay node (no URL, status=disconnected).
func intSeedPullRelay(t *testing.T, s *storage.Store, relayID string) {
	t.Helper()
	node := storage.RelayNode{
		ID:        "uuid-int-" + relayID,
		RelayID:   relayID,
		URL:       "",
		Mode:      "pull",
		Status:    "disconnected",
		CreatedAt: time.Now().Unix(),
	}
	if err := s.UpsertRelayNode(node); err != nil {
		t.Fatalf("intSeedPullRelay UpsertRelayNode %s: %v", relayID, err)
	}
}

// intWaitRelayConnected spins until relayID appears in the ws global relay map.
func intWaitRelayConnected(t *testing.T, relayID string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if ws.IsRelayConnected(relayID) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("relay %s not connected after %s", relayID, timeout)
}

// intWaitRelayDisconnected spins until relayID is removed from the ws global relay map.
func intWaitRelayDisconnected(t *testing.T, relayID string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if !ws.IsRelayConnected(relayID) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("relay %s still connected after %s", relayID, timeout)
}

// intSendAgentList sends an agent_list message and reads the agent_list_ack.
// Blocks until the ack is received (2 s deadline).
func intSendAgentList(t *testing.T, conn *websocket.Conn, hostnames []string) {
	t.Helper()
	agents := make([]ws.RelayAgentInfo, len(hostnames))
	for i, h := range hostnames {
		agents[i] = ws.RelayAgentInfo{Hostname: h, Status: "connected"}
	}
	msg := ws.RelayMessage{Type: "agent_list", Agents: agents}
	if err := conn.WriteJSON(msg); err != nil {
		t.Fatalf("intSendAgentList WriteJSON: %v", err)
	}
	var ack ws.RelayMessage
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("intSendAgentList SetReadDeadline: %v", err)
	}
	if err := conn.ReadJSON(&ack); err != nil {
		t.Fatalf("intSendAgentList ReadJSON ack: %v", err)
	}
	if ack.Type != "agent_list_ack" {
		t.Fatalf("expected agent_list_ack, got %q", ack.Type)
	}
}

// intRelayEchoWorker starts a goroutine that reads one task_dispatch from conn
// and responds with task_result rc=0, stdout=replyStdout.
// Returns a channel closed when the goroutine exits.
func intRelayEchoWorker(conn *websocket.Conn, replyStdout string) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
			return
		}
		var msg ws.RelayMessage
		if err := conn.ReadJSON(&msg); err != nil {
			return
		}
		if msg.Type != "task_dispatch" {
			return
		}
		result := ws.RelayMessage{
			Type:   "task_result",
			TaskID: msg.TaskID,
			RC:     0,
			Stdout: replyStdout,
		}
		if err := conn.WriteJSON(result); err != nil {
			return
		}
	}()
	return done
}

// intNewPullRouter builds a ProxyRouter that uses real ws package functions
// (not the injected mocks) — suitable for pull-mode integration tests.
func intNewPullRouter(s *storage.Store) *ProxyRouter {
	return &ProxyRouter{
		store:                 s,
		isRelayConnected:      ws.IsRelayConnected,
		dispatchToRelay:       ws.DispatchToRelay,
		unregisterRelayFuture: ws.UnregisterRelayTaskFuture,
	}
}

// ── Scenario 1: Pull mode exec routing ────────────────────────────────────────

// TestProxyModeExecRouting verifies the full pull-mode exec cycle:
// ProxyRouter dispatches a task to a downstream relay via the real
// ws.DispatchToRelay path, the relay responds with task_result, and the result
// is correctly returned to the caller.
//
// Topology: ProxyRouter → /ws/relay (relay goroutine) → task_result
func TestProxyModeExecRouting(t *testing.T) {
	const (
		relayID    = "int-pull-exec"
		hostname   = "int-host-exec"
		wantStdout = "integration-exec-ok"
	)

	s := newRouterTestStore(t)
	srv := intRelayServer(t, s)

	// Pre-register relay node in storage (needed for AggregateRelayInventory later)
	intSeedPullRelay(t, s, relayID)

	// Connect relay WS client
	relayConn := intDialRelay(t, srv, relayID, false)
	intWaitRelayConnected(t, relayID, 2*time.Second)

	// Relay announces host
	intSendAgentList(t, relayConn, []string{hostname})

	// Wait for relay_routing DB update (async after ack)
	awaitCond(t, 2*time.Second, "routing populated for "+hostname, func() bool {
		rid, err := s.GetRelayForHostname(hostname)
		return err == nil && rid == relayID
	})

	// Verify routing table was populated
	rid, err := s.GetRelayForHostname(hostname)
	if err != nil || rid != relayID {
		t.Fatalf("routing not populated: rid=%q err=%v", rid, err)
	}

	// Start relay echo worker AFTER reading the agent_list_ack
	// (the next message it reads will be the task_dispatch from RouteExec)
	done := intRelayEchoWorker(relayConn, wantStdout)

	// Route exec via ProxyRouter using real ws.DispatchToRelay
	router := intNewPullRouter(s)
	resp, routeErr := router.RouteExec(
		context.Background(),
		hostname,
		"int-task-exec-1",
		ExecRequest{Cmd: "echo integration", Timeout: 5},
	)

	// Wait for relay goroutine to finish
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Error("relay echo goroutine did not finish in time")
	}

	if routeErr != nil {
		t.Fatalf("RouteExec pull mode: %v", routeErr)
	}
	if resp.RC != 0 {
		t.Errorf("expected RC=0, got %d", resp.RC)
	}
	if resp.Stdout != wantStdout {
		t.Errorf("expected stdout=%q, got %q", wantStdout, resp.Stdout)
	}
}

// ── Scenario 2: Inventory aggregation — two relays ────────────────────────────

// TestProxyInventoryAggregation verifies that a ProxyRouter aggregates agents
// from two simultaneously connected pull-mode relays (3 agents each = 6 total).
//
// Topology: ProxyRouter ← relay-inv-1 (3 agents) + relay-inv-2 (3 agents)
func TestProxyInventoryAggregation(t *testing.T) {
	const (
		relay1 = "int-inv-relay-1"
		relay2 = "int-inv-relay-2"
	)

	hosts1 := []string{"int-inv-h1", "int-inv-h2", "int-inv-h3"}
	hosts2 := []string{"int-inv-h4", "int-inv-h5", "int-inv-h6"}

	s := newRouterTestStore(t)
	srv := intRelayServer(t, s)

	// Pre-register both relay nodes
	intSeedPullRelay(t, s, relay1)
	intSeedPullRelay(t, s, relay2)

	// Connect relay 1 and announce its 3 agents
	conn1 := intDialRelay(t, srv, relay1, false)
	intWaitRelayConnected(t, relay1, 2*time.Second)
	intSendAgentList(t, conn1, hosts1)

	// Connect relay 2 and announce its 3 agents
	conn2 := intDialRelay(t, srv, relay2, false)
	intWaitRelayConnected(t, relay2, 2*time.Second)
	intSendAgentList(t, conn2, hosts2)

	// Aggregate inventory (wait for DB writes to propagate)
	router := intNewPullRouter(s)
	awaitInventoryLen(t, router, 6)
	entries, err := router.AggregateRelayInventory()
	if err != nil {
		t.Fatalf("AggregateRelayInventory: %v", err)
	}
	if len(entries) != 6 {
		t.Errorf("expected 6 total agents, got %d: %+v", len(entries), entries)
	}

	// Count by relay
	byRelay := make(map[string]int)
	for _, e := range entries {
		byRelay[e.RelayID]++
	}
	if byRelay[relay1] != 3 {
		t.Errorf("expected 3 agents from %s, got %d", relay1, byRelay[relay1])
	}
	if byRelay[relay2] != 3 {
		t.Errorf("expected 3 agents from %s, got %d", relay2, byRelay[relay2])
	}

	// Both relays are live WS connections → status must be "connected"
	for _, e := range entries {
		if e.RelayStatus != "connected" {
			t.Errorf("agent %q: expected connected, got %q", e.Hostname, e.RelayStatus)
		}
	}
}

// ── Scenario 3: Host not found ────────────────────────────────────────────────

// TestProxyHostNotFound verifies that a ProxyRouter returns ErrHostNotFound
// (the sentinel error) when the requested hostname is not in any relay's
// routing table, and that the error wraps no further context.
func TestProxyHostNotFound(t *testing.T) {
	// Empty store — no relays, no routing entries
	s := newRouterTestStore(t)
	router := intNewPullRouter(s)

	// RouteExec with unknown hostname
	_, err := router.RouteExec(
		context.Background(),
		"int-unknown-host",
		"int-task-notfound",
		ExecRequest{Cmd: "ls", Timeout: 5},
	)
	if err == nil {
		t.Fatal("expected ErrHostNotFound, got nil")
	}
	if err != ErrHostNotFound {
		t.Errorf("expected ErrHostNotFound sentinel, got: %v", err)
	}

	// Same for RouteUpload and RouteFetch
	if err2 := router.RouteUpload(context.Background(), "int-unknown-host", "t-up",
		UploadRequest{Dest: "/tmp/x", Data: "dA=="}); err2 != ErrHostNotFound {
		t.Errorf("RouteUpload: expected ErrHostNotFound, got %v", err2)
	}
	if _, err3 := router.RouteFetch(context.Background(), "int-unknown-host", "t-ft",
		FetchRequest{Src: "/tmp/x"}); err3 != ErrHostNotFound {
		t.Errorf("RouteFetch: expected ErrHostNotFound, got %v", err3)
	}
}

// ── Scenario 4: Relay disconnect clears routing ───────────────────────────────

// TestProxyRelayDisconnect verifies that when a pull-mode relay disconnects,
// the relay's entries are removed from relay_routing (BulkUpsertRelayRouting
// with nil hostnames is called by unregisterRelayConnection), and the
// ProxyRouter no longer returns those agents in AggregateRelayInventory.
func TestProxyRelayDisconnect(t *testing.T) {
	const relayID = "int-relay-dc"
	hosts := []string{"int-dc-h1", "int-dc-h2", "int-dc-h3"}

	s := newRouterTestStore(t)
	srv := intRelayServer(t, s)

	intSeedPullRelay(t, s, relayID)

	relayConn := intDialRelay(t, srv, relayID, false)
	intWaitRelayConnected(t, relayID, 2*time.Second)

	// Relay announces 3 agents
	intSendAgentList(t, relayConn, hosts)

	// Confirm routing table has 3 entries
	router := intNewPullRouter(s)
	awaitInventoryLen(t, router, 3)
	before, err := router.AggregateRelayInventory()
	if err != nil {
		t.Fatalf("AggregateRelayInventory before disconnect: %v", err)
	}
	if len(before) != 3 {
		t.Errorf("expected 3 entries before disconnect, got %d", len(before))
	}

	// Close relay WS connection — triggers unregisterRelayConnection
	_ = relayConn.Close()
	intWaitRelayDisconnected(t, relayID, 3*time.Second)

	// Wait for async cleanup (BulkUpsertRelayRouting nil call)
	awaitCond(t, 2*time.Second, "routing cleared after disconnect", func() bool {
		entries, err := s.ListRelayRouting(relayID)
		return err == nil && len(entries) == 0
	})

	// Routing entries must be cleared
	routingEntries, listErr := s.ListRelayRouting(relayID)
	if listErr != nil {
		t.Fatalf("ListRelayRouting after disconnect: %v", listErr)
	}
	if len(routingEntries) != 0 {
		t.Errorf("expected 0 routing entries after disconnect, got %d: %v",
			len(routingEntries), routingEntries)
	}

	// AggregateRelayInventory must return 0 entries (no routing rows for this relay)
	after, err := router.AggregateRelayInventory()
	if err != nil {
		t.Fatalf("AggregateRelayInventory after disconnect: %v", err)
	}
	for _, e := range after {
		if e.RelayID == relayID {
			t.Errorf("relay %s should have no agents after disconnect, found: %q",
				relayID, e.Hostname)
		}
	}

	// RouteExec for any of those hosts must now return ErrHostNotFound
	for _, h := range hosts {
		_, rerr := router.RouteExec(context.Background(), h, "t-dc", ExecRequest{Cmd: "ls"})
		if rerr != ErrHostNotFound {
			t.Errorf("host %q: expected ErrHostNotFound after relay disconnect, got %v", h, rerr)
		}
	}
}

// ── Scenario 5: Proxy chaining with is_proxy flag ─────────────────────────────

// TestProxyChaining verifies the following pull-mode chain:
//
//	ProxyRouter (proxy-A) ← relay-proxy-b connects with is_proxy=true
//	                          └── agents: int-chain-h1, int-chain-h2
//
// Checks:
//   - relay_hello with is_proxy=true stores IsProxy=true in relay_nodes DB
//   - AggregateRelayInventory returns agents from the proxy relay
//   - RouteExec dispatched via WS to the proxy relay succeeds end-to-end
func TestProxyChaining(t *testing.T) {
	const (
		relayID    = "int-proxy-b"
		hostA      = "int-chain-h1"
		hostB      = "int-chain-h2"
		wantStdout = "chain-exec-ok"
	)

	var isProxyCallMu sync.Mutex
	var isProxyCalled bool
	var isProxyCalledValue bool

	s := newRouterTestStore(t)

	// Wire integration functions (intRelayServer does this, but we need to capture
	// the is_proxy update to verify the DB flag was persisted)
	setWSHooks(t, wsHooks{
		routing: s.BulkUpsertRelayRouting,
		status:  s.UpdateRelayStatus,
		isProxy: func(rid string, ip bool) error {
			isProxyCallMu.Lock()
			isProxyCalled = true
			isProxyCalledValue = ip
			isProxyCallMu.Unlock()
			return s.SetRelayIsProxy(rid, ip)
		},
	})
	srv := httptest.NewServer(http.HandlerFunc(ws.RelayHandler))
	t.Cleanup(srv.Close)

	// Pre-register relay node (as pull + is_proxy initially false)
	intSeedPullRelay(t, s, relayID)

	// Connect relay with is_proxy=true query param
	relayConn := intDialRelay(t, srv, relayID, true)
	intWaitRelayConnected(t, relayID, 2*time.Second)

	// Send relay_hello so the handler processes the is_proxy flag
	hello := ws.RelayMessage{
		Type:     "relay_hello",
		RelayID:  relayID,
		Version:  "1.0",
		IsProxy:  true,
		NodeType: "proxy",
	}
	if err := relayConn.WriteJSON(hello); err != nil {
		t.Fatalf("WriteJSON relay_hello: %v", err)
	}
	// Read relay_ack
	var ack ws.RelayMessage
	if err := relayConn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("relayConn SetReadDeadline: %v", err)
	}
	if err := relayConn.ReadJSON(&ack); err != nil {
		t.Fatalf("ReadJSON relay_ack: %v", err)
	}
	if ack.Type != "relay_ack" {
		t.Errorf("expected relay_ack, got %q", ack.Type)
	}

	// Wait for is_proxy update
	awaitCond(t, 2*time.Second, "RelayIsProxyUpdateFunc called", func() bool {
		isProxyCallMu.Lock()
		defer isProxyCallMu.Unlock()
		return isProxyCalled
	})

	// Verify is_proxy was stored in DB
	isProxyCallMu.Lock()
	called := isProxyCalled
	calledVal := isProxyCalledValue
	isProxyCallMu.Unlock()
	if !called {
		t.Error("RelayIsProxyUpdateFunc was not called after relay_hello with is_proxy=true")
	}
	if !calledVal {
		t.Error("RelayIsProxyUpdateFunc called with is_proxy=false, expected true")
	}

	node, dbErr := s.GetRelayNode(relayID)
	if dbErr != nil || node == nil {
		t.Fatalf("GetRelayNode: err=%v node=%v", dbErr, node)
	}
	if !node.IsProxy {
		t.Error("expected IsProxy=true in relay_nodes after relay_hello with is_proxy=true")
	}

	// Proxy relay announces its agents
	intSendAgentList(t, relayConn, []string{hostA, hostB})

	// AggregateRelayInventory includes proxy relay's agents
	router := intNewPullRouter(s)
	awaitInventoryLen(t, router, 2)
	entries, err := router.AggregateRelayInventory()
	if err != nil {
		t.Fatalf("AggregateRelayInventory: %v", err)
	}
	if len(entries) != 2 {
		t.Errorf("expected 2 agents from proxy relay, got %d", len(entries))
	}

	// Exec through the chain: proxy-A dispatches via WS to proxy-B relay
	done := intRelayEchoWorker(relayConn, wantStdout)

	resp, routeErr := router.RouteExec(
		context.Background(),
		hostA,
		"int-chain-task-1",
		ExecRequest{Cmd: "echo chain", Timeout: 5},
	)

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Error("relay chain echo goroutine did not finish")
	}

	if routeErr != nil {
		t.Fatalf("RouteExec chain: %v", routeErr)
	}
	if resp.RC != 0 {
		t.Errorf("expected RC=0, got %d", resp.RC)
	}
	if resp.Stdout != wantStdout {
		t.Errorf("expected stdout=%q, got %q", wantStdout, resp.Stdout)
	}
}

// Push-mode integration tests were removed in v3.0 (#123) when PushManager
// and RelayClient were deleted.  The offline behaviour for push relays without
// a WS connection is covered by TestProxyRouter_RouteExec_PushModeOffline
// in router_test.go.  Push routing will be re-enabled by #140.
