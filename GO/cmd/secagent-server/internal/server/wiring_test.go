package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// ── wiring of the REAL start-up sequence (#155) ──────────────────────────────

const testAdminToken = "node-test-admin"

func adminCall(t *testing.T, admin, method, path string, body any) (int, []byte) {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, "http://"+admin+path, rdr)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+testAdminToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, out
}

// dialRelayWS opens /ws/relay on the node's WS listener with a bearer token.
func dialRelayWS(wsAddr, token string) (*websocket.Conn, int, error) {
	h := http.Header{}
	if token != "" {
		h.Set("Authorization", "Bearer "+token)
	}
	c, resp, err := websocket.DefaultDialer.Dial("ws://"+wsAddr+"/ws/relay", h)
	status := 0
	if resp != nil {
		status = resp.StatusCode
	}
	return c, status, err
}

func readUntilClose(t *testing.T, c *websocket.Conn) int {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	for {
		var m map[string]any
		if err := c.ReadJSON(&m); err != nil {
			if ce, ok := err.(*websocket.CloseError); ok {
				return ce.Code
			}
			t.Fatalf("expected a close frame, got %v", err)
		}
	}
}

func registerRelay(t *testing.T, admin, id string) (token, uuid string) {
	t.Helper()
	code, body := adminCall(t, admin, "POST", "/api/admin/relays", map[string]any{"relay_id": id, "mode": "pull"})
	if code != http.StatusCreated {
		t.Fatalf("register %s: %d %s", id, code, body)
	}
	var r struct {
		ID       string `json:"id"`
		JWTToken string `json:"jwt_token"`
	}
	if err := json.Unmarshal(body, &r); err != nil || r.JWTToken == "" {
		t.Fatalf("register response: %s %v", body, err)
	}
	return r.JWTToken, r.ID
}

// ── admin handlers are never reachable on the public ports ───────────────────

// shared by design: the same pattern is intentionally served on the public router too.
var publicByDesign = map[string]bool{
	"POST /api/admin/authorize": true, // agent bootstrap compat on 7770
	"GET /api/inventory":        true, // public inventory (plugin token); the admin router serves AdminGetInventory
}

func concretePath(pattern string) (method, path string) {
	method, path = "GET", pattern
	if i := strings.Index(pattern, " "); i > 0 {
		method, path = pattern[:i], pattern[i+1:]
	}
	for {
		i := strings.Index(path, "{")
		if i < 0 {
			break
		}
		j := strings.Index(path[i:], "}")
		path = path[:i] + "x" + path[i+j+1:]
	}
	return method, path
}

func TestWiring_AdminHandlersAreNotReachableOnThePublicPorts(t *testing.T) {
	n, api, admin, wsAddr := startNode(t, nil)
	apiRoutes, adminRoutes, wsRoutes := n.Routes()
	if len(adminRoutes) < 20 {
		t.Fatalf("suspiciously few admin routes recorded: %d", len(adminRoutes))
	}

	// 1. declared: no admin pattern is registered on the public routers (except by design)
	for _, routes := range [][]string{apiRoutes, wsRoutes} {
		for _, p := range routes {
			if strings.Contains(p, "/api/admin/") && !publicByDesign[p] {
				t.Errorf("admin pattern %q is registered on a public router", p)
			}
		}
	}
	adminOnly := 0
	for _, p := range adminRoutes {
		if publicByDesign[p] {
			continue
		}
		adminOnly++
		method, path := concretePath(p)
		// 2. observed: the admin route answers on the admin port but is a 404 on the public ports
		for name, addr := range map[string]string{"public API": api, "WebSocket": wsAddr} {
			req, _ := http.NewRequest(method, "http://"+addr+path, nil)
			req.Header.Set("Authorization", "Bearer "+testAdminToken)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusNotFound {
				t.Errorf("%s %s reachable on the %s port: status %d, want 404", method, path, name, resp.StatusCode)
			}
		}
		req, _ := http.NewRequest(method, "http://"+admin+path, nil)
		req.Header.Set("Authorization", "Bearer "+testAdminToken)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusNotFound && !strings.Contains(path, "x") {
			t.Errorf("%s %s must be served on the admin port", method, path)
		}
	}
	if adminOnly < 20 {
		t.Errorf("only %d admin-only routes were probed", adminOnly)
	}
}

// ── security hooks are wired: removing one makes these fail ──────────────────

func TestWiring_RelayTokenRevocationIsEnforcedEndToEnd(t *testing.T) {
	_, _, admin, wsAddr := startNode(t, nil)

	// no credentials / garbage → refused (JWT secrets wired)
	if _, status, err := dialRelayWS(wsAddr, ""); err == nil || status != http.StatusUnauthorized {
		t.Errorf("anonymous /ws/relay: status %d err %v, want 401", status, err)
	}
	if _, status, err := dialRelayWS(wsAddr, "not.a.jwt"); err == nil || status != http.StatusUnauthorized {
		t.Errorf("garbage token: status %d err %v, want 401", status, err)
	}

	token, id := registerRelay(t, admin, "dmz1")
	c, status, err := dialRelayWS(wsAddr, token)
	if err != nil {
		t.Fatalf("a freshly registered relay must connect: %v (status %d)", err, status)
	}
	defer func() { _ = c.Close() }()

	code, body := adminCall(t, admin, "POST", "/api/admin/relays/"+id+"/revoke", nil)
	if code != http.StatusOK || !strings.Contains(string(body), `"disconnected":true`) {
		t.Fatalf("revoke: %d %s", code, body)
	}
	if got := readUntilClose(t, c); got != 4010 {
		t.Errorf("close code = %d, want 4010 (CloseRelay wired)", got)
	}
	// the same token is refused afterwards: blacklist and revoked check are wired
	if _, status, err := dialRelayWS(wsAddr, token); err == nil || status != http.StatusUnauthorized {
		t.Errorf("revoked relay reconnected: status %d err %v, want 401", status, err)
	}
	// another relay is unaffected
	tok2, _ := registerRelay(t, admin, "dmz2")
	c2, _, err := dialRelayWS(wsAddr, tok2)
	if err != nil {
		t.Fatalf("dmz2 must connect: %v", err)
	}
	_ = c2.Close()
}

func TestWiring_RelayParentTokenRevocationAndParentLinkAreWired(t *testing.T) {
	_, _, admin, wsAddr := startNode(t, nil)

	code, body := adminCall(t, admin, "POST", "/api/admin/tokens", map[string]any{
		"role": "relay-parent", "sub": "central", "expires_at": time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)})
	if code != http.StatusCreated {
		t.Fatalf("mint: %d %s", code, body)
	}
	var tok struct{ Token, ID string }
	if err := json.Unmarshal(body, &tok); err != nil || tok.Token == "" {
		t.Fatalf("mint response: %s", body)
	}

	c, _, err := dialRelayWS(wsAddr, tok.Token)
	if err != nil {
		t.Fatalf("relay-parent token must open the link: %v", err)
	}
	defer func() { _ = c.Close() }()
	if err := c.WriteJSON(map[string]any{"type": "relay_hello", "relay_id": "central", "version": "3.0"}); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	var ack map[string]any
	if err := c.ReadJSON(&ack); err != nil || ack["type"] != "relay_ack" {
		t.Fatalf("a root node must accept a parent link (parent link hook wired): %v %v", ack, err)
	}

	code, body = adminCall(t, admin, "POST", "/api/admin/tokens/"+tok.ID+"/revoke", nil)
	if code != http.StatusOK || !strings.Contains(string(body), `"disconnected":true`) {
		t.Fatalf("revoke: %d %s", code, body)
	}
	if got := readUntilClose(t, c); got != 4010 {
		t.Errorf("close code = %d, want 4010", got)
	}
	if _, status, err := dialRelayWS(wsAddr, tok.Token); err == nil || status != http.StatusUnauthorized {
		t.Errorf("revoked relay-parent token reconnected: status %d err %v, want 401 (JTI blacklist wired)", status, err)
	}
}

// A relay cannot take over a host that another relay already declared in its snapshot: this needs
// the route lookup hook (SetRelayHostRouteFunc) to be wired with a real implementation.
func TestWiring_SnapshotCannotHijackAHostRoutedViaAnotherRelay(t *testing.T) {
	_, _, admin, wsAddr := startNode(t, nil)
	tokA, _ := registerRelay(t, admin, "relay-a")
	tokB, _ := registerRelay(t, admin, "relay-b")

	snapshot := func(token, relayID string) *websocket.Conn {
		c, _, err := dialRelayWS(wsAddr, token)
		if err != nil {
			t.Fatalf("%s: %v", relayID, err)
		}
		t.Cleanup(func() { _ = c.Close() })
		if err := c.WriteJSON(map[string]any{"type": "relay_hello", "relay_id": relayID, "version": "3.0"}); err != nil {
			t.Fatal(err)
		}
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		var ack map[string]any
		if err := c.ReadJSON(&ack); err != nil {
			t.Fatal(err)
		}
		if err := c.WriteJSON(map[string]any{"type": "topology_snapshot", "relays": []any{},
			"agents": []any{map[string]any{"hostname": "victim-host", "relay_id": relayID, "relay_chain": []string{relayID}}}}); err != nil {
			t.Fatal(err)
		}
		return c
	}
	b := snapshot(tokB, "relay-b")
	_ = b.SetReadDeadline(time.Now().Add(5 * time.Second))
	var ackB map[string]any
	if err := b.ReadJSON(&ackB); err != nil || ackB["type"] != "topology_ack" {
		t.Fatalf("relay-b's snapshot must be accepted: %v %v", ackB, err)
	}
	a := snapshot(tokA, "relay-a")
	if got := readUntilClose(t, a); got != 4012 {
		t.Errorf("relay-a claiming relay-b's host: close code %d, want 4012 (route lookup wired)", got)
	}
}

// ── health endpoint stays public and minimal on the real node ────────────────

func TestWiring_HealthIsPublicAndMinimal(t *testing.T) {
	_, api, _, _ := startNode(t, nil)
	resp, err := http.Get("http://" + api + "/health")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var m map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		t.Fatal(err)
	}
	for k := range m {
		if k != "status" && k != "timestamp" && k != "degraded" {
			t.Errorf("unexpected key %q on the public /health", k)
		}
	}
}

// #192: the refresh route is gone from every router (the public one included).
func TestRouters_NoTokenRefreshRoute(t *testing.T) {
	n, _, _, _ := startNode(t, nil)
	api, admin, wsRoutes := n.Routes()
	for name, routes := range map[string][]string{"api": api, "admin": admin, "ws": wsRoutes} {
		for _, r := range routes {
			if strings.Contains(r, "token/refresh") {
				t.Errorf("%s router still registers %q", name, r)
			}
		}
	}
}
