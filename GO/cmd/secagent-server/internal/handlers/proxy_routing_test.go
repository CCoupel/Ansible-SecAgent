// proxy_routing_test.go — Tests for proxy routing in exec/upload/fetch/inventory handlers.
//
// These tests verify that when a ProxyRouter is configured, the handlers:
//   - Route exec/upload/fetch to downstream relays via the router
//   - Fall through to local agent logic when hostname is not in relay_routing
//   - Aggregate relay agents in the inventory response
package handlers

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"secagent-server/cmd/secagent-server/internal/proxy"
	"secagent-server/cmd/secagent-server/internal/storage"
)

// ── Setup helpers ─────────────────────────────────────────────────────────────

const proxyTestToken = "secagent_plg_proxy_test_token"

// setupProxyTest creates an in-memory store, a plugin token, and a ProxyRouter.
// Returns the store and a request decorator that adds the plugin auth header.
// Cleans up proxyRouter on test completion.
func setupProxyTest(t *testing.T) (*storage.Store, func(r *http.Request) *http.Request) {
	t.Helper()
	s := newTestStore(t)
	SetAdminStore(s)

	// Register plugin token
	h := sha256.Sum256([]byte(proxyTestToken))
	tok := storage.PluginToken{
		ID:        "tok-proxy-test",
		TokenHash: fmt.Sprintf("%x", h),
		Role:      "plugin",
		CreatedAt: time.Now().UTC(),
	}
	if err := s.CreatePluginToken(context.Background(), tok); err != nil {
		t.Fatalf("setupProxyTest: CreatePluginToken: %v", err)
	}

	// Create and inject proxy router backed by this store
	r := proxy.NewProxyRouter(s)
	SetProxyRouter(r)
	t.Cleanup(func() { SetProxyRouter(nil) })

	return s, func(req *http.Request) *http.Request {
		req.Header.Set("Authorization", "Bearer "+proxyTestToken)
		req.RemoteAddr = "127.0.0.1:8080"
		return req
	}
}

// seedProxyRelay inserts a push-mode relay node + routing entries into the store.
func seedProxyRelay(t *testing.T, s *storage.Store, relayID, url string, hosts []string) {
	t.Helper()
	node := storage.RelayNode{
		ID:          "uuid-" + relayID,
		RelayID:     relayID,
		URL:         url,
		TokenSecret: "enc:relay-token", // the state only holds sealed push tokens
		Mode:        "push",
		Status:      "connected",
		CreatedAt:   time.Now().Unix(),
	}
	if err := s.UpsertRelayNode(node); err != nil {
		t.Fatalf("seedProxyRelay: UpsertRelayNode: %v", err)
	}
	if err := s.BulkUpsertRelayRouting(relayID, hosts); err != nil {
		t.Fatalf("seedProxyRelay: BulkUpsertRelayRouting: %v", err)
	}
}

// mockRelayHTTPServer starts a minimal httptest server mimicking a relay REST API.
func mockRelayHTTPServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasPrefix(r.URL.Path, "/api/exec/"):
			mustEncode(t, w, map[string]interface{}{
				"rc": 0, "stdout": "relay-exec-ok", "stderr": "", "truncated": false,
			})
		case strings.HasPrefix(r.URL.Path, "/api/upload/"):
			mustEncode(t, w, map[string]string{"status": "ok"})
		case strings.HasPrefix(r.URL.Path, "/api/fetch/"):
			mustEncode(t, w, map[string]interface{}{
				"rc": 0, "data": "cmVsYXktZmV0Y2g=",
			})
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// ── ExecCommand proxy routing ─────────────────────────────────────────────────

// TestExecCommand_ProxyRouting_PushMode verifies that a push-mode relay without
// a WS connection returns relay_offline (503).  REST push routing was removed in
// v3.0 (#123); push entries are preserved in DB but are inert until #140.
func TestExecCommand_ProxyRouting_PushMode(t *testing.T) {
	s, withAuth := setupProxyTest(t)
	// Push relay: stored in DB but not WS-connected → relay_offline
	seedProxyRelay(t, s, "dmz-exec", "http://dmz-exec:7770", []string{"relay-host-exec"})

	body, _ := json.Marshal(map[string]interface{}{"cmd": "echo hi", "timeout": 10})
	req := withAuth(httptest.NewRequest("POST", "/api/exec/relay-host-exec", bytes.NewReader(body)))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("hostname", "relay-host-exec")
	w := httptest.NewRecorder()

	ExecCommand(w, req)

	// Push relay without WS → relay_offline (503)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 (relay_offline for push relay without WS), got %d — %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	mustDecode(t, w.Body, &resp)
	if !strings.Contains(resp["error"], "relay_offline") {
		t.Errorf("expected relay_offline error, got %q", resp["error"])
	}
}

func TestExecCommand_ProxyRouting_HostNotInRelay_FallsThrough(t *testing.T) {
	// Host is NOT in relay_routing → falls through to local agent (which is offline → 503)
	_, withAuth := setupProxyTest(t)

	body, _ := json.Marshal(map[string]interface{}{"cmd": "ls", "timeout": 5})
	req := withAuth(httptest.NewRequest("POST", "/api/exec/not-in-relay", bytes.NewReader(body)))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("hostname", "not-in-relay")
	w := httptest.NewRecorder()

	ExecCommand(w, req)

	// Local agent is offline → 503
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 (agent_offline fallthrough), got %d — %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	mustDecode(t, w.Body, &resp)
	if resp["error"] != "agent_offline" {
		t.Errorf("expected error=agent_offline, got %q", resp["error"])
	}
}

func TestExecCommand_ProxyRouting_RelayOffline(t *testing.T) {
	// Host IS in relay_routing but relay has no URL and is not WS connected → relay_offline
	s, withAuth := setupProxyTest(t)

	// Register relay with no URL
	node := storage.RelayNode{
		ID: "uuid-nourl", RelayID: "no-url-relay",
		URL: "", Mode: "pull", Status: "disconnected", CreatedAt: time.Now().Unix(),
	}
	_ = s.UpsertRelayNode(node)
	_ = s.BulkUpsertRelayRouting("no-url-relay", []string{"host-no-relay"})

	body, _ := json.Marshal(map[string]interface{}{"cmd": "ls", "timeout": 5})
	req := withAuth(httptest.NewRequest("POST", "/api/exec/host-no-relay", bytes.NewReader(body)))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("hostname", "host-no-relay")
	w := httptest.NewRecorder()

	ExecCommand(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d — %s", w.Code, w.Body.String())
	}
}

// ── UploadFile proxy routing ──────────────────────────────────────────────────

// TestUploadFile_ProxyRouting_PushMode verifies that upload to a push-mode relay
// without WS connection returns relay_offline (503) in v3.0 (#123).
func TestUploadFile_ProxyRouting_PushMode(t *testing.T) {
	s, withAuth := setupProxyTest(t)
	// Push relay: stored in DB but not WS-connected → relay_offline
	seedProxyRelay(t, s, "dmz-upload", "http://dmz-upload:7770", []string{"upload-relay-host"})

	body, _ := json.Marshal(map[string]interface{}{
		"dest": "/tmp/f.txt", "data": "aGVsbG8=", "mode": "0644",
	})
	req := withAuth(httptest.NewRequest("POST", "/api/upload/upload-relay-host", bytes.NewReader(body)))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("hostname", "upload-relay-host")
	w := httptest.NewRecorder()

	UploadFile(w, req)

	// Push relay without WS → relay_offline (503)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 (relay_offline for push relay), got %d — %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	mustDecode(t, w.Body, &resp)
	if !strings.Contains(resp["error"], "relay_offline") {
		t.Errorf("expected relay_offline error, got %q", resp["error"])
	}
}

// ── FetchFile proxy routing ───────────────────────────────────────────────────

// TestFetchFile_ProxyRouting_PushMode verifies that fetch from a push-mode relay
// without WS connection returns relay_offline (503) in v3.0 (#123).
func TestFetchFile_ProxyRouting_PushMode(t *testing.T) {
	s, withAuth := setupProxyTest(t)
	// Push relay: stored in DB but not WS-connected → relay_offline
	seedProxyRelay(t, s, "dmz-fetch", "http://dmz-fetch:7770", []string{"fetch-relay-host"})

	body, _ := json.Marshal(map[string]interface{}{"src": "/etc/hosts"})
	req := withAuth(httptest.NewRequest("POST", "/api/fetch/fetch-relay-host", bytes.NewReader(body)))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("hostname", "fetch-relay-host")
	w := httptest.NewRecorder()

	FetchFile(w, req)

	// Push relay without WS → relay_offline (503)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 (relay_offline for push relay), got %d — %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	mustDecode(t, w.Body, &resp)
	if !strings.Contains(resp["error"], "relay_offline") {
		t.Errorf("expected relay_offline error, got %q", resp["error"])
	}
}

// ── Inventory aggregation ─────────────────────────────────────────────────────

func TestGetInventory_UnifiedWithRelayAgents(t *testing.T) {
	relaySrv := mockRelayHTTPServer(t)
	s, withAuth := setupProxyTest(t)
	seedProxyRelay(t, s, "dmz-inv", relaySrv.URL, []string{"relay-h1", "relay-h2"})

	req := withAuth(httptest.NewRequest("GET", "/api/inventory", nil))
	w := httptest.NewRecorder()
	GetInventory(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp InventoryResponse
	mustDecode(t, w.Body, &resp)

	// relay-h1 and relay-h2 should appear
	hostSet := make(map[string]bool, len(resp.All.Hosts))
	for _, h := range resp.All.Hosts {
		hostSet[h] = true
	}
	for _, expected := range []string{"relay-h1", "relay-h2"} {
		if !hostSet[expected] {
			t.Errorf("expected %q in unified inventory, not found in %v", expected, resp.All.Hosts)
		}
	}

	// relay_id must be set for relay agents
	for _, h := range []string{"relay-h1", "relay-h2"} {
		hv, ok := resp.Meta.Hostvars[h]
		if !ok {
			t.Errorf("missing hostvars for %q", h)
			continue
		}
		if hv.RelayID != "dmz-inv" {
			t.Errorf("expected secagent_relay_id=dmz-inv for %q, got %q", h, hv.RelayID)
		}
		if hv.AnsibleConnection != "relay" {
			t.Errorf("expected ansible_connection=relay for %q, got %q", h, hv.AnsibleConnection)
		}
	}
}

func TestGetInventory_RelayAgents_OnlyConnected_Filtered(t *testing.T) {
	s, withAuth := setupProxyTest(t)

	// Disconnected relay
	dcNode := storage.RelayNode{
		ID: "uuid-dc", RelayID: "dmz-dc",
		Mode: "pull", Status: "disconnected", CreatedAt: time.Now().Unix(),
	}
	_ = s.UpsertRelayNode(dcNode)
	_ = s.BulkUpsertRelayRouting("dmz-dc", []string{"dc-relay-host"})

	req := withAuth(httptest.NewRequest("GET", "/api/inventory?only_connected=true", nil))
	w := httptest.NewRecorder()
	GetInventory(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp InventoryResponse
	mustDecode(t, w.Body, &resp)

	for _, h := range resp.All.Hosts {
		if h == "dc-relay-host" {
			t.Errorf("dc-relay-host should be filtered out with only_connected=true")
		}
	}
}

func TestGetInventory_LocalAgentTakesPrecedenceOverRelay(t *testing.T) {
	// If same hostname appears in relay_routing AND local agents, local wins (no relay_id)
	s, withAuth := setupProxyTest(t)

	// Seed relay routing for a host that's "also" local
	_ = s.UpsertRelayNode(storage.RelayNode{
		ID: "uuid-dup", RelayID: "dmz-dup",
		URL: "http://dmz-dup:7770", Mode: "push", Status: "connected", CreatedAt: time.Now().Unix(),
	})
	_ = s.BulkUpsertRelayRouting("dmz-dup", []string{"dup-host"})

	// Register dup-host as a fully-registered local agent (in agents table)
	ctx := context.Background()
	if err := s.UpsertAgent(ctx, "dup-host", "PUBKEY-PEM", "jti-dup-host"); err != nil {
		t.Fatalf("UpsertAgent: %v", err)
	}

	req := withAuth(httptest.NewRequest("GET", "/api/inventory", nil))
	w := httptest.NewRecorder()
	GetInventory(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp InventoryResponse
	mustDecode(t, w.Body, &resp)

	// dup-host should appear exactly once and without relay_id (local takes precedence)
	count := 0
	for _, h := range resp.All.Hosts {
		if h == "dup-host" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("dup-host should appear exactly once, got %d", count)
	}
	if hv, ok := resp.Meta.Hostvars["dup-host"]; ok {
		if hv.RelayID != "" {
			t.Errorf("expected no relay_id for local agent, got %q", hv.RelayID)
		}
	}
}

func TestGetInventory_NoProxyRouter_LocalOnly(t *testing.T) {
	// When proxyRouter is nil, inventory only shows local agents (no relay aggregation)
	s := newTestStore(t)
	SetAdminStore(s)
	SetProxyRouter(nil)
	t.Cleanup(func() { SetProxyRouter(nil) })

	// Set up plugin token on the fresh store
	h := sha256.Sum256([]byte("secagent_plg_local_only"))
	tok := storage.PluginToken{
		ID:        "tok-local-only",
		TokenHash: fmt.Sprintf("%x", h),
		Role:      "plugin",
		CreatedAt: time.Now().UTC(),
	}
	_ = s.CreatePluginToken(context.Background(), tok)

	req := httptest.NewRequest("GET", "/api/inventory", nil)
	req.Header.Set("Authorization", "Bearer secagent_plg_local_only")
	req.RemoteAddr = "127.0.0.1:8080"
	w := httptest.NewRecorder()
	GetInventory(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp InventoryResponse
	mustDecode(t, w.Body, &resp)
	if resp.All.Hosts == nil {
		t.Error("expected non-nil hosts array")
	}
}
