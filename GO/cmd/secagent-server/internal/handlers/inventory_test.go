package handlers

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"secagent-server/cmd/secagent-server/internal/storage"
)

// inventoryTestToken is the plain-text plugin token used across inventory tests.
const inventoryTestToken = "secagent_plg_inventory_test_shared"

// setupInventoryAuth initialises an in-memory store with a valid plugin token
// and returns a helper that stamps requests with the bearer header.
func setupInventoryAuth(t *testing.T) func(r *http.Request) *http.Request {
	t.Helper()
	s := newTestStore(t)
	SetAdminStore(s)

	h := sha256.Sum256([]byte(inventoryTestToken))
	tok := storage.PluginToken{
		ID:        "tok-inv-shared",
		TokenHash: fmt.Sprintf("%x", h),
		Role:      "plugin",
		CreatedAt: time.Now().UTC(),
	}
	if err := s.CreatePluginToken(context.Background(), tok); err != nil {
		t.Fatalf("setupInventoryAuth: %v", err)
	}

	return func(r *http.Request) *http.Request {
		r.Header.Set("Authorization", "Bearer "+inventoryTestToken)
		r.RemoteAddr = "127.0.0.1:8080"
		return r
	}
}

// TestGetInventoryAll tests returning all agents
func TestGetInventoryAll(t *testing.T) {
	withAuth := setupInventoryAuth(t)
	httpReq := withAuth(httptest.NewRequest("GET", "/api/inventory", nil))
	w := httptest.NewRecorder()

	GetInventory(w, httpReq)

	if w.Code != http.StatusOK {
		t.Errorf("GetInventory: expected 200, got %d", w.Code)
	}

	var resp InventoryResponse
	json.Unmarshal(w.Body.Bytes(), &resp)

	if resp.All.Hosts == nil {
		t.Error("expected All.Hosts array, got nil")
	}

	if resp.Meta.Hostvars == nil {
		t.Error("expected Meta.Hostvars map, got nil")
	}

	// Should have at least the mock data (agent-1, agent-2)
	if len(resp.All.Hosts) < 1 {
		t.Logf("expected at least 1 host, got %d", len(resp.All.Hosts))
	}
}

// TestGetInventoryOnlyConnected tests filtering to connected agents only
func TestGetInventoryOnlyConnected(t *testing.T) {
	withAuth := setupInventoryAuth(t)
	httpReq := withAuth(httptest.NewRequest("GET", "/api/inventory?only_connected=true", nil))
	w := httptest.NewRecorder()

	GetInventory(w, httpReq)

	if w.Code != http.StatusOK {
		t.Errorf("GetInventory: expected 200, got %d", w.Code)
	}

	var resp InventoryResponse
	json.Unmarshal(w.Body.Bytes(), &resp)

	// Check that all returned hosts are marked as connected
	for hostname, hostvar := range resp.Meta.Hostvars {
		if hostvar.RelayStatus != "connected" {
			t.Errorf("host %q has status %q, expected connected", hostname, hostvar.RelayStatus)
		}
	}
}

// TestGetInventoryOnlyConnectedFalse tests disabling the filter
func TestGetInventoryOnlyConnectedFalse(t *testing.T) {
	withAuth := setupInventoryAuth(t)
	httpReq := withAuth(httptest.NewRequest("GET", "/api/inventory?only_connected=false", nil))
	w := httptest.NewRecorder()

	GetInventory(w, httpReq)

	if w.Code != http.StatusOK {
		t.Errorf("GetInventory: expected 200, got %d", w.Code)
	}

	var resp InventoryResponse
	json.Unmarshal(w.Body.Bytes(), &resp)

	// Should include both connected and disconnected hosts
	if len(resp.All.Hosts) < 2 {
		t.Logf("expected at least 2 hosts (connected + disconnected), got %d", len(resp.All.Hosts))
	}
}

// TestGetInventoryInvalidOnlyConnected tests invalid boolean value
func TestGetInventoryInvalidOnlyConnected(t *testing.T) {
	withAuth := setupInventoryAuth(t)
	httpReq := withAuth(httptest.NewRequest("GET", "/api/inventory?only_connected=not-a-bool", nil))
	w := httptest.NewRecorder()

	GetInventory(w, httpReq)

	if w.Code != http.StatusOK {
		t.Errorf("GetInventory: expected 200, got %d", w.Code)
	}

	// Should succeed with default behavior (not fail on invalid bool)
	var resp InventoryResponse
	json.Unmarshal(w.Body.Bytes(), &resp)

	if resp.All.Hosts == nil {
		t.Error("expected valid response even with invalid query param")
	}
}

// TestGetInventoryFormat tests the Ansible inventory format structure
func TestGetInventoryFormat(t *testing.T) {
	withAuth := setupInventoryAuth(t)
	httpReq := withAuth(httptest.NewRequest("GET", "/api/inventory", nil))
	w := httptest.NewRecorder()

	GetInventory(w, httpReq)

	var resp InventoryResponse
	json.Unmarshal(w.Body.Bytes(), &resp)

	// Check that structure matches Ansible format
	if resp.All.Hosts == nil || len(resp.All.Hosts) < 1 {
		t.Skip("no hosts in inventory")
	}

	firstHost := resp.All.Hosts[0]

	// Check hostvars for first host
	hostvar, exists := resp.Meta.Hostvars[firstHost]
	if !exists {
		t.Errorf("host %q not found in hostvars", firstHost)
	}

	// Verify required fields
	if hostvar.AnsibleConnection != "relay" {
		t.Errorf("ansible_connection: expected 'relay', got %q", hostvar.AnsibleConnection)
	}

	if hostvar.AnsibleHost != firstHost {
		t.Errorf("ansible_host: expected %q, got %q", firstHost, hostvar.AnsibleHost)
	}

	if hostvar.RelayStatus == "" {
		t.Error("secagent_status must not be empty")
	}
}

// TestGetInventoryHostVarsCompleteness tests all required fields are present
func TestGetInventoryHostVarsCompleteness(t *testing.T) {
	withAuth := setupInventoryAuth(t)
	httpReq := withAuth(httptest.NewRequest("GET", "/api/inventory", nil))
	w := httptest.NewRecorder()

	GetInventory(w, httpReq)

	var resp InventoryResponse
	json.Unmarshal(w.Body.Bytes(), &resp)

	if len(resp.All.Hosts) < 1 {
		t.Skip("no hosts in inventory")
	}

	for hostname, hostvar := range resp.Meta.Hostvars {
		// All these fields should be present
		if hostvar.AnsibleConnection == "" {
			t.Errorf("host %q: missing ansible_connection", hostname)
		}

		if hostvar.AnsibleHost == "" {
			t.Errorf("host %q: missing ansible_host", hostname)
		}

		if hostvar.RelayStatus == "" {
			t.Errorf("host %q: missing secagent_status", hostname)
		}

		// secagent_last_seen may be empty for freshly registered hosts
		// but should be present as a field (even if empty)
	}
}

// TestGetInventoryContentType tests response content type
func TestGetInventoryContentType(t *testing.T) {
	withAuth := setupInventoryAuth(t)
	httpReq := withAuth(httptest.NewRequest("GET", "/api/inventory", nil))
	w := httptest.NewRecorder()

	GetInventory(w, httpReq)

	contentType := w.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("expected Content-Type: application/json, got %q", contentType)
	}
}

// TestInventoryResponseStruct tests the data structure
func TestInventoryResponseStruct(t *testing.T) {
	resp := InventoryResponse{}
	resp.All.Hosts = []string{"host-1", "host-2"}
	resp.Meta.Hostvars = make(map[string]HostVars)
	resp.Meta.Hostvars["host-1"] = HostVars{
		AnsibleConnection: "relay",
		AnsibleHost:       "host-1",
		RelayStatus:       "connected",
		RelayLastSeen:     "2026-03-05T12:00:00Z",
	}

	// Marshal and unmarshal to verify JSON compatibility
	body, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var resp2 InventoryResponse
	err = json.Unmarshal(body, &resp2)
	if err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if len(resp2.All.Hosts) != 2 {
		t.Errorf("expected 2 hosts, got %d", len(resp2.All.Hosts))
	}

	if resp2.Meta.Hostvars["host-1"].AnsibleConnection != "relay" {
		t.Error("failed to preserve ansible_connection")
	}
}

// TestHostVarsStruct tests the HostVars data structure
func TestHostVarsStruct(t *testing.T) {
	hv := HostVars{
		AnsibleConnection: "relay",
		AnsibleHost:       "test-host",
		RelayStatus:       "connected",
		RelayLastSeen:     "2026-03-05T12:00:00Z",
	}

	body, err := json.Marshal(hv)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var hv2 HostVars
	err = json.Unmarshal(body, &hv2)
	if err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if hv2.AnsibleConnection != hv.AnsibleConnection {
		t.Error("failed to preserve ansible_connection")
	}

	if hv2.AnsibleHost != hv.AnsibleHost {
		t.Error("failed to preserve ansible_host")
	}

	if hv2.RelayStatus != hv.RelayStatus {
		t.Error("failed to preserve secagent_status")
	}

	if hv2.RelayLastSeen != hv.RelayLastSeen {
		t.Error("failed to preserve secagent_last_seen")
	}
}

// ========================================================================
// AdminGetInventory — admin token auth on port 7771
// ========================================================================

// TestAdminGetInventory_RequiresAdminAuth verifies 401 without auth header.
func TestAdminGetInventory_RequiresAdminAuth(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)

	req := httptest.NewRequest("GET", "/api/inventory", nil)
	w := httptest.NewRecorder()
	AdminGetInventory(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 without auth, got %d", w.Code)
	}
}

// TestAdminGetInventory_RejectsPluginToken verifies plugin tokens are rejected.
func TestAdminGetInventory_RejectsPluginToken(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)

	req := httptest.NewRequest("GET", "/api/inventory", nil)
	req.Header.Set("Authorization", "Bearer secagent_plg_not_admin")
	w := httptest.NewRecorder()
	AdminGetInventory(w, req)

	// Should be 401 (not an admin token)
	if w.Code == http.StatusOK {
		t.Error("expected rejection for non-admin token")
	}
}

// TestAdminGetInventory_Success verifies 200 with valid admin token.
func TestAdminGetInventory_Success(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)

	req := httptest.NewRequest("GET", "/api/inventory", nil)
	req.Header.Set("Authorization", "Bearer "+server.AdminToken)
	w := httptest.NewRecorder()
	AdminGetInventory(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d — %s", w.Code, w.Body.String())
	}

	var resp InventoryResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.All.Hosts == nil {
		t.Error("expected All.Hosts array, got nil")
	}
	if resp.Meta.Hostvars == nil {
		t.Error("expected Meta.Hostvars map, got nil")
	}
}

// TestAdminGetInventory_ContentType verifies application/json content type.
func TestAdminGetInventory_ContentType(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)

	req := httptest.NewRequest("GET", "/api/inventory", nil)
	req.Header.Set("Authorization", "Bearer "+server.AdminToken)
	w := httptest.NewRecorder()
	AdminGetInventory(w, req)

	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("expected application/json, got %q", ct)
	}
}

// TestAdminGetInventory_OnlyConnectedParam verifies query param is accepted.
func TestAdminGetInventory_OnlyConnectedParam(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)

	req := httptest.NewRequest("GET", "/api/inventory?only_connected=true", nil)
	req.Header.Set("Authorization", "Bearer "+server.AdminToken)
	w := httptest.NewRecorder()
	AdminGetInventory(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 with only_connected=true, got %d", w.Code)
	}
}

// TestAdminGetInventory_OnlyConnectedFalse verifies only_connected=false is accepted.
func TestAdminGetInventory_OnlyConnectedFalse(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)

	req := httptest.NewRequest("GET", "/api/inventory?only_connected=false", nil)
	req.Header.Set("Authorization", "Bearer "+server.AdminToken)
	w := httptest.NewRecorder()
	AdminGetInventory(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 with only_connected=false, got %d", w.Code)
	}
	var resp InventoryResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.All.Hosts == nil {
		t.Error("expected All.Hosts array, got nil")
	}
}

// TestAdminGetInventory_InvalidOnlyConnected verifies invalid param defaults gracefully.
func TestAdminGetInventory_InvalidOnlyConnected(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)

	req := httptest.NewRequest("GET", "/api/inventory?only_connected=not-a-bool", nil)
	req.Header.Set("Authorization", "Bearer "+server.AdminToken)
	w := httptest.NewRecorder()
	AdminGetInventory(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 with invalid param, got %d", w.Code)
	}
	var resp InventoryResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.All.Hosts == nil {
		t.Error("expected valid response even with invalid query param")
	}
}

// TestAdminGetInventory_ResponseStructure verifies Ansible-compatible JSON format.
func TestAdminGetInventory_ResponseStructure(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)

	req := httptest.NewRequest("GET", "/api/inventory", nil)
	req.Header.Set("Authorization", "Bearer "+server.AdminToken)
	w := httptest.NewRecorder()
	AdminGetInventory(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	// Must be valid JSON with "all" and "_meta" keys
	var raw map[string]json.RawMessage
	if err := json.NewDecoder(w.Body).Decode(&raw); err != nil {
		t.Fatalf("response is not valid JSON: %v", err)
	}
	if _, ok := raw["all"]; !ok {
		t.Error("response missing 'all' key")
	}
	if _, ok := raw["_meta"]; !ok {
		t.Error("response missing '_meta' key")
	}
}

// TestAdminGetInventory_NoArgs verifies no query param defaults to all hosts.
func TestAdminGetInventory_NoArgs(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)

	req := httptest.NewRequest("GET", "/api/inventory", nil)
	req.Header.Set("Authorization", "Bearer "+server.AdminToken)
	w := httptest.NewRecorder()
	AdminGetInventory(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 with no params, got %d", w.Code)
	}
}

// ========================================================================
// Regression: GetInventory on port 7770 (plugin auth) still works
// ========================================================================

// TestGetInventoryRequiresPluginAuth_Regression verifies GetInventory still
// requires plugin token auth (not admin) — regression for port 7770.
func TestGetInventoryRequiresPluginAuth_Regression(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)

	// No auth header — must 401
	req := httptest.NewRequest("GET", "/api/inventory", nil)
	w := httptest.NewRecorder()
	GetInventory(w, req)

	if w.Code == http.StatusOK {
		t.Error("GetInventory must require plugin auth on port 7770")
	}
}

// TestGetInventoryAdminTokenRejected_Regression verifies that the admin token
// does NOT work on GetInventory (port 7770 requires plugin token, not admin bearer).
func TestGetInventoryAdminTokenRejected_Regression(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)

	req := httptest.NewRequest("GET", "/api/inventory", nil)
	// Admin token is not a plugin token — plugin auth should reject it
	req.Header.Set("Authorization", "Bearer "+server.AdminToken)
	req.RemoteAddr = "127.0.0.1:9999"
	w := httptest.NewRecorder()
	GetInventory(w, req)

	// requirePluginAuth looks up hash in plugin_tokens table: admin token not there → 401
	if w.Code == http.StatusOK {
		t.Error("GetInventory should reject admin token (not a plugin token)")
	}
}

// TestAdminGetInventory_PluginTokenRejected_Regression verifies that a plugin token
// does NOT work on AdminGetInventory (port 7771 requires admin bearer token).
func TestAdminGetInventory_PluginTokenRejected_Regression(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)

	// Create a real plugin token in the store
	h := sha256.Sum256([]byte("secagent_plg_regression_test"))
	tok := storage.PluginToken{
		ID:        "tok-regression-01",
		TokenHash: fmt.Sprintf("%x", h),
		Role:      "plugin",
		CreatedAt: time.Now().UTC(),
	}
	if err := s.CreatePluginToken(context.Background(), tok); err != nil {
		t.Fatalf("create plugin token: %v", err)
	}

	req := httptest.NewRequest("GET", "/api/inventory", nil)
	req.Header.Set("Authorization", "Bearer secagent_plg_regression_test")
	w := httptest.NewRecorder()
	AdminGetInventory(w, req)

	// requireAdminAuth compares token directly to ADMIN_TOKEN — plugin token != admin token → 401
	if w.Code == http.StatusOK {
		t.Error("AdminGetInventory should reject plugin token (not admin bearer)")
	}
}
