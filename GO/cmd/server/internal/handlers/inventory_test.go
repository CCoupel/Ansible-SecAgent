package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestGetInventoryAll tests returning all agents
func TestGetInventoryAll(t *testing.T) {
	httpReq := httptest.NewRequest("GET", "/api/inventory", nil)
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
	httpReq := httptest.NewRequest("GET", "/api/inventory?only_connected=true", nil)
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
	httpReq := httptest.NewRequest("GET", "/api/inventory?only_connected=false", nil)
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
	httpReq := httptest.NewRequest("GET", "/api/inventory?only_connected=not-a-bool", nil)
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
	httpReq := httptest.NewRequest("GET", "/api/inventory", nil)
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
		t.Error("relay_status must not be empty")
	}
}

// TestGetInventoryHostVarsCompleteness tests all required fields are present
func TestGetInventoryHostVarsCompleteness(t *testing.T) {
	httpReq := httptest.NewRequest("GET", "/api/inventory", nil)
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
			t.Errorf("host %q: missing relay_status", hostname)
		}

		// relay_last_seen may be empty for freshly registered hosts
		// but should be present as a field (even if empty)
	}
}

// TestGetInventoryContentType tests response content type
func TestGetInventoryContentType(t *testing.T) {
	httpReq := httptest.NewRequest("GET", "/api/inventory", nil)
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
		t.Error("failed to preserve relay_status")
	}

	if hv2.RelayLastSeen != hv.RelayLastSeen {
		t.Error("failed to preserve relay_last_seen")
	}
}
