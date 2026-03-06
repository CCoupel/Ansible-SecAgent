package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"relay-server/cmd/server/internal/storage"
)

// newTestStore creates an in-memory SQLite store for testing.
func newTestStore(t *testing.T) *storage.Store {
	t.Helper()
	s, err := storage.NewStore(":memory:")
	if err != nil {
		t.Fatalf("newTestStore: %v", err)
	}
	t.Cleanup(func() {
		s.Close()
	})
	return s
}

// adminReq builds a test request with admin auth header.
// Uses server.AdminToken (set from ADMIN_TOKEN env = "test" in tests).
func adminReq(method, path string, body interface{}) *http.Request {
	var buf bytes.Buffer
	if body != nil {
		json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Authorization", "Bearer "+server.AdminToken)
	req.Header.Set("Content-Type", "application/json")
	return req
}

// seedAgent inserts a test agent into the store.
func seedAgent(t *testing.T, s *storage.Store, hostname string) {
	t.Helper()
	ctx := context.Background()
	if err := s.UpsertAgent(ctx, hostname, "PUBKEY-PEM", "jti-"+hostname); err != nil {
		t.Fatalf("seedAgent: %v", err)
	}
}

// ========================================================================
// GET /api/admin/minions
// ========================================================================

func TestAdminListMinions_Empty(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)

	req := adminReq("GET", "/api/admin/minions", nil)
	w := httptest.NewRecorder()
	AdminListMinions(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var result []MinionSummary
	json.Unmarshal(w.Body.Bytes(), &result)
	if result == nil {
		t.Error("expected empty array, got nil")
	}
}

func TestAdminListMinions_WithAgents(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)
	seedAgent(t, s, "host-01")
	seedAgent(t, s, "host-02")

	req := adminReq("GET", "/api/admin/minions", nil)
	w := httptest.NewRecorder()
	AdminListMinions(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var result []MinionSummary
	json.Unmarshal(w.Body.Bytes(), &result)
	if len(result) < 2 {
		t.Errorf("expected at least 2 agents, got %d", len(result))
	}
}

func TestAdminListMinions_Unauthorized(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)

	req := httptest.NewRequest("GET", "/api/admin/minions", nil)
	// No auth header
	w := httptest.NewRecorder()
	AdminListMinions(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestAdminListMinions_WrongToken(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)

	req := httptest.NewRequest("GET", "/api/admin/minions", nil)
	req.Header.Set("Authorization", "Bearer wrong-token")
	w := httptest.NewRecorder()
	AdminListMinions(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

// ========================================================================
// GET /api/admin/minions/{hostname}
// ========================================================================

func TestAdminGetMinion_Found(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)
	seedAgent(t, s, "host-01")

	req := adminReq("GET", "/api/admin/minions/host-01", nil)
	req.SetPathValue("hostname", "host-01")
	w := httptest.NewRecorder()
	AdminGetMinion(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var detail MinionDetail
	json.Unmarshal(w.Body.Bytes(), &detail)
	if detail.Hostname != "host-01" {
		t.Errorf("expected hostname=host-01, got %q", detail.Hostname)
	}
	if detail.Vars == nil {
		t.Error("expected vars map, got nil")
	}
}

func TestAdminGetMinion_NotFound(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)

	req := adminReq("GET", "/api/admin/minions/nonexistent", nil)
	req.SetPathValue("hostname", "nonexistent")
	w := httptest.NewRecorder()
	AdminGetMinion(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

// ========================================================================
// POST /api/admin/minions/{hostname}/suspend
// POST /api/admin/minions/{hostname}/resume
// ========================================================================

func TestAdminSuspendResume(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)
	seedAgent(t, s, "host-01")

	// Suspend
	req := adminReq("POST", "/api/admin/minions/host-01/suspend", nil)
	req.SetPathValue("hostname", "host-01")
	w := httptest.NewRecorder()
	AdminSuspendMinion(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("suspend: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Verify suspended in DB
	susp, _ := s.IsAgentSuspended(context.Background(), "host-01")
	if !susp {
		t.Error("expected agent to be suspended after POST /suspend")
	}

	// Resume
	req2 := adminReq("POST", "/api/admin/minions/host-01/resume", nil)
	req2.SetPathValue("hostname", "host-01")
	w2 := httptest.NewRecorder()
	AdminResumeMinion(w2, req2)

	if w2.Code != http.StatusOK {
		t.Errorf("resume: expected 200, got %d: %s", w2.Code, w2.Body.String())
	}

	susp2, _ := s.IsAgentSuspended(context.Background(), "host-01")
	if susp2 {
		t.Error("expected agent to NOT be suspended after POST /resume")
	}
}

func TestAdminSuspendMinion_NotFound(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)

	req := adminReq("POST", "/api/admin/minions/ghost/suspend", nil)
	req.SetPathValue("hostname", "ghost")
	w := httptest.NewRecorder()
	AdminSuspendMinion(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

// ========================================================================
// POST /api/admin/minions/{hostname}/set-state
// ========================================================================

func TestAdminSetMinionState_Valid(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)
	seedAgent(t, s, "host-01")

	req := adminReq("POST", "/api/admin/minions/host-01/set-state", map[string]string{"status": "connected"})
	req.SetPathValue("hostname", "host-01")
	w := httptest.NewRecorder()
	AdminSetMinionState(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestAdminSetMinionState_InvalidStatus(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)
	seedAgent(t, s, "host-01")

	req := adminReq("POST", "/api/admin/minions/host-01/set-state", map[string]string{"status": "banana"})
	req.SetPathValue("hostname", "host-01")
	w := httptest.NewRecorder()
	AdminSetMinionState(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

// ========================================================================
// Vars CRUD
// ========================================================================

func TestAdminVarsCRUD(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)
	seedAgent(t, s, "host-01")

	// Set vars
	req := adminReq("POST", "/api/admin/minions/host-01/vars", map[string]interface{}{
		"ansible_user": "deploy",
		"env":          "prod",
	})
	req.SetPathValue("hostname", "host-01")
	w := httptest.NewRecorder()
	AdminSetMinionVars(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("set vars: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Get vars
	req2 := adminReq("GET", "/api/admin/minions/host-01/vars", nil)
	req2.SetPathValue("hostname", "host-01")
	w2 := httptest.NewRecorder()
	AdminGetMinionVars(w2, req2)

	if w2.Code != http.StatusOK {
		t.Errorf("get vars: expected 200, got %d", w2.Code)
	}

	var vars map[string]interface{}
	json.Unmarshal(w2.Body.Bytes(), &vars)
	if vars["ansible_user"] != "deploy" {
		t.Errorf("expected ansible_user=deploy, got %v", vars["ansible_user"])
	}
	if vars["env"] != "prod" {
		t.Errorf("expected env=prod, got %v", vars["env"])
	}

	// Delete one var
	req3 := adminReq("DELETE", "/api/admin/minions/host-01/vars/env", nil)
	req3.SetPathValue("hostname", "host-01")
	req3.SetPathValue("key", "env")
	w3 := httptest.NewRecorder()
	AdminDeleteMinionVar(w3, req3)

	if w3.Code != http.StatusOK {
		t.Errorf("delete var: expected 200, got %d: %s", w3.Code, w3.Body.String())
	}

	// Verify deletion
	req4 := adminReq("GET", "/api/admin/minions/host-01/vars", nil)
	req4.SetPathValue("hostname", "host-01")
	w4 := httptest.NewRecorder()
	AdminGetMinionVars(w4, req4)

	var vars2 map[string]interface{}
	json.Unmarshal(w4.Body.Bytes(), &vars2)
	if _, exists := vars2["env"]; exists {
		t.Error("expected 'env' key to be deleted")
	}
	if vars2["ansible_user"] != "deploy" {
		t.Error("expected 'ansible_user' to still be present after deleting 'env'")
	}
}

func TestAdminDeleteMinionVar_KeyNotFound(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)
	seedAgent(t, s, "host-01")

	req := adminReq("DELETE", "/api/admin/minions/host-01/vars/nonexistent", nil)
	req.SetPathValue("hostname", "host-01")
	req.SetPathValue("key", "nonexistent")
	w := httptest.NewRecorder()
	AdminDeleteMinionVar(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestAdminSetMinionVars_AgentNotFound(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)

	req := adminReq("POST", "/api/admin/minions/ghost/vars", map[string]interface{}{"k": "v"})
	req.SetPathValue("hostname", "ghost")
	w := httptest.NewRecorder()
	AdminSetMinionVars(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

// ========================================================================
// GET /api/admin/status
// GET /api/admin/stats
// ========================================================================

func TestAdminStatus(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)
	NATSHealthCheck = func() bool { return false }

	req := adminReq("GET", "/api/admin/status", nil)
	w := httptest.NewRecorder()
	AdminStatus(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var body map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &body)

	if body["nats"] != "unreachable" {
		t.Errorf("expected nats=unreachable, got %v", body["nats"])
	}
	if body["db"] != "ok" {
		t.Errorf("expected db=ok, got %v", body["db"])
	}
	if _, ok := body["ws_connections"]; !ok {
		t.Error("expected ws_connections field")
	}
	if _, ok := body["uptime"]; !ok {
		t.Error("expected uptime field")
	}
}

func TestAdminStatusNATSOK(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)
	NATSHealthCheck = func() bool { return true }
	defer func() { NATSHealthCheck = nil }()

	req := adminReq("GET", "/api/admin/status", nil)
	w := httptest.NewRecorder()
	AdminStatus(w, req)

	var body map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &body)
	if body["nats"] != "ok" {
		t.Errorf("expected nats=ok, got %v", body["nats"])
	}
}

func TestAdminStats(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)
	seedAgent(t, s, "host-01")
	seedAgent(t, s, "host-02")

	req := adminReq("GET", "/api/admin/stats", nil)
	w := httptest.NewRecorder()
	AdminStats(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var body map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &body)

	total, ok := body["agents_total"].(float64)
	if !ok || total < 2 {
		t.Errorf("expected agents_total >= 2, got %v", body["agents_total"])
	}
	if _, ok := body["agents_connected"]; !ok {
		t.Error("expected agents_connected field")
	}
	if _, ok := body["tasks_active"]; !ok {
		t.Error("expected tasks_active field")
	}
}

// ========================================================================
// POST /api/admin/revoke/{hostname}
// ========================================================================

func TestAdminRevokeMinion_AgentExists(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)
	seedAgent(t, s, "host-01")

	req := adminReq("POST", "/api/admin/revoke/host-01", nil)
	req.SetPathValue("hostname", "host-01")
	w := httptest.NewRecorder()
	AdminRevokeMinion(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var body map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &body)
	if body["status"] != "revoked" {
		t.Errorf("expected status=revoked, got %v", body["status"])
	}
}

func TestAdminRevokeMinion_NotFound(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)

	req := adminReq("POST", "/api/admin/revoke/ghost", nil)
	req.SetPathValue("hostname", "ghost")
	w := httptest.NewRecorder()
	AdminRevokeMinion(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}
