// SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"secagent-server/cmd/secagent-server/internal/storage"
	"secagent-server/cmd/secagent-server/internal/storage/storagetest"
	"secagent-server/cmd/secagent-server/internal/ws"
)

// newTestStore creates an in-memory SQLite store for testing.
func newTestStore(t *testing.T) *storage.Store {
	t.Helper()
	s, err := storagetest.OpenTemp()
	if err != nil {
		t.Fatalf("newTestStore: %v", err)
	}
	// Tests inject s via SetAdminStore/SetRegisterStore; restore the shared
	// stores from TestMain on cleanup so that later tests (and later -count
	// iterations) never see a closed database.
	prevAdmin, prevRegister := adminStore, registerStore
	t.Cleanup(func() {
		adminStore, registerStore = prevAdmin, prevRegister
		_ = s.Close()
	})
	return s
}

// useFreshStores gives the test its own in-memory store, injected as both the
// admin and register store, and restores the previous ones on cleanup. Tests
// that rely on the package-level store (instead of calling newTestStore
// themselves) use it so they are independent of execution order and can be
// replayed with -count>1.
func useFreshStores(t *testing.T) *storage.Store {
	t.Helper()
	s := newTestStore(t) // registers the cleanup that restores previous stores
	SetAdminStore(s)
	SetRegisterStore(s)
	return s
}

// adminReq builds a test request with admin auth header.
// Uses server.AdminToken (set from ADMIN_TOKEN env = "test" in tests).
func adminReq(method, path string, body interface{}) *http.Request {
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
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
	mustUnmarshal(t, w.Body.Bytes(), &result)
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
	mustUnmarshal(t, w.Body.Bytes(), &result)
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
	mustUnmarshal(t, w.Body.Bytes(), &detail)
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
	mustUnmarshal(t, w2.Body.Bytes(), &vars)
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
	mustUnmarshal(t, w4.Body.Bytes(), &vars2)
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

	req := adminReq("GET", "/api/admin/status", nil)
	w := httptest.NewRecorder()
	AdminStatus(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var body map[string]interface{}
	mustUnmarshal(t, w.Body.Bytes(), &body)

	// #178: NATS was removed, the field is gone from the contract.
	if _, present := body["nats"]; present {
		t.Errorf("the nats field must not be reported any more: %v", body["nats"])
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
	mustUnmarshal(t, w.Body.Bytes(), &body)

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
	mustUnmarshal(t, w.Body.Bytes(), &body)
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

// #233: GET /api/admin/minions/{hostname} overlays the live WebSocket state, as the list does (minions delete
// relies on it to say that the agent is connected).
func TestAdminGetMinion_StatusFollowsTheLiveConnection(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)
	ctx := context.Background()
	if _, err := s.RegisterAgent(ctx, "live-detail", "pem", "jti-live"); err != nil {
		t.Fatal(err)
	}
	get := func() string {
		req := adminReq("GET", "/api/admin/minions/live-detail", nil)
		req.SetPathValue("hostname", "live-detail")
		w := httptest.NewRecorder()
		AdminGetMinion(w, req)
		var d map[string]interface{}
		_ = json.Unmarshal(w.Body.Bytes(), &d)
		st, _ := d["status"].(string)
		return st
	}
	if st := get(); st == "connected" {
		t.Fatalf("no connection yet, status = %q", st)
	}
	ws.RegisterConnection("live-detail", &ws.AgentConnection{Hostname: "live-detail"})
	t.Cleanup(func() { ws.UnregisterConnection("live-detail") })
	if st := get(); st != "connected" {
		t.Fatalf("a live connection must show connected, got %q", st)
	}
}

// M12 (#233): the holders of the JWT are refused BEFORE the WebSocket is closed. At the moment of the first
// close the current and the previous JTI are blacklisted and the row is gone; a connection that slipped in
// meanwhile is closed again.
func TestAdminDeleteMinion_RefusesTheJWTBeforeClosingTheSocket(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)
	ctx := context.Background()
	if _, err := s.RegisterAgent(ctx, "del-order", "pem", "jti-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpdateTokenJTIUnlessRevoked(ctx, "del-order", "jti-2"); err != nil { // jti-1 becomes the previous JTI
		t.Fatal(err)
	}
	prev := closeAgentFn
	t.Cleanup(func() { closeAgentFn = prev })
	calls := 0
	closeAgentFn = func(host string, code int, reason string) bool {
		calls++
		if calls == 1 {
			for _, jti := range []string{"jti-1", "jti-2"} {
				if bl, _ := s.IsJTIBlacklisted(ctx, jti); !bl {
					t.Errorf("at the first close, %s must already be blacklisted", jti)
				}
			}
			if a, _ := s.GetAgent(ctx, "del-order"); a != nil {
				t.Errorf("at the first close the row must already be deleted: %+v", a)
			}
			// a connection slips in between the deletion and the close
			ws.RegisterConnection("del-order", &ws.AgentConnection{Hostname: "del-order"})
		}
		return true
	}
	t.Cleanup(func() { ws.UnregisterConnection("del-order") })
	req := adminReq("DELETE", "/api/admin/minions/del-order", nil)
	req.SetPathValue("hostname", "del-order")
	w := httptest.NewRecorder()
	AdminDeleteMinion(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("delete: %d %s", w.Code, w.Body.String())
	}
	if calls != 2 {
		t.Errorf("closeAgent called %d times, want 2 (a second close for the connection that slipped in)", calls)
	}
}

// B54: once the host is revoked, a failing step of the deletion closes the link with 4001 (the revoked host must
// not keep a live connection), like `minions revoke`.
func TestAdminDeleteMinion_AFailureAfterTheRevocationClosesTheLinkWith4001(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)
	ctx := context.Background()
	if _, err := s.RegisterAgent(ctx, "del-fail", "pem", "jti-f1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpdateTokenJTIUnlessRevoked(ctx, "del-fail", "jti-f2"); err != nil { // a previous JTI to blacklist
		t.Fatal(err)
	}
	s.SetWriteGuard(func() error { // the revocation passes; every write after it is refused
		if a, _ := s.GetAgent(ctx, "del-fail"); a != nil && a.Revoked {
			return storage.ErrReadOnly
		}
		return nil
	})
	t.Cleanup(func() { s.SetWriteGuard(func() error { return nil }) })
	prev := closeAgentFn
	t.Cleanup(func() { closeAgentFn = prev })
	var code int
	closeAgentFn = func(host string, c int, reason string) bool { code = c; return true }
	req := adminReq("DELETE", "/api/admin/minions/del-fail", nil)
	req.SetPathValue("hostname", "del-fail")
	w := httptest.NewRecorder()
	AdminDeleteMinion(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("a refused write after the revocation must be an error: %d %s", w.Code, w.Body.String())
	}
	if code != ws.WSCloseRevoked {
		t.Fatalf("the link must be closed with 4001, close code = %d", code)
	}
	if a, _ := s.GetAgent(ctx, "del-fail"); a == nil || !a.Revoked {
		t.Errorf("the host stays revoked until the deletion is retried: %+v", a)
	}
}
