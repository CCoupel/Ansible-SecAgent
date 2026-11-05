// SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

// Tests pour DELETE /api/admin/minions/{hostname} — AdminDeleteMinion
// (Le handler a été déplacé depuis admin_webhooks.go vers admin.go lors de
// la Phase 11 révisée qui remplace le système webhooks par le système hooks.)

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// decodeJSON unmarshals the response body into v.
func decodeJSON(t *testing.T, w *httptest.ResponseRecorder, v interface{}) {
	t.Helper()
	if err := json.NewDecoder(w.Body).Decode(v); err != nil {
		t.Fatalf("decode JSON: %v — body: %s", err, w.Body.String())
	}
}

// ========================================================================
// DELETE /api/admin/minions/{hostname}
// ========================================================================

func TestAdminDeleteMinionOK(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)
	seedAgent(t, s, "host-to-delete")

	req := adminReq("DELETE", "/api/admin/minions/host-to-delete", nil)
	req.SetPathValue("hostname", "host-to-delete")
	w := httptest.NewRecorder()
	AdminDeleteMinion(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	decodeJSON(t, w, &resp)
	if resp["hostname"] != "host-to-delete" {
		t.Errorf("hostname: got %v", resp["hostname"])
	}
	if resp["status"] != "deleted" {
		t.Errorf("status: got %v, want deleted", resp["status"])
	}
	if _, ok := resp["ws_disconnected"]; !ok {
		t.Error("expected ws_disconnected field in response")
	}

	// Agent must be gone from DB
	got, err := s.GetAgent(context.Background(), "host-to-delete")
	if err != nil {
		t.Fatalf("GetAgent after delete: %v", err)
	}
	if got != nil {
		t.Error("expected agent to be deleted from DB")
	}
}

func TestAdminDeleteMinionNotFound(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)

	req := adminReq("DELETE", "/api/admin/minions/unknown-host", nil)
	req.SetPathValue("hostname", "unknown-host")
	w := httptest.NewRecorder()
	AdminDeleteMinion(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d — %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	decodeJSON(t, w, &resp)
	if resp["error"] != "agent_not_found" {
		t.Errorf("expected error=agent_not_found, got %v", resp["error"])
	}
}

func TestAdminDeleteMinionUnauthorized(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)

	req := httptest.NewRequest("DELETE", "/api/admin/minions/some-host", nil)
	// no Authorization header
	w := httptest.NewRecorder()
	AdminDeleteMinion(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}
