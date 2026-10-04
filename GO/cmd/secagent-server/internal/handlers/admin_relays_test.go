package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// helpers ─────────────────────────────────────────────────────────────────────

func adminRelayRequest(t *testing.T, method, path string, body interface{}) *httptest.ResponseRecorder {
	t.Helper()
	var buf *bytes.Buffer
	if body != nil {
		b, _ := json.Marshal(body)
		buf = bytes.NewBuffer(b)
	} else {
		buf = &bytes.Buffer{}
	}
	req := httptest.NewRequest(method, path, buf)
	req.Header.Set("Authorization", "Bearer "+server.AdminToken)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	return rr
}

func doAdminRelayRequest(t *testing.T, handler http.HandlerFunc, method, path string, body interface{}) *httptest.ResponseRecorder {
	t.Helper()
	rr := adminRelayRequest(t, method, path, body)
	var buf *bytes.Buffer
	if body != nil {
		b, _ := json.Marshal(body)
		buf = bytes.NewBuffer(b)
	} else {
		buf = &bytes.Buffer{}
	}
	req := httptest.NewRequest(method, path, buf)
	req.Header.Set("Authorization", "Bearer "+server.AdminToken)
	req.Header.Set("Content-Type", "application/json")
	handler(rr, req)
	return rr
}

// ── POST /api/admin/relays ────────────────────────────────────────────────────

func TestAdminCreateRelay_PullMode(t *testing.T) {
	rr := doAdminRelayRequest(t, AdminCreateRelay, "POST", "/api/admin/relays", map[string]interface{}{
		"relay_id":    "test-dmz1",
		"mode":        "pull",
		"description": "Test pull relay",
	})

	if rr.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp RelayCreateResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	if resp.RelayID != "test-dmz1" {
		t.Errorf("expected relay_id=test-dmz1, got %s", resp.RelayID)
	}
	if resp.Mode != "pull" {
		t.Errorf("expected mode=pull, got %s", resp.Mode)
	}
	if resp.JWTToken == "" {
		t.Error("expected jwt_token to be set for pull mode")
	}
	if resp.Status != "pending" {
		t.Errorf("expected status=pending, got %s", resp.Status)
	}
}

func TestAdminCreateRelay_PushMode(t *testing.T) {
	rr := doAdminRelayRequest(t, AdminCreateRelay, "POST", "/api/admin/relays", map[string]interface{}{
		"relay_id": "test-dmz2",
		"mode":     "push",
		"url":      "https://dmz2.example.com:7770",
		"token":    "my-relay-token",
	})

	if rr.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp RelayCreateResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	if resp.Mode != "push" {
		t.Errorf("expected mode=push, got %s", resp.Mode)
	}
	if resp.JWTToken != "" {
		t.Error("jwt_token should be empty for push mode")
	}
	if resp.URL != "https://dmz2.example.com:7770" {
		t.Errorf("unexpected url: %s", resp.URL)
	}
}

func TestAdminCreateRelay_MissingRelayID(t *testing.T) {
	rr := doAdminRelayRequest(t, AdminCreateRelay, "POST", "/api/admin/relays", map[string]interface{}{
		"mode": "pull",
	})
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestAdminCreateRelay_InvalidMode(t *testing.T) {
	rr := doAdminRelayRequest(t, AdminCreateRelay, "POST", "/api/admin/relays", map[string]interface{}{
		"relay_id": "test-relay",
		"mode":     "invalid",
	})
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestAdminCreateRelay_PushMissingURL(t *testing.T) {
	rr := doAdminRelayRequest(t, AdminCreateRelay, "POST", "/api/admin/relays", map[string]interface{}{
		"relay_id": "test-relay-push",
		"mode":     "push",
		"token":    "some-token",
		// url missing
	})
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestAdminCreateRelay_PushMissingToken(t *testing.T) {
	rr := doAdminRelayRequest(t, AdminCreateRelay, "POST", "/api/admin/relays", map[string]interface{}{
		"relay_id": "test-relay-push2",
		"mode":     "push",
		"url":      "https://relay:7770",
		// token missing
	})
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestAdminCreateRelay_DefaultModePull(t *testing.T) {
	rr := doAdminRelayRequest(t, AdminCreateRelay, "POST", "/api/admin/relays", map[string]interface{}{
		"relay_id": "test-default-mode",
		// no mode → defaults to pull
	})
	if rr.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp RelayCreateResponse
	mustUnmarshal(t, rr.Body.Bytes(), &resp)
	if resp.Mode != "pull" {
		t.Errorf("expected default mode=pull, got %s", resp.Mode)
	}
}

func TestAdminCreateRelay_Unauthorized(t *testing.T) {
	req := httptest.NewRequest("POST", "/api/admin/relays", bytes.NewBufferString(`{"relay_id":"x"}`))
	req.Header.Set("Authorization", "Bearer wrong-token")
	rr := httptest.NewRecorder()
	AdminCreateRelay(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

// ── GET /api/admin/relays ─────────────────────────────────────────────────────

func TestAdminListRelays(t *testing.T) {
	// Create a relay first
	doAdminRelayRequest(t, AdminCreateRelay, "POST", "/api/admin/relays", map[string]interface{}{
		"relay_id": "list-relay-1",
		"mode":     "pull",
	})

	rr := doAdminRelayRequest(t, AdminListRelays, "GET", "/api/admin/relays", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	relays, ok := resp["relays"].([]interface{})
	if !ok {
		t.Fatal("expected relays array in response")
	}
	// At least one relay should be present
	if len(relays) == 0 {
		t.Error("expected at least one relay in list")
	}
}

func TestAdminListRelays_Unauthorized(t *testing.T) {
	req := httptest.NewRequest("GET", "/api/admin/relays", nil)
	rr := httptest.NewRecorder()
	AdminListRelays(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

// ── GET /api/admin/relays/status ─────────────────────────────────────────────

func TestAdminRelaysStatus(t *testing.T) {
	rr := doAdminRelayRequest(t, AdminRelaysStatus, "GET", "/api/admin/relays/status", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp RelayStatusResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	if resp.Timestamp == "" {
		t.Error("expected timestamp in response")
	}
}

// ── DELETE /api/admin/relays/{id} ─────────────────────────────────────────────

func TestAdminDeleteRelay(t *testing.T) {
	// Create a relay
	rr := doAdminRelayRequest(t, AdminCreateRelay, "POST", "/api/admin/relays", map[string]interface{}{
		"relay_id": "relay-to-delete",
		"mode":     "pull",
	})
	var created RelayCreateResponse
	mustUnmarshal(t, rr.Body.Bytes(), &created)

	// Delete by ID
	req := httptest.NewRequest("DELETE", "/api/admin/relays/"+created.ID, nil)
	req.Header.Set("Authorization", "Bearer "+server.AdminToken)

	// We need to set path value since httptest doesn't use a router
	req.SetPathValue("id", created.ID)
	rr2 := httptest.NewRecorder()
	AdminDeleteRelay(rr2, req)

	if rr2.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", rr2.Code, rr2.Body.String())
	}
}

func TestAdminDeleteRelay_NotFound(t *testing.T) {
	req := httptest.NewRequest("DELETE", "/api/admin/relays/nonexistent-id", nil)
	req.Header.Set("Authorization", "Bearer "+server.AdminToken)
	req.SetPathValue("id", "nonexistent-id")
	rr := httptest.NewRecorder()
	AdminDeleteRelay(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rr.Code)
	}
}

func TestAdminDeleteRelay_Unauthorized(t *testing.T) {
	req := httptest.NewRequest("DELETE", "/api/admin/relays/some-id", nil)
	req.SetPathValue("id", "some-id")
	rr := httptest.NewRecorder()
	AdminDeleteRelay(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}
