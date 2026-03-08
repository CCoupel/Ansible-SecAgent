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

	"relay-server/cmd/server/internal/storage"
)

// ========================================================================
// Helpers
// ========================================================================

// seedEnrollmentToken inserts an enrollment token directly into adminStore.
func seedEnrollmentToken(t *testing.T, id, plain, pattern string, reusable bool, expiresAt *time.Time) {
	t.Helper()
	h := sha256.Sum256([]byte(plain))
	tok := storage.EnrollmentToken{
		ID:              id,
		TokenHash:       fmt.Sprintf("%x", h),
		HostnamePattern: pattern,
		Reusable:        reusable,
		CreatedAt:       time.Now().UTC(),
		ExpiresAt:       expiresAt,
		CreatedBy:       "test",
	}
	if err := adminStore.CreateEnrollmentToken(context.Background(), tok); err != nil {
		t.Fatalf("seedEnrollmentToken: %v", err)
	}
}

// seedPluginToken inserts a plugin token directly into adminStore.
func seedPluginToken(t *testing.T, id, plain, desc, allowedIPs string) {
	t.Helper()
	h := sha256.Sum256([]byte(plain))
	tok := storage.PluginToken{
		ID:          id,
		TokenHash:   fmt.Sprintf("%x", h),
		Description: desc,
		Role:        "plugin",
		AllowedIPs:  allowedIPs,
		CreatedAt:   time.Now().UTC(),
	}
	if err := adminStore.CreatePluginToken(context.Background(), tok); err != nil {
		t.Fatalf("seedPluginToken: %v", err)
	}
}

// decodeTokenCreate parses a TokenCreateResponse from a recorder.
func decodeTokenCreate(t *testing.T, w *httptest.ResponseRecorder) TokenCreateResponse {
	t.Helper()
	var resp TokenCreateResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode TokenCreateResponse: %v — body: %s", err, w.Body.String())
	}
	return resp
}

// ========================================================================
// POST /api/admin/tokens — enrollment
// ========================================================================

func TestAdminCreateEnrollmentToken(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)

	req := adminReq("POST", "/api/admin/tokens", TokenCreateRequest{
		Role:            "enrollment",
		HostnamePattern: "vp.*",
		Reusable:        0,
	})
	w := httptest.NewRecorder()
	AdminCreateToken(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d — %s", w.Code, w.Body.String())
	}

	resp := decodeTokenCreate(t, w)
	if resp.Token == "" {
		t.Error("expected token in response")
	}
	if !startsWith(resp.Token, "relay_enr_") {
		t.Errorf("expected relay_enr_ prefix, got %q", resp.Token[:10])
	}
	if resp.ID == "" {
		t.Error("expected id in response")
	}
	if resp.Role != "enrollment" {
		t.Errorf("expected role=enrollment, got %q", resp.Role)
	}
	if resp.HostnamePattern != "vp.*" {
		t.Errorf("expected hostname_pattern=vp.*, got %q", resp.HostnamePattern)
	}
	if resp.Reusable {
		t.Error("expected reusable=false for one-shot token")
	}

	// Verify stored in DB (by hash)
	h := sha256.Sum256([]byte(resp.Token))
	stored, err := adminStore.GetEnrollmentTokenByHash(context.Background(), fmt.Sprintf("%x", h))
	if err != nil || stored == nil {
		t.Fatalf("expected token in DB: %v", err)
	}
	if stored.HostnamePattern != "vp.*" {
		t.Errorf("DB hostname_pattern: got %q", stored.HostnamePattern)
	}
}

func TestAdminCreateEnrollmentTokenPermanent(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)

	future := time.Now().UTC().Add(30 * 24 * time.Hour).Format(time.RFC3339)
	req := adminReq("POST", "/api/admin/tokens", TokenCreateRequest{
		Role:            "enrollment",
		HostnamePattern: "qualif-host-[0-9]+",
		Reusable:        1,
		ExpiresAt:       future,
	})
	w := httptest.NewRecorder()
	AdminCreateToken(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d — %s", w.Code, w.Body.String())
	}

	resp := decodeTokenCreate(t, w)
	if !resp.Reusable {
		t.Error("expected reusable=true")
	}
	if resp.ExpiresAt == "" {
		t.Error("expected expires_at in response")
	}
}

func TestAdminCreateEnrollmentTokenMissingPattern(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)

	req := adminReq("POST", "/api/admin/tokens", TokenCreateRequest{
		Role: "enrollment",
		// no hostname_pattern
	})
	w := httptest.NewRecorder()
	AdminCreateToken(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

// ========================================================================
// POST /api/admin/tokens — plugin
// ========================================================================

func TestAdminCreatePluginToken(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)

	req := adminReq("POST", "/api/admin/tokens", TokenCreateRequest{
		Role:                   "plugin",
		Description:            "ansible-control-prod",
		AllowedIPs:             "192.168.1.0/24,10.0.0.0/8",
		AllowedHostnamePattern: "ansible-control-[0-9]+",
	})
	w := httptest.NewRecorder()
	AdminCreateToken(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d — %s", w.Code, w.Body.String())
	}

	resp := decodeTokenCreate(t, w)
	if !startsWith(resp.Token, "relay_plg_") {
		t.Errorf("expected relay_plg_ prefix, got %q", resp.Token[:10])
	}
	if resp.Role != "plugin" {
		t.Errorf("expected role=plugin, got %q", resp.Role)
	}
	if resp.Description != "ansible-control-prod" {
		t.Errorf("description: got %q", resp.Description)
	}
	if resp.AllowedIPs != "192.168.1.0/24,10.0.0.0/8" {
		t.Errorf("allowed_ips: got %q", resp.AllowedIPs)
	}

	// Verify stored in DB
	h := sha256.Sum256([]byte(resp.Token))
	stored, err := adminStore.GetPluginTokenByHash(context.Background(), fmt.Sprintf("%x", h))
	if err != nil || stored == nil {
		t.Fatalf("expected plugin token in DB: %v", err)
	}
	if stored.Description != "ansible-control-prod" {
		t.Errorf("DB description: got %q", stored.Description)
	}
}

func TestAdminCreatePluginTokenNoRestrictions(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)

	req := adminReq("POST", "/api/admin/tokens", TokenCreateRequest{
		Role:        "plugin",
		Description: "dev-token",
	})
	w := httptest.NewRecorder()
	AdminCreateToken(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d — %s", w.Code, w.Body.String())
	}

	resp := decodeTokenCreate(t, w)
	if resp.AllowedIPs != "" {
		t.Errorf("expected empty allowed_ips, got %q", resp.AllowedIPs)
	}
}

func TestAdminCreateTokenInvalidRole(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)

	req := adminReq("POST", "/api/admin/tokens", TokenCreateRequest{Role: "admin"})
	w := httptest.NewRecorder()
	AdminCreateToken(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestAdminCreateTokenInvalidExpiresAt(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)

	req := adminReq("POST", "/api/admin/tokens", TokenCreateRequest{
		Role:            "enrollment",
		HostnamePattern: "vp.*",
		ExpiresAt:       "not-a-date",
	})
	w := httptest.NewRecorder()
	AdminCreateToken(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestAdminCreateTokenUnauthorized(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)

	req := httptest.NewRequest("POST", "/api/admin/tokens", nil)
	w := httptest.NewRecorder()
	AdminCreateToken(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

// ========================================================================
// GET /api/admin/tokens
// ========================================================================

func TestAdminListTokensAll(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)

	seedEnrollmentToken(t, "e-list-01", "enr-list-01", "vp.*", false, nil)
	seedEnrollmentToken(t, "e-list-02", "enr-list-02", "web.*", true, nil)
	seedPluginToken(t, "p-list-01", "plg-list-01", "dev", "")
	seedPluginToken(t, "p-list-02", "plg-list-02", "prod", "10.0.0.0/8")

	req := adminReq("GET", "/api/admin/tokens", nil)
	w := httptest.NewRecorder()
	AdminListTokens(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — %s", w.Code, w.Body.String())
	}

	var result []interface{}
	json.Unmarshal(w.Body.Bytes(), &result)
	if len(result) < 4 {
		t.Errorf("expected at least 4 tokens, got %d", len(result))
	}
}

func TestAdminListTokensFilterEnrollment(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)

	seedEnrollmentToken(t, "e-filt-01", "enr-filt-01", "vp.*", false, nil)
	seedPluginToken(t, "p-filt-01", "plg-filt-01", "dev", "")

	req := adminReq("GET", "/api/admin/tokens?role=enrollment", nil)
	w := httptest.NewRecorder()
	AdminListTokens(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	// Parse as array of maps
	var result []map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &result)

	for _, item := range result {
		if item["role"] != "enrollment" {
			t.Errorf("expected only enrollment tokens, got role=%v", item["role"])
		}
	}
}

func TestAdminListTokensFilterPlugin(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)

	seedEnrollmentToken(t, "e-fp-01", "enr-fp-01", "vp.*", false, nil)
	seedPluginToken(t, "p-fp-01", "plg-fp-01", "dev", "")

	req := adminReq("GET", "/api/admin/tokens?role=plugin", nil)
	w := httptest.NewRecorder()
	AdminListTokens(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var result []map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &result)

	for _, item := range result {
		if item["role"] != "plugin" {
			t.Errorf("expected only plugin tokens, got role=%v", item["role"])
		}
	}
}

func TestAdminListTokensEmpty(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)

	req := adminReq("GET", "/api/admin/tokens", nil)
	w := httptest.NewRecorder()
	AdminListTokens(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var result []interface{}
	json.Unmarshal(w.Body.Bytes(), &result)
	if len(result) != 0 {
		t.Errorf("expected empty list, got %d", len(result))
	}
}

func TestAdminListTokensNoPlaintext(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)

	// Create a token via the endpoint (which returns plain text)
	createReq := adminReq("POST", "/api/admin/tokens", TokenCreateRequest{
		Role:            "enrollment",
		HostnamePattern: "vp.*",
	})
	cw := httptest.NewRecorder()
	AdminCreateToken(cw, createReq)
	resp := decodeTokenCreate(t, cw)
	plainToken := resp.Token

	// List — must NOT contain the plain token
	listReq := adminReq("GET", "/api/admin/tokens?role=enrollment", nil)
	lw := httptest.NewRecorder()
	AdminListTokens(lw, listReq)

	body := lw.Body.String()
	if contains(body, plainToken) {
		t.Error("list response must NOT contain plain token text")
	}
	// Must contain hash prefix
	h := sha256.Sum256([]byte(plainToken))
	hashHex := fmt.Sprintf("%x", h)
	if !contains(body, hashHex[:16]) { // check first 16 chars of hash
		t.Error("list response should contain token_hash")
	}
}

func TestAdminListTokensInvalidRole(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)

	req := adminReq("GET", "/api/admin/tokens?role=admin", nil)
	w := httptest.NewRecorder()
	AdminListTokens(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

// ========================================================================
// POST /api/admin/tokens/{id}/revoke
// ========================================================================

func TestAdminRevokePluginToken(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)
	seedPluginToken(t, "p-rev-01", "plg-rev-01", "revocable", "")

	req := adminReq("POST", "/api/admin/tokens/p-rev-01/revoke", nil)
	req.SetPathValue("id", "p-rev-01")
	w := httptest.NewRecorder()
	AdminRevokeToken(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — %s", w.Code, w.Body.String())
	}

	var body map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &body)
	if body["revoked"] != true {
		t.Errorf("expected revoked=true, got %v", body["revoked"])
	}
	if body["id"] != "p-rev-01" {
		t.Errorf("expected id=p-rev-01, got %v", body["id"])
	}

	// Verify revoked in DB
	tok, _ := adminStore.GetPluginTokenByID(context.Background(), "p-rev-01")
	if tok == nil || !tok.Revoked {
		t.Error("expected token to be revoked in DB")
	}
}

func TestAdminRevokeEnrollmentTokenReturnsBadRequest(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)
	seedEnrollmentToken(t, "e-rev-01", "enr-rev-01", "vp.*", false, nil)

	req := adminReq("POST", "/api/admin/tokens/e-rev-01/revoke", nil)
	req.SetPathValue("id", "e-rev-01")
	w := httptest.NewRecorder()
	AdminRevokeToken(w, req)

	// Enrollment tokens must use DELETE, not revoke
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for enrollment token revoke, got %d", w.Code)
	}
}

func TestAdminRevokeTokenNotFound(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)

	req := adminReq("POST", "/api/admin/tokens/nonexistent/revoke", nil)
	req.SetPathValue("id", "nonexistent")
	w := httptest.NewRecorder()
	AdminRevokeToken(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

// ========================================================================
// DELETE /api/admin/tokens/{id}
// ========================================================================

func TestAdminDeleteEnrollmentToken(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)
	seedEnrollmentToken(t, "e-del-01", "enr-del-01", "vp.*", false, nil)

	req := adminReq("DELETE", "/api/admin/tokens/e-del-01", nil)
	req.SetPathValue("id", "e-del-01")
	w := httptest.NewRecorder()
	AdminDeleteToken(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — %s", w.Code, w.Body.String())
	}

	var body map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &body)
	if body["deleted"] != true {
		t.Errorf("expected deleted=true, got %v", body["deleted"])
	}

	// Verify gone from DB
	tok, _ := adminStore.GetEnrollmentTokenByID(context.Background(), "e-del-01")
	if tok != nil {
		t.Error("expected token to be deleted from DB")
	}
}

func TestAdminDeletePluginToken(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)
	seedPluginToken(t, "p-del-01", "plg-del-01", "deletable", "")

	req := adminReq("DELETE", "/api/admin/tokens/p-del-01", nil)
	req.SetPathValue("id", "p-del-01")
	w := httptest.NewRecorder()
	AdminDeleteToken(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — %s", w.Code, w.Body.String())
	}

	// Verify gone
	tok, _ := adminStore.GetPluginTokenByID(context.Background(), "p-del-01")
	if tok != nil {
		t.Error("expected plugin token to be deleted from DB")
	}
}

func TestAdminDeleteTokenNotFound(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)

	req := adminReq("DELETE", "/api/admin/tokens/nonexistent", nil)
	req.SetPathValue("id", "nonexistent")
	w := httptest.NewRecorder()
	AdminDeleteToken(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

// ========================================================================
// POST /api/admin/tokens/purge
// ========================================================================

func TestAdminPurgeTokensExpired(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)

	past := time.Now().UTC().Add(-time.Hour)
	future := time.Now().UTC().Add(time.Hour)

	seedEnrollmentToken(t, "e-purge-exp-01", "enr-purge-exp-01", "vp.*", false, &past)
	seedEnrollmentToken(t, "e-purge-exp-02", "enr-purge-exp-02", "web.*", false, &future)
	seedEnrollmentToken(t, "e-purge-exp-03", "enr-purge-exp-03", "db.*", false, nil) // no expiry

	req := adminReq("POST", "/api/admin/tokens/purge?expired=1", nil)
	w := httptest.NewRecorder()
	AdminPurgeTokens(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — %s", w.Code, w.Body.String())
	}

	var resp PurgeResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.DeletedCount != 1 {
		t.Errorf("expected 1 deleted, got %d", resp.DeletedCount)
	}

	// Expired token gone
	tok, _ := adminStore.GetEnrollmentTokenByID(context.Background(), "e-purge-exp-01")
	if tok != nil {
		t.Error("expected expired token to be purged")
	}

	// Future token remains
	tok2, _ := adminStore.GetEnrollmentTokenByID(context.Background(), "e-purge-exp-02")
	if tok2 == nil {
		t.Error("expected future token to remain")
	}
}

func TestAdminPurgeTokensUsed(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)

	seedEnrollmentToken(t, "e-purge-used-01", "enr-purge-used-01", "vp.*", false, nil)
	seedEnrollmentToken(t, "e-purge-used-02", "enr-purge-used-02", "web.*", false, nil)
	seedEnrollmentToken(t, "e-purge-perm-01", "enr-purge-perm-01", "db.*", true, nil) // reusable

	// Consume one-shot token
	if err := adminStore.ConsumeEnrollmentToken(context.Background(), "e-purge-used-01"); err != nil {
		t.Fatalf("ConsumeEnrollmentToken: %v", err)
	}
	// Consume reusable token (must NOT be purged)
	if err := adminStore.ConsumeEnrollmentToken(context.Background(), "e-purge-perm-01"); err != nil {
		t.Fatalf("ConsumeEnrollmentToken reusable: %v", err)
	}

	req := adminReq("POST", "/api/admin/tokens/purge?used=1", nil)
	w := httptest.NewRecorder()
	AdminPurgeTokens(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — %s", w.Code, w.Body.String())
	}

	var resp PurgeResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.DeletedCount != 1 {
		t.Errorf("expected 1 deleted, got %d", resp.DeletedCount)
	}

	// Consumed one-shot gone
	tok, _ := adminStore.GetEnrollmentTokenByID(context.Background(), "e-purge-used-01")
	if tok != nil {
		t.Error("expected consumed one-shot to be purged")
	}

	// Fresh one-shot remains
	tok2, _ := adminStore.GetEnrollmentTokenByID(context.Background(), "e-purge-used-02")
	if tok2 == nil {
		t.Error("expected fresh one-shot to remain")
	}

	// Reusable remains
	tok3, _ := adminStore.GetEnrollmentTokenByID(context.Background(), "e-purge-perm-01")
	if tok3 == nil {
		t.Error("expected reusable token to remain")
	}
}

func TestAdminPurgeTokensBoth(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)

	past := time.Now().UTC().Add(-time.Hour)

	seedEnrollmentToken(t, "e-both-exp", "enr-both-exp", "vp.*", false, &past)
	seedEnrollmentToken(t, "e-both-used", "enr-both-used", "web.*", false, nil)
	seedEnrollmentToken(t, "e-both-ok", "enr-both-ok", "db.*", false, nil)

	// Consume one-shot
	if err := adminStore.ConsumeEnrollmentToken(context.Background(), "e-both-used"); err != nil {
		t.Fatalf("ConsumeEnrollmentToken: %v", err)
	}

	req := adminReq("POST", "/api/admin/tokens/purge?expired=1&used=1", nil)
	w := httptest.NewRecorder()
	AdminPurgeTokens(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — %s", w.Code, w.Body.String())
	}

	var resp PurgeResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.DeletedCount != 2 {
		t.Errorf("expected 2 deleted (1 expired + 1 used), got %d", resp.DeletedCount)
	}
}

func TestAdminPurgeTokensNoParams(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)

	req := adminReq("POST", "/api/admin/tokens/purge", nil)
	w := httptest.NewRecorder()
	AdminPurgeTokens(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for no params, got %d", w.Code)
	}
}

func TestAdminPurgeTokensPurgedAtPresent(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)

	req := adminReq("POST", "/api/admin/tokens/purge?expired=1", nil)
	w := httptest.NewRecorder()
	AdminPurgeTokens(w, req)

	var resp PurgeResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.PurgedAt == "" {
		t.Error("expected purged_at timestamp in response")
	}
}

// ========================================================================
// Internal helpers
// ========================================================================

func startsWith(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

func contains(s, sub string) bool {
	return len(sub) > 0 && len(s) >= len(sub) &&
		func() bool {
			for i := 0; i <= len(s)-len(sub); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
			return false
		}()
}
