package handlers

// ========================================================================
// E2E Token Workflows — Phase 10 (SECURITY.md §3 + §6)
//
// These tests exercise complete end-to-end flows, chaining admin operations
// with the actual enrollment and plugin auth handlers, verifying the full
// lifecycle in a single test:
//
//   Enrollment E2E:
//     AdminCreateToken → doPhase1 → doPhase2 → decrypt JWT → verify DB state
//
//   Plugin E2E:
//     AdminCreateToken → call handler with token → verify audit logged
//     AdminRevokeToken → call handler → verify 403
//     AdminDeleteToken → call handler → verify 403 (not found)
// ========================================================================

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// ========================================================================
// E2E: Enrollment token full lifecycle
// ========================================================================

// TestE2EEnrollmentTokenOneShotFullWorkflow tests the complete lifecycle:
// admin creates token → agent uses it once (2-phase) → JWT decryptable →
// use_count == 1 → second attempt rejected.
func TestE2EEnrollmentTokenOneShotFullWorkflow(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)
	SetRegisterStore(s)

	// Step 1: admin creates an enrollment token via API
	createReq := adminReq("POST", "/api/admin/tokens", TokenCreateRequest{
		Role:            "enrollment",
		HostnamePattern: "e2e-host-01",
		Reusable:        0,
	})
	cw := httptest.NewRecorder()
	AdminCreateToken(cw, createReq)

	if cw.Code != http.StatusCreated {
		t.Fatalf("AdminCreateToken: expected 201, got %d — %s", cw.Code, cw.Body.String())
	}

	var createResp TokenCreateResponse
	if err := json.NewDecoder(cw.Body).Decode(&createResp); err != nil {
		t.Fatalf("decode TokenCreateResponse: %v", err)
	}
	tokenPlain := createResp.Token
	tokenID := createResp.ID

	if tokenPlain == "" || len(tokenPlain) < 10 {
		t.Fatal("expected non-empty token in create response")
	}
	if tokenID == "" {
		t.Fatal("expected non-empty id in create response")
	}

	// Verify token is stored (by hash) but plain text is NOT in DB
	h := sha256.Sum256([]byte(tokenPlain))
	hashHex := fmt.Sprintf("%x", h)
	stored, err := s.GetEnrollmentTokenByHash(context.Background(), hashHex)
	if err != nil {
		t.Fatalf("GetEnrollmentTokenByHash: %v", err)
	}
	if stored == nil {
		t.Fatal("token not found in DB after AdminCreateToken")
	}
	if stored.UseCount != 0 {
		t.Errorf("expected use_count=0 before enrollment, got %d", stored.UseCount)
	}

	// Step 2: agent generates RSA keypair and runs phase-1 enrollment
	agentPrivKey, agentPubPEM := genRSAPubPEM(t, 4096)

	code1, cr := doPhase1(t, "e2e-host-01", agentPubPEM, tokenPlain)
	if code1 != http.StatusOK {
		t.Fatalf("phase-1: expected 200, got %d", code1)
	}
	if cr == nil || cr.Challenge == "" {
		t.Fatal("expected challenge in phase-1 response")
	}

	// Step 3: agent decrypts challenge, builds response, sends phase-2
	challengeResp := buildChallengeResponse(t, cr, agentPrivKey, tokenPlain)
	code2, regResp := doPhase2(t, "e2e-host-01", agentPubPEM, tokenPlain, challengeResp)
	if code2 != http.StatusOK {
		t.Fatalf("phase-2: expected 200, got %d", code2)
	}
	if regResp == nil || regResp.TokenEncrypted == "" {
		t.Fatal("expected token_encrypted in phase-2 response")
	}

	// Step 4: agent decrypts JWT with its private key
	ciphertext, err := base64.StdEncoding.DecodeString(regResp.TokenEncrypted)
	if err != nil {
		t.Fatalf("decode token_encrypted: %v", err)
	}
	jwtBytes, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, agentPrivKey, ciphertext, nil)
	if err != nil {
		t.Fatalf("decrypt JWT with agent private key: %v", err)
	}
	jwtStr := string(jwtBytes)
	if len(jwtStr) < 3 || jwtStr[:3] != "eyJ" {
		t.Errorf("decrypted JWT looks invalid: %q", jwtStr[:min(20, len(jwtStr))])
	}

	// Step 5: verify DB state — use_count == 1, last_used_at set
	updated, err := s.GetEnrollmentTokenByID(context.Background(), tokenID)
	if err != nil {
		t.Fatalf("GetEnrollmentTokenByID after enrollment: %v", err)
	}
	if updated.UseCount != 1 {
		t.Errorf("expected use_count=1 after enrollment, got %d", updated.UseCount)
	}
	if updated.LastUsedAt == nil {
		t.Error("expected last_used_at to be set after enrollment")
	}

	// Step 6: second enrollment attempt must be rejected (one-shot consumed)
	code3, _ := doPhase1(t, "e2e-host-01", agentPubPEM, tokenPlain)
	if code3 != http.StatusForbidden {
		t.Errorf("second enrollment: expected 403 (token_already_used), got %d", code3)
	}
}

// TestE2EEnrollmentTokenPermanentMultipleAgents tests the permanent token path:
// admin creates reusable token → two different agents enroll → both succeed →
// use_count == 2 → token still valid.
func TestE2EEnrollmentTokenPermanentMultipleAgents(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)
	SetRegisterStore(s)

	createReq := adminReq("POST", "/api/admin/tokens", TokenCreateRequest{
		Role:            "enrollment",
		HostnamePattern: "e2e-fleet-.*",
		Reusable:        1,
	})
	cw := httptest.NewRecorder()
	AdminCreateToken(cw, createReq)

	if cw.Code != http.StatusCreated {
		t.Fatalf("AdminCreateToken: expected 201, got %d", cw.Code)
	}
	var createResp TokenCreateResponse
	json.NewDecoder(cw.Body).Decode(&createResp)
	tokenPlain := createResp.Token
	tokenID := createResp.ID

	// Agent A enrolls
	keyA, pubPEMA := genRSAPubPEM(t, 4096)
	codeA, _ := fullEnrollment(t, "e2e-fleet-a", tokenPlain, keyA, pubPEMA)
	if codeA != http.StatusOK {
		t.Fatalf("agent-a enrollment: expected 200, got %d", codeA)
	}

	// Agent B enrolls with same token
	keyB, pubPEMB := genRSAPubPEM(t, 4096)
	codeB, _ := fullEnrollment(t, "e2e-fleet-b", tokenPlain, keyB, pubPEMB)
	if codeB != http.StatusOK {
		t.Fatalf("agent-b enrollment: expected 200, got %d", codeB)
	}

	// use_count should be 2
	tok, _ := s.GetEnrollmentTokenByID(context.Background(), tokenID)
	if tok.UseCount != 2 {
		t.Errorf("expected use_count=2, got %d", tok.UseCount)
	}

	// Token still valid — agent C can enroll
	keyC, pubPEMC := genRSAPubPEM(t, 4096)
	codeC, _ := fullEnrollment(t, "e2e-fleet-c", tokenPlain, keyC, pubPEMC)
	if codeC != http.StatusOK {
		t.Fatalf("agent-c enrollment with permanent token: expected 200, got %d", codeC)
	}

	tok2, _ := s.GetEnrollmentTokenByID(context.Background(), tokenID)
	if tok2.UseCount != 3 {
		t.Errorf("expected use_count=3, got %d", tok2.UseCount)
	}
}

// TestE2EEnrollmentTokenExpiredAtCreation tests admin creates an already-expired token
// (past expires_at) → agent is immediately rejected.
func TestE2EEnrollmentTokenExpiredAtCreation(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)
	SetRegisterStore(s)

	// Create token with past expiry
	past := time.Now().UTC().Add(-time.Hour).Format(time.RFC3339)
	createReq := adminReq("POST", "/api/admin/tokens", TokenCreateRequest{
		Role:            "enrollment",
		HostnamePattern: "e2e-expired-01",
		ExpiresAt:       past,
	})
	cw := httptest.NewRecorder()
	AdminCreateToken(cw, createReq)

	if cw.Code != http.StatusCreated {
		t.Fatalf("AdminCreateToken: expected 201, got %d — %s", cw.Code, cw.Body.String())
	}
	var createResp TokenCreateResponse
	json.NewDecoder(cw.Body).Decode(&createResp)
	tokenPlain := createResp.Token

	// Agent tries to enroll — must be rejected immediately
	_, agentPubPEM := genRSAPubPEM(t, 2048)
	code, _ := doPhase1(t, "e2e-expired-01", agentPubPEM, tokenPlain)
	if code != http.StatusForbidden {
		t.Errorf("expired token: expected 403, got %d", code)
	}
}

// TestE2EEnrollmentTokenDeletedMidFlow tests that deleting a token between phase-1 and
// phase-2 causes phase-2 to fail.
func TestE2EEnrollmentTokenDeletedMidFlow(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)
	SetRegisterStore(s)

	createReq := adminReq("POST", "/api/admin/tokens", TokenCreateRequest{
		Role:            "enrollment",
		HostnamePattern: "e2e-deleted-mid-01",
	})
	cw := httptest.NewRecorder()
	AdminCreateToken(cw, createReq)
	var createResp TokenCreateResponse
	json.NewDecoder(cw.Body).Decode(&createResp)
	tokenPlain := createResp.Token
	tokenID := createResp.ID

	_, agentPubPEM := genRSAPubPEM(t, 4096)
	agentPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	_ = agentPrivKey

	// Phase 1 succeeds
	code1, cr := doPhase1(t, "e2e-deleted-mid-01", agentPubPEM, tokenPlain)
	if code1 != http.StatusOK || cr == nil {
		t.Fatalf("phase-1 expected 200, got %d", code1)
	}

	// Admin deletes the token mid-flow
	delReq := adminReq("DELETE", "/api/admin/tokens/"+tokenID, nil)
	delReq.SetPathValue("id", tokenID)
	dw := httptest.NewRecorder()
	AdminDeleteToken(dw, delReq)
	if dw.Code != http.StatusOK {
		t.Fatalf("AdminDeleteToken: expected 200, got %d", dw.Code)
	}

	// Phase 2 must fail — token no longer exists
	serverPubKey := &server.PrivateKey.PublicKey
	dummy := make([]byte, 16)
	rand.Read(dummy)
	encrypted, _ := rsa.EncryptOAEP(sha256.New(), rand.Reader, serverPubKey, dummy, nil)
	badResp := base64.StdEncoding.EncodeToString(encrypted)

	code2, _ := doPhase2(t, "e2e-deleted-mid-01", agentPubPEM, tokenPlain, badResp)
	if code2 != http.StatusForbidden {
		t.Errorf("phase-2 after delete: expected 403, got %d", code2)
	}
}

// TestE2EEnrollmentTokenAdminListShowsUpdatedUseCount verifies that after enrollment,
// the admin list endpoint reflects the updated use_count.
func TestE2EEnrollmentTokenAdminListShowsUpdatedUseCount(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)
	SetRegisterStore(s)

	createReq := adminReq("POST", "/api/admin/tokens", TokenCreateRequest{
		Role:            "enrollment",
		HostnamePattern: "e2e-list-count-host-.*",
		Reusable:        1,
	})
	cw := httptest.NewRecorder()
	AdminCreateToken(cw, createReq)
	var createResp TokenCreateResponse
	json.NewDecoder(cw.Body).Decode(&createResp)
	tokenPlain := createResp.Token

	// Enroll twice
	for i := 0; i < 2; i++ {
		key, pubPEM := genRSAPubPEM(t, 4096)
		hostname := fmt.Sprintf("e2e-list-count-host-%02d", i)
		code, _ := fullEnrollment(t, hostname, tokenPlain, key, pubPEM)
		if code != http.StatusOK {
			t.Fatalf("enrollment %d: expected 200, got %d", i, code)
		}
	}

	// List tokens via admin API
	listReq := adminReq("GET", "/api/admin/tokens?role=enrollment", nil)
	lw := httptest.NewRecorder()
	AdminListTokens(lw, listReq)

	if lw.Code != http.StatusOK {
		t.Fatalf("AdminListTokens: expected 200, got %d", lw.Code)
	}

	var result []map[string]interface{}
	json.NewDecoder(lw.Body).Decode(&result)

	// Find our token by hostname_pattern
	found := false
	for _, item := range result {
		if item["hostname_pattern"] == "e2e-list-count-host-.*" {
			found = true
			useCount, _ := item["use_count"].(float64)
			if int(useCount) != 2 {
				t.Errorf("list shows use_count=%v, expected 2", item["use_count"])
			}
			lastUsedAt, _ := item["last_used_at"].(string)
			if lastUsedAt == "" {
				t.Error("list should show last_used_at after enrollment")
			}
			break
		}
	}
	if !found {
		t.Error("token not found in list response")
	}
}

// TestE2EEnrollmentTokenPurgeAfterUse tests the full purge workflow:
// create → use → purge --used → token gone.
func TestE2EEnrollmentTokenPurgeAfterUse(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)
	SetRegisterStore(s)

	// Create two tokens
	createAndGetPlain := func(t *testing.T, pattern string) (string, string) {
		t.Helper()
		req := adminReq("POST", "/api/admin/tokens", TokenCreateRequest{
			Role:            "enrollment",
			HostnamePattern: pattern,
		})
		w := httptest.NewRecorder()
		AdminCreateToken(w, req)
		var resp TokenCreateResponse
		json.NewDecoder(w.Body).Decode(&resp)
		return resp.Token, resp.ID
	}

	tokenA, idA := createAndGetPlain(t, "e2e-purge-a")
	tokenB, _ := createAndGetPlain(t, "e2e-purge-b")
	_ = tokenB

	// Use token A (one-shot)
	keyA, pubPEMA := genRSAPubPEM(t, 4096)
	codeA, _ := fullEnrollment(t, "e2e-purge-a", tokenA, keyA, pubPEMA)
	if codeA != http.StatusOK {
		t.Fatalf("enrollment token A: expected 200, got %d", codeA)
	}

	// Purge used one-shots
	purgeReq := adminReq("POST", "/api/admin/tokens/purge?used=1", nil)
	pw := httptest.NewRecorder()
	AdminPurgeTokens(pw, purgeReq)

	if pw.Code != http.StatusOK {
		t.Fatalf("AdminPurgeTokens: expected 200, got %d — %s", pw.Code, pw.Body.String())
	}

	var purgeResp PurgeResponse
	json.NewDecoder(pw.Body).Decode(&purgeResp)
	if purgeResp.DeletedCount < 1 {
		t.Errorf("expected at least 1 deleted, got %d", purgeResp.DeletedCount)
	}

	// Token A must be gone
	tokA, _ := s.GetEnrollmentTokenByID(context.Background(), idA)
	if tokA != nil {
		t.Error("token A should be purged after use")
	}

	// Token B (unused) must remain
	h := sha256.Sum256([]byte(tokenB))
	tokB, _ := s.GetEnrollmentTokenByHash(context.Background(), fmt.Sprintf("%x", h))
	if tokB == nil {
		t.Error("token B (unused) should remain after purge --used")
	}
}

// ========================================================================
// E2E: Plugin token full lifecycle
// ========================================================================

// TestE2EPluginTokenCreateAndUse tests the complete plugin token lifecycle:
// admin creates token → plugin calls /api/inventory → 200 → audit logged.
func TestE2EPluginTokenCreateAndUse(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)

	// Step 1: admin creates plugin token
	createReq := adminReq("POST", "/api/admin/tokens", TokenCreateRequest{
		Role:        "plugin",
		Description: "e2e-ansible-control",
		AllowedIPs:  "10.0.0.0/8",
	})
	cw := httptest.NewRecorder()
	AdminCreateToken(cw, createReq)

	if cw.Code != http.StatusCreated {
		t.Fatalf("AdminCreateToken plugin: expected 201, got %d — %s", cw.Code, cw.Body.String())
	}

	var createResp TokenCreateResponse
	json.NewDecoder(cw.Body).Decode(&createResp)
	tokenPlain := createResp.Token
	tokenID := createResp.ID

	if !startsWith(tokenPlain, "relay_plg_") {
		t.Errorf("expected relay_plg_ prefix, got %q", tokenPlain[:10])
	}

	// Step 2: plugin calls /api/inventory with valid token and allowed IP
	invReq := httptest.NewRequest("GET", "/api/inventory", nil)
	invReq.Header.Set("Authorization", "Bearer "+tokenPlain)
	invReq.RemoteAddr = "10.5.6.7:443" // inside 10.0.0.0/8
	iw := httptest.NewRecorder()
	GetInventory(iw, invReq)

	if iw.Code != http.StatusOK {
		t.Errorf("GetInventory with valid plugin token: expected 200, got %d — %s", iw.Code, iw.Body.String())
	}

	// Step 3: verify audit — last_used_at and last_used_ip set
	tok, err := s.GetPluginTokenByID(context.Background(), tokenID)
	if err != nil {
		t.Fatalf("GetPluginTokenByID: %v", err)
	}
	if tok.LastUsedAt == nil {
		t.Error("expected last_used_at to be set after plugin call")
	}
	if tok.LastUsedIP != "10.5.6.7" {
		t.Errorf("last_used_ip: got %q, want %q", tok.LastUsedIP, "10.5.6.7")
	}
}

// TestE2EPluginTokenRevokeAndReject tests: admin creates token → plugin uses it (OK) →
// admin revokes → plugin is rejected.
func TestE2EPluginTokenRevokeAndReject(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)

	// Create token
	createReq := adminReq("POST", "/api/admin/tokens", TokenCreateRequest{
		Role:        "plugin",
		Description: "e2e-revoke-test",
	})
	cw := httptest.NewRecorder()
	AdminCreateToken(cw, createReq)
	var createResp TokenCreateResponse
	json.NewDecoder(cw.Body).Decode(&createResp)
	tokenPlain := createResp.Token
	tokenID := createResp.ID

	// First use — must succeed
	req1 := httptest.NewRequest("GET", "/api/inventory", nil)
	req1.Header.Set("Authorization", "Bearer "+tokenPlain)
	req1.RemoteAddr = "10.0.0.1:80"
	w1 := httptest.NewRecorder()
	GetInventory(w1, req1)
	if w1.Code != http.StatusOK {
		t.Fatalf("first use: expected 200, got %d", w1.Code)
	}

	// Admin revokes the token
	revokeReq := adminReq("POST", "/api/admin/tokens/"+tokenID+"/revoke", nil)
	revokeReq.SetPathValue("id", tokenID)
	rw := httptest.NewRecorder()
	AdminRevokeToken(rw, revokeReq)
	if rw.Code != http.StatusOK {
		t.Fatalf("AdminRevokeToken: expected 200, got %d — %s", rw.Code, rw.Body.String())
	}

	// Second use — must be rejected (token_revoked)
	req2 := httptest.NewRequest("GET", "/api/inventory", nil)
	req2.Header.Set("Authorization", "Bearer "+tokenPlain)
	req2.RemoteAddr = "10.0.0.1:80"
	w2 := httptest.NewRecorder()
	GetInventory(w2, req2)

	if w2.Code != http.StatusForbidden {
		t.Errorf("after revoke: expected 403, got %d", w2.Code)
	}
	var body map[string]string
	json.NewDecoder(w2.Body).Decode(&body)
	if body["error"] != "token_revoked" {
		t.Errorf("expected token_revoked, got %q", body["error"])
	}
}

// TestE2EPluginTokenDeleteAndReject tests: admin creates token → deletes it →
// plugin is rejected (not found).
func TestE2EPluginTokenDeleteAndReject(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)

	createReq := adminReq("POST", "/api/admin/tokens", TokenCreateRequest{
		Role:        "plugin",
		Description: "e2e-delete-test",
	})
	cw := httptest.NewRecorder()
	AdminCreateToken(cw, createReq)
	var createResp TokenCreateResponse
	json.NewDecoder(cw.Body).Decode(&createResp)
	tokenPlain := createResp.Token
	tokenID := createResp.ID

	// Delete the token
	delReq := adminReq("DELETE", "/api/admin/tokens/"+tokenID, nil)
	delReq.SetPathValue("id", tokenID)
	dw := httptest.NewRecorder()
	AdminDeleteToken(dw, delReq)
	if dw.Code != http.StatusOK {
		t.Fatalf("AdminDeleteToken: expected 200, got %d", dw.Code)
	}

	// Attempt to use deleted token
	req := httptest.NewRequest("GET", "/api/inventory", nil)
	req.Header.Set("Authorization", "Bearer "+tokenPlain)
	req.RemoteAddr = "10.0.0.1:80"
	w := httptest.NewRecorder()
	GetInventory(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("after delete: expected 403, got %d", w.Code)
	}
	var body map[string]string
	json.NewDecoder(w.Body).Decode(&body)
	if body["error"] != "token_not_found" {
		t.Errorf("expected token_not_found, got %q", body["error"])
	}
}

// TestE2EPluginTokenIPConstraintEnforced tests: token with CIDR →
// call from allowed IP succeeds, call from denied IP fails.
func TestE2EPluginTokenIPConstraintEnforced(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)

	createReq := adminReq("POST", "/api/admin/tokens", TokenCreateRequest{
		Role:        "plugin",
		Description: "e2e-ip-constraint",
		AllowedIPs:  "192.168.10.0/24",
	})
	cw := httptest.NewRecorder()
	AdminCreateToken(cw, createReq)
	var createResp TokenCreateResponse
	json.NewDecoder(cw.Body).Decode(&createResp)
	tokenPlain := createResp.Token

	// Allowed IP
	req1 := httptest.NewRequest("GET", "/api/inventory", nil)
	req1.Header.Set("Authorization", "Bearer "+tokenPlain)
	req1.RemoteAddr = "192.168.10.50:9000"
	w1 := httptest.NewRecorder()
	GetInventory(w1, req1)
	if w1.Code != http.StatusOK {
		t.Errorf("allowed IP: expected 200, got %d — %s", w1.Code, w1.Body.String())
	}

	// Denied IP
	req2 := httptest.NewRequest("GET", "/api/inventory", nil)
	req2.Header.Set("Authorization", "Bearer "+tokenPlain)
	req2.RemoteAddr = "10.0.0.1:80"
	w2 := httptest.NewRecorder()
	GetInventory(w2, req2)
	if w2.Code != http.StatusForbidden {
		t.Errorf("denied IP: expected 403, got %d", w2.Code)
	}
	var body map[string]string
	json.NewDecoder(w2.Body).Decode(&body)
	if body["error"] != "ip_not_allowed" {
		t.Errorf("expected ip_not_allowed, got %q", body["error"])
	}
}

// TestE2EPluginTokenHostnameConstraintEnforced tests: token with hostname pattern →
// matching hostname succeeds, mismatching fails.
func TestE2EPluginTokenHostnameConstraintEnforced(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)

	createReq := adminReq("POST", "/api/admin/tokens", TokenCreateRequest{
		Role:                   "plugin",
		Description:            "e2e-hostname-constraint",
		AllowedHostnamePattern: "ansible-control-[0-9]+",
	})
	cw := httptest.NewRecorder()
	AdminCreateToken(cw, createReq)
	var createResp TokenCreateResponse
	json.NewDecoder(cw.Body).Decode(&createResp)
	tokenPlain := createResp.Token

	// Matching hostname
	req1 := httptest.NewRequest("GET", "/api/inventory", nil)
	req1.Header.Set("Authorization", "Bearer "+tokenPlain)
	req1.Header.Set("X-Relay-Client-Host", "ansible-control-01")
	req1.RemoteAddr = "10.0.0.1:80"
	w1 := httptest.NewRecorder()
	GetInventory(w1, req1)
	if w1.Code != http.StatusOK {
		t.Errorf("matching hostname: expected 200, got %d — %s", w1.Code, w1.Body.String())
	}

	// Mismatching hostname
	req2 := httptest.NewRequest("GET", "/api/inventory", nil)
	req2.Header.Set("Authorization", "Bearer "+tokenPlain)
	req2.Header.Set("X-Relay-Client-Host", "terraform-runner-01")
	req2.RemoteAddr = "10.0.0.1:80"
	w2 := httptest.NewRecorder()
	GetInventory(w2, req2)
	if w2.Code != http.StatusForbidden {
		t.Errorf("mismatching hostname: expected 403, got %d", w2.Code)
	}
	var body map[string]string
	json.NewDecoder(w2.Body).Decode(&body)
	if body["error"] != "hostname_not_allowed" {
		t.Errorf("expected hostname_not_allowed, got %q", body["error"])
	}
}

// TestE2EPluginTokenExecCommandAudit tests the /api/exec endpoint:
// create plugin token → ExecCommand → verify audit logged.
func TestE2EPluginTokenExecCommandAudit(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)

	createReq := adminReq("POST", "/api/admin/tokens", TokenCreateRequest{
		Role:        "plugin",
		Description: "e2e-exec-audit",
	})
	cw := httptest.NewRecorder()
	AdminCreateToken(cw, createReq)
	var createResp TokenCreateResponse
	json.NewDecoder(cw.Body).Decode(&createResp)
	tokenPlain := createResp.Token
	tokenID := createResp.ID

	// Call ExecCommand
	execBody, _ := json.Marshal(map[string]interface{}{"cmd": "hostname", "timeout": 10})
	req := httptest.NewRequest("POST", "/api/exec/some-host", bytes.NewReader(execBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+tokenPlain)
	req.RemoteAddr = "172.16.0.5:1234"
	req.SetPathValue("hostname", "some-host")
	w := httptest.NewRecorder()
	ExecCommand(w, req)

	// Should pass auth (may 404 on agent-online check, but must not be 401/403)
	if w.Code == http.StatusUnauthorized || w.Code == http.StatusForbidden {
		t.Errorf("ExecCommand: expected auth to pass, got %d — %s", w.Code, w.Body.String())
	}

	// Verify audit: last_used_at and last_used_ip set
	tok, err := s.GetPluginTokenByID(context.Background(), tokenID)
	if err != nil {
		t.Fatalf("GetPluginTokenByID: %v", err)
	}
	if tok.LastUsedAt == nil {
		t.Error("expected last_used_at to be set after ExecCommand")
	}
	if tok.LastUsedIP != "172.16.0.5" {
		t.Errorf("last_used_ip: got %q, want %q", tok.LastUsedIP, "172.16.0.5")
	}
}

// TestE2EPluginTokenXForwardedForAudit verifies that when X-Forwarded-For is set,
// the forwarded IP is used for both CIDR check and audit.
func TestE2EPluginTokenXForwardedForAudit(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)

	createReq := adminReq("POST", "/api/admin/tokens", TokenCreateRequest{
		Role:        "plugin",
		Description: "e2e-xff-audit",
		AllowedIPs:  "192.168.20.0/24",
	})
	cw := httptest.NewRecorder()
	AdminCreateToken(cw, createReq)
	var createResp TokenCreateResponse
	json.NewDecoder(cw.Body).Decode(&createResp)
	tokenPlain := createResp.Token
	tokenID := createResp.ID

	// Plugin behind proxy: RemoteAddr is proxy, XFF is real client
	req := httptest.NewRequest("GET", "/api/inventory", nil)
	req.Header.Set("Authorization", "Bearer "+tokenPlain)
	req.Header.Set("X-Forwarded-For", "192.168.20.42")
	req.RemoteAddr = "10.0.0.100:8080" // proxy IP — not in CIDR
	w := httptest.NewRecorder()
	GetInventory(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("XFF audit: expected 200 (XFF IP in CIDR), got %d — %s", w.Code, w.Body.String())
	}

	// Audit must record the XFF IP, not the proxy IP
	tok, _ := s.GetPluginTokenByID(context.Background(), tokenID)
	if tok.LastUsedIP != "192.168.20.42" {
		t.Errorf("audit last_used_ip: got %q, want %q", tok.LastUsedIP, "192.168.20.42")
	}
}

// ========================================================================
// E2E: Admin token list shows correct state after operations
// ========================================================================

// TestE2EAdminListReflectsAllTokenTypes verifies that AdminListTokens returns
// both enrollment and plugin tokens with correct metadata.
func TestE2EAdminListReflectsAllTokenTypes(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)
	SetRegisterStore(s)

	// Create enrollment token
	enrReq := adminReq("POST", "/api/admin/tokens", TokenCreateRequest{
		Role:            "enrollment",
		HostnamePattern: "e2e-list-enr-.*",
		Reusable:        1,
	})
	ew := httptest.NewRecorder()
	AdminCreateToken(ew, enrReq)
	var enrResp TokenCreateResponse
	json.NewDecoder(ew.Body).Decode(&enrResp)
	enrPlain := enrResp.Token

	// Create plugin token with expiry
	future := time.Now().UTC().Add(365 * 24 * time.Hour).Format(time.RFC3339)
	plgReq := adminReq("POST", "/api/admin/tokens", TokenCreateRequest{
		Role:        "plugin",
		Description: "e2e-list-plg-prod",
		AllowedIPs:  "10.0.0.0/8",
		ExpiresAt:   future,
	})
	pw := httptest.NewRecorder()
	AdminCreateToken(pw, plgReq)
	var plgResp TokenCreateResponse
	json.NewDecoder(pw.Body).Decode(&plgResp)
	plgPlain := plgResp.Token

	// Use enrollment token once
	key, pubPEM := genRSAPubPEM(t, 4096)
	fullEnrollment(t, "e2e-list-enr-host-01", enrPlain, key, pubPEM)

	// Use plugin token once
	apiReq := httptest.NewRequest("GET", "/api/inventory", nil)
	apiReq.Header.Set("Authorization", "Bearer "+plgPlain)
	apiReq.RemoteAddr = "10.1.2.3:80"
	httptest.NewRecorder()
	lw := httptest.NewRecorder()
	GetInventory(lw, apiReq)

	// List all tokens
	listReq := adminReq("GET", "/api/admin/tokens", nil)
	listW := httptest.NewRecorder()
	AdminListTokens(listW, listReq)

	if listW.Code != http.StatusOK {
		t.Fatalf("AdminListTokens: expected 200, got %d", listW.Code)
	}

	body := listW.Body.String()

	// Plain tokens must NOT appear in list
	if contains(body, enrPlain) {
		t.Error("enrollment plain token must not appear in list response")
	}
	if contains(body, plgPlain) {
		t.Error("plugin plain token must not appear in list response")
	}

	// Roles must appear
	if !contains(body, "enrollment") {
		t.Error("expected 'enrollment' role in list response")
	}
	if !contains(body, "plugin") {
		t.Error("expected 'plugin' role in list response")
	}

	// plugin token expires_at must be present
	if !contains(body, "expires_at") {
		t.Error("expected expires_at in list response for plugin token with expiry")
	}
}
