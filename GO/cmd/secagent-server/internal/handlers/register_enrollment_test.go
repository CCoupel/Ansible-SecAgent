package handlers

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
	"strings"
	"testing"
	"time"

	"secagent-server/cmd/secagent-server/internal/storage"
)

// ========================================================================
// Helpers
// ========================================================================

// insertEnrollmentToken directly inserts a token into the test store.
func insertEnrollmentToken(t *testing.T, id, tokenPlain, pattern string, reusable bool, expiresAt *time.Time) {
	t.Helper()
	h := sha256.Sum256([]byte(tokenPlain))
	tok := storage.EnrollmentToken{
		ID:              id,
		TokenHash:       fmt.Sprintf("%x", h),
		HostnamePattern: pattern,
		Reusable:        reusable,
		CreatedAt:       time.Now().UTC(),
		ExpiresAt:       expiresAt,
		CreatedBy:       "test",
	}
	if err := registerStore.CreateEnrollmentToken(context.Background(), tok); err != nil {
		t.Fatalf("insertEnrollmentToken: %v", err)
	}
}

// doPhase1 sends phase-1 of enrollment-token flow.
// Returns the decoded ChallengeResponse and HTTP status.
func doPhase1(t *testing.T, hostname, pubKeyPEM, token string) (int, *ChallengeResponse) {
	t.Helper()
	req := RegisterRequest{
		Hostname:        hostname,
		PublicKeyPEM:    pubKeyPEM,
		EnrollmentToken: token,
	}
	body, _ := json.Marshal(req)
	httpReq := httptest.NewRequest("POST", "/api/register", bytes.NewReader(body))
	w := httptest.NewRecorder()
	RegisterAgent(w, httpReq)

	if w.Code != http.StatusOK {
		return w.Code, nil
	}
	var cr ChallengeResponse
	if err := json.NewDecoder(w.Body).Decode(&cr); err != nil {
		t.Fatalf("doPhase1 decode response: %v", err)
	}
	return w.Code, &cr
}

// buildChallengeResponse decrypts the challenge with agentPrivKey and builds
// the RSA-OAEP encrypted response: OAEP(nonce + token, serverPubKey).
func buildChallengeResponse(t *testing.T, cr *ChallengeResponse, agentPrivKey *rsa.PrivateKey, token string) string {
	t.Helper()

	challengeBytes, err := base64.StdEncoding.DecodeString(cr.Challenge)
	if err != nil {
		t.Fatalf("buildChallengeResponse decode challenge: %v", err)
	}

	// Decrypt nonce with agent private key
	nonce, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, agentPrivKey, challengeBytes, nil)
	if err != nil {
		t.Fatalf("buildChallengeResponse decrypt nonce: %v", err)
	}

	// Build response: nonce + token
	payload := append(nonce, []byte(token)...)

	// Encrypt with server public key
	serverPubKey := &server.PrivateKey.PublicKey
	encrypted, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, serverPubKey, payload, nil)
	if err != nil {
		t.Fatalf("buildChallengeResponse encrypt: %v", err)
	}

	return base64.StdEncoding.EncodeToString(encrypted)
}

// doPhase2 sends phase-2 with the challenge_response.
func doPhase2(t *testing.T, hostname, pubKeyPEM, token, challengeResponse string) (int, *RegisterResponse) {
	t.Helper()
	req := RegisterRequest{
		Hostname:          hostname,
		PublicKeyPEM:      pubKeyPEM,
		EnrollmentToken:   token,
		ChallengeResponse: challengeResponse,
	}
	body, _ := json.Marshal(req)
	httpReq := httptest.NewRequest("POST", "/api/register", bytes.NewReader(body))
	w := httptest.NewRecorder()
	RegisterAgent(w, httpReq)

	if w.Code != http.StatusOK {
		return w.Code, nil
	}
	var resp RegisterResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("doPhase2 decode response: %v", err)
	}
	return w.Code, &resp
}

// fullEnrollment runs both phases and returns the final RegisterResponse.
func fullEnrollment(t *testing.T, hostname, token string, agentPrivKey *rsa.PrivateKey, pubKeyPEM string) (int, *RegisterResponse) {
	t.Helper()

	// Phase 1
	code, cr := doPhase1(t, hostname, pubKeyPEM, token)
	if code != http.StatusOK {
		return code, nil
	}
	if cr == nil || cr.Challenge == "" {
		t.Fatal("expected challenge in phase-1 response")
	}

	// Build response
	challengeResp := buildChallengeResponse(t, cr, agentPrivKey, token)

	// Phase 2
	return doPhase2(t, hostname, pubKeyPEM, token, challengeResp)
}

// ========================================================================
// Tests: one-shot token
// ========================================================================

func TestEnrollmentTokenOneShotSuccess(t *testing.T) {
	useFreshStores(t)
	agentPrivKey, agentPubPEM := genRSAPubPEM(t, 4096)
	hostname := "enroll-oneshot-01"
	token := "secagent_enr_oneshot_success_01"

	insertEnrollmentToken(t, "tok-oneshot-01", token, hostname, false, nil)

	code, resp := fullEnrollment(t, hostname, token, agentPrivKey, agentPubPEM)
	if code != http.StatusOK {
		t.Fatalf("expected 200, got %d", code)
	}
	if resp.TokenEncrypted == "" {
		t.Error("expected token_encrypted in response")
	}
	if resp.ServerPublicKeyPEM == "" {
		t.Error("expected server_public_key_pem in response")
	}

	// Verify use_count incremented
	tok, err := registerStore.GetEnrollmentTokenByID(context.Background(), "tok-oneshot-01")
	if err != nil {
		t.Fatalf("GetEnrollmentTokenByID: %v", err)
	}
	if tok.UseCount != 1 {
		t.Errorf("expected use_count=1, got %d", tok.UseCount)
	}
}

func TestEnrollmentTokenOneShotRejectsSecondUse(t *testing.T) {
	useFreshStores(t)
	agentPrivKey, agentPubPEM := genRSAPubPEM(t, 4096)
	hostname := "enroll-oneshot-02"
	token := "secagent_enr_oneshot_reject_02"

	insertEnrollmentToken(t, "tok-oneshot-02", token, hostname, false, nil)

	// First enrollment must succeed
	code, _ := fullEnrollment(t, hostname, token, agentPrivKey, agentPubPEM)
	if code != http.StatusOK {
		t.Fatalf("first enrollment: expected 200, got %d", code)
	}

	// Second enrollment must be rejected (token_already_used)
	code2, cr2 := doPhase1(t, hostname, agentPubPEM, token)
	if code2 != http.StatusForbidden {
		t.Errorf("second enrollment phase-1: expected 403, got %d", code2)
	}
	if cr2 != nil {
		t.Error("expected nil challenge on rejected token")
	}
}

// ========================================================================
// Tests: permanent (reusable) token
// ========================================================================

func TestEnrollmentTokenPermanentMultipleUses(t *testing.T) {
	useFreshStores(t)
	agentPrivKey1, agentPubPEM1 := genRSAPubPEM(t, 4096)
	agentPrivKey2, agentPubPEM2 := genRSAPubPEM(t, 4096)

	token := "secagent_enr_permanent_01"
	insertEnrollmentToken(t, "tok-perm-01", token, "enroll-perm-.*", true, nil)

	// First host
	code1, resp1 := fullEnrollment(t, "enroll-perm-host-a", token, agentPrivKey1, agentPubPEM1)
	if code1 != http.StatusOK {
		t.Fatalf("host-a enrollment: expected 200, got %d", code1)
	}
	if resp1.TokenEncrypted == "" {
		t.Error("expected token_encrypted for host-a")
	}

	// Second host — same token, should still work
	code2, resp2 := fullEnrollment(t, "enroll-perm-host-b", token, agentPrivKey2, agentPubPEM2)
	if code2 != http.StatusOK {
		t.Fatalf("host-b enrollment: expected 200, got %d", code2)
	}
	if resp2.TokenEncrypted == "" {
		t.Error("expected token_encrypted for host-b")
	}

	// Verify use_count = 2
	tok, _ := registerStore.GetEnrollmentTokenByID(context.Background(), "tok-perm-01")
	if tok.UseCount != 2 {
		t.Errorf("expected use_count=2, got %d", tok.UseCount)
	}
}

// ========================================================================
// Tests: expired token
// ========================================================================

func TestEnrollmentTokenExpiredRejected(t *testing.T) {
	useFreshStores(t)
	_, agentPubPEM := genRSAPubPEM(t, 2048)
	hostname := "enroll-expired-01"
	token := "secagent_enr_expired_01"

	past := time.Now().UTC().Add(-time.Hour)
	insertEnrollmentToken(t, "tok-expired-01", token, hostname, false, &past)

	code, _ := doPhase1(t, hostname, agentPubPEM, token)
	if code != http.StatusForbidden {
		t.Errorf("expected 403 for expired token, got %d", code)
	}
}

// ========================================================================
// Tests: hostname pattern mismatch
// ========================================================================

func TestEnrollmentTokenHostnameMismatchRejected(t *testing.T) {
	useFreshStores(t)
	_, agentPubPEM := genRSAPubPEM(t, 2048)
	token := "secagent_enr_mismatch_01"

	// Token only allows "vp-.*"
	insertEnrollmentToken(t, "tok-mismatch-01", token, "vp-.*", false, nil)

	// Try with a hostname that does NOT match
	code, _ := doPhase1(t, "web-server-01", agentPubPEM, token)
	if code != http.StatusForbidden {
		t.Errorf("expected 403 for hostname mismatch, got %d", code)
	}
}

func TestEnrollmentTokenHostnamePatternMatch(t *testing.T) {
	useFreshStores(t)
	agentPrivKey, agentPubPEM := genRSAPubPEM(t, 4096)
	token := "secagent_enr_pattern_01"

	// Token allows "qualif-host-[0-9]+"
	insertEnrollmentToken(t, "tok-pattern-01", token, "qualif-host-[0-9]+", false, nil)

	code, resp := fullEnrollment(t, "qualif-host-42", token, agentPrivKey, agentPubPEM)
	if code != http.StatusOK {
		t.Fatalf("expected 200 for matching hostname, got %d", code)
	}
	if resp.TokenEncrypted == "" {
		t.Error("expected token_encrypted")
	}
}

// ========================================================================
// Tests: unknown token
// ========================================================================

func TestEnrollmentTokenNotFoundRejected(t *testing.T) {
	useFreshStores(t)
	_, agentPubPEM := genRSAPubPEM(t, 2048)

	code, _ := doPhase1(t, "some-host", agentPubPEM, "secagent_enr_does_not_exist")
	if code != http.StatusForbidden {
		t.Errorf("expected 403 for unknown token, got %d", code)
	}
}

// ========================================================================
// Tests: OAEP challenge-response — invalid response
// ========================================================================

func TestEnrollmentTokenChallengeResponseMismatch(t *testing.T) {
	useFreshStores(t)
	_, agentPubPEM := genRSAPubPEM(t, 4096)
	hostname := "enroll-mismatch-resp-01"
	token := "secagent_enr_challenge_mismatch_01"

	insertEnrollmentToken(t, "tok-cmismatch-01", token, hostname, false, nil)

	// Phase 1 — get challenge
	code, cr := doPhase1(t, hostname, agentPubPEM, token)
	if code != http.StatusOK || cr == nil {
		t.Fatalf("phase-1 expected 200, got %d", code)
	}

	// Build a WRONG response (random bytes encrypted with server pubkey)
	wrongPayload := []byte("wrong-nonce-wrong-token")
	serverPubKey := &server.PrivateKey.PublicKey
	encrypted, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, serverPubKey, wrongPayload, nil)
	if err != nil {
		t.Fatalf("encrypt wrong payload: %v", err)
	}
	badResponse := base64.StdEncoding.EncodeToString(encrypted)

	code2, _ := doPhase2(t, hostname, agentPubPEM, token, badResponse)
	if code2 != http.StatusForbidden {
		t.Errorf("expected 403 for wrong challenge response, got %d", code2)
	}
}

func TestEnrollmentTokenChallengeExpired(t *testing.T) {
	useFreshStores(t)
	_, agentPubPEM := genRSAPubPEM(t, 4096)
	hostname := "enroll-nonce-expired-01"
	token := "secagent_enr_nonce_exp_01"

	insertEnrollmentToken(t, "tok-nonce-exp-01", token, hostname, false, nil)

	// Phase 1
	code, _ := doPhase1(t, hostname, agentPubPEM, token)
	if code != http.StatusOK {
		t.Fatalf("phase-1 expected 200, got %d", code)
	}

	// Manually expire the nonce
	pendingNoncesMu.Lock()
	if p, ok := pendingNonces[hostname]; ok {
		p.expiresAt = time.Now().Add(-time.Second)
	}
	pendingNoncesMu.Unlock()

	// Phase 2 with any response — should fail because nonce is expired
	serverPubKey := &server.PrivateKey.PublicKey
	dummyPayload := make([]byte, 20)
	encrypted, _ := rsa.EncryptOAEP(sha256.New(), rand.Reader, serverPubKey, dummyPayload, nil)
	badResponse := base64.StdEncoding.EncodeToString(encrypted)

	code2, _ := doPhase2(t, hostname, agentPubPEM, token, badResponse)
	if code2 != http.StatusForbidden {
		t.Errorf("expected 403 for expired nonce, got %d", code2)
	}
}

func TestEnrollmentTokenPhase2WithoutPhase1(t *testing.T) {
	useFreshStores(t)
	_, agentPubPEM := genRSAPubPEM(t, 4096)
	hostname := "enroll-nophase1-01"
	token := "secagent_enr_nophase1_01"

	insertEnrollmentToken(t, "tok-nophase1-01", token, hostname, false, nil)

	// Jump directly to phase 2 without having done phase 1
	serverPubKey := &server.PrivateKey.PublicKey
	dummyPayload := make([]byte, 20)
	encrypted, _ := rsa.EncryptOAEP(sha256.New(), rand.Reader, serverPubKey, dummyPayload, nil)
	badResponse := base64.StdEncoding.EncodeToString(encrypted)

	code, _ := doPhase2(t, hostname, agentPubPEM, token, badResponse)
	if code != http.StatusForbidden {
		t.Errorf("expected 403 for phase-2 without phase-1, got %d", code)
	}
}

// ========================================================================
// Tests: OAEP challenge-response — invalid encoding
// ========================================================================

func TestEnrollmentTokenChallengeResponseInvalidBase64(t *testing.T) {
	useFreshStores(t)
	_, agentPubPEM := genRSAPubPEM(t, 4096)
	hostname := "enroll-badenc-01"
	token := "secagent_enr_badenc_01"

	insertEnrollmentToken(t, "tok-badenc-01", token, hostname, false, nil)

	code, _ := doPhase1(t, hostname, agentPubPEM, token)
	if code != http.StatusOK {
		t.Fatalf("phase-1 expected 200, got %d", code)
	}

	// Phase 2 with invalid base64
	req := RegisterRequest{
		Hostname:          hostname,
		PublicKeyPEM:      agentPubPEM,
		EnrollmentToken:   token,
		ChallengeResponse: "!!!not-base64!!!",
	}
	body, _ := json.Marshal(req)
	httpReq := httptest.NewRequest("POST", "/api/register", bytes.NewReader(body))
	w := httptest.NewRecorder()
	RegisterAgent(w, httpReq)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for invalid base64, got %d", w.Code)
	}
}

// ========================================================================
// Tests: no enrollment without a token (#192c)
// ========================================================================

// The historical tokenless flow ("pre-authorized key, one step") is gone: it issued a JWT and a NEW JTI
// without any proof of possession of the private key and without looking at the revocation.
func tokenlessRegister(hostname, pubPEM string) *httptest.ResponseRecorder {
	body, _ := json.Marshal(RegisterRequest{Hostname: hostname, PublicKeyPEM: pubPEM})
	w := httptest.NewRecorder()
	RegisterAgent(w, httptest.NewRequest("POST", "/api/register", bytes.NewReader(body)))
	return w
}

func TestRegisterWithoutEnrollmentTokenIsRefused(t *testing.T) {
	useFreshStores(t)
	_, agentPubPEM := genRSAPubPEM(t, 4096)
	hostname := "enroll-tokenless-01"
	if err := registerStore.AddAuthorizedKey(context.Background(), hostname, agentPubPEM, "test"); err != nil {
		t.Fatalf("AddAuthorizedKey: %v", err)
	}
	w := tokenlessRegister(hostname, agentPubPEM) // the key IS pre-authorized: it must not matter
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "enrollment_token_required") {
		t.Fatalf("tokenless register: %d %s, want 403 enrollment_token_required", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "token_encrypted") {
		t.Error("a refused enrollment must not carry a token")
	}
	if a, _ := registerStore.GetAgent(context.Background(), hostname); a != nil {
		t.Error("a refused enrollment must not create the agent")
	}
}

// The revocation cannot be undone by registering again without a token, and nobody can replace the JTI
// of an enrolled agent knowing only its hostname and public key.
func TestRegisterWithoutTokenCannotUndoARevocationNorReplaceAJTI(t *testing.T) {
	useFreshStores(t)
	agentPriv, agentPubPEM := genRSAPubPEM(t, 4096)
	hostname := "enroll-tokenless-02"
	token := "secagent_enr_tokenless_revoke_02"
	insertEnrollmentToken(t, "tok-tokenless-02", token, hostname, false, nil)
	if code, _ := fullEnrollment(t, hostname, token, agentPriv, agentPubPEM); code != http.StatusOK {
		t.Fatalf("setup enrollment: %d", code)
	}
	before, _ := registerStore.GetAgent(context.Background(), hostname)
	if before == nil {
		t.Fatal("setup: no agent")
	}

	// 40 forged tokenless requests (hostname + public key are not secrets): the JTI must not move
	for i := 0; i < 40; i++ {
		if w := tokenlessRegister(hostname, agentPubPEM); w.Code != http.StatusForbidden {
			t.Fatalf("forged request %d: %d", i, w.Code)
		}
	}
	if cur, _ := registerStore.GetAgent(context.Background(), hostname); cur.TokenJTI != before.TokenJTI {
		t.Fatal("a tokenless request replaced the JTI of an enrolled agent")
	}

	// revoke (blacklist the current JTI), then register again without a token
	reason := "admin_revoke"
	if err := registerStore.AddToBlacklist(context.Background(), before.TokenJTI, hostname, time.Now().Add(25*time.Hour).Format(time.RFC3339), &reason); err != nil {
		t.Fatal(err)
	}
	if w := tokenlessRegister(hostname, agentPubPEM); w.Code != http.StatusForbidden {
		t.Fatalf("a revoked agent registering without a token: %d, want 403", w.Code)
	}
	cur, _ := registerStore.GetAgent(context.Background(), hostname)
	if cur.TokenJTI != before.TokenJTI {
		t.Error("the revoked agent obtained a new JTI")
	}
	if bl, _ := registerStore.IsJTIBlacklisted(context.Background(), cur.TokenJTI); !bl {
		t.Error("the revoked JTI must stay blacklisted")
	}
}

// Enrollment through a token and the nonce challenge is unchanged.
func TestEnrollmentWithATokenStillWorksAfterTheTokenlessFlowWasRemoved(t *testing.T) {
	useFreshStores(t)
	priv, pub := genRSAPubPEM(t, 4096)
	hostname := "enroll-tokenless-03"
	token := "secagent_enr_tokenless_ok_03"
	insertEnrollmentToken(t, "tok-tokenless-03", token, hostname, false, nil)
	if code, resp := fullEnrollment(t, hostname, token, priv, pub); code != http.StatusOK || resp == nil || resp.TokenEncrypted == "" {
		t.Fatalf("token enrollment: %d %+v", code, resp)
	}
}

// ========================================================================
// Tests: agent JWT can be decrypted after full enrollment
// ========================================================================

func TestEnrollmentTokenJWTDecryptable(t *testing.T) {
	useFreshStores(t)
	agentPrivKey, agentPubPEM := genRSAPubPEM(t, 4096)
	hostname := "enroll-jwt-01"
	token := "secagent_enr_jwt_decrypt_01"

	insertEnrollmentToken(t, "tok-jwt-01", token, hostname, false, nil)

	code, resp := fullEnrollment(t, hostname, token, agentPrivKey, agentPubPEM)
	if code != http.StatusOK {
		t.Fatalf("expected 200, got %d", code)
	}

	// Decrypt JWT with agent private key
	ciphertext, err := base64.StdEncoding.DecodeString(resp.TokenEncrypted)
	if err != nil {
		t.Fatalf("decode token_encrypted: %v", err)
	}

	plaintext, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, agentPrivKey, ciphertext, nil)
	if err != nil {
		t.Fatalf("decrypt JWT: %v", err)
	}

	// JWT should start with "eyJ" (base64url-encoded header)
	if len(plaintext) < 3 || string(plaintext[:3]) != "eyJ" {
		t.Errorf("decrypted JWT looks invalid: %q", string(plaintext[:min(20, len(plaintext))]))
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
