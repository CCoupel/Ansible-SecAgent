package handlers

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
)

// genRSAPubPEM generates a fresh RSA key of bitSize and returns the PEM-encoded public key.
func genRSAPubPEM(t *testing.T, bitSize int) (privKey *rsa.PrivateKey, pubPEM string) {
	t.Helper()
	privKey, err := rsa.GenerateKey(rand.Reader, bitSize)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal public key: %v", err)
	}
	pubPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))
	return
}

// preAuthorize inserts a hostname/pubkey into the authorized_keys table via AdminAuthorize.
func preAuthorize(t *testing.T, hostname, pubKeyPEM string) {
	t.Helper()
	if err := registerStore.AddAuthorizedKey(context.Background(), hostname, pubKeyPEM, "test-setup"); err != nil {
		t.Fatalf("preAuthorize: %v", err)
	}
}

// TestRegisterAgentSuccess tests successful agent registration
func TestRegisterAgentSuccess(t *testing.T) {
	// Must use 4096-bit key: RSA-OAEP/SHA-256 with 2048-bit key can only
	// encrypt ~190 bytes, but a JWT is ~300 bytes.
	privKey, pubKeyPEM := genRSAPubPEM(t, 4096)
	_ = privKey

	hostname := "test-agent-01"
	preAuthorize(t, hostname, pubKeyPEM)

	req := RegisterRequest{
		Hostname:     hostname,
		PublicKeyPEM: pubKeyPEM,
	}

	body, _ := json.Marshal(req)
	httpReq := httptest.NewRequest("POST", "/api/register", bytes.NewReader(body))
	w := httptest.NewRecorder()

	RegisterAgent(w, httpReq)

	if w.Code != http.StatusOK {
		t.Errorf("RegisterAgent: expected 200, got %d — body: %s", w.Code, w.Body.String())
	}

	var resp RegisterResponse
	json.Unmarshal(w.Body.Bytes(), &resp)

	if resp.TokenEncrypted == "" {
		t.Error("expected token_encrypted, got empty string")
	}
	if resp.ServerPublicKeyPEM == "" {
		t.Error("expected server_public_key_pem, got empty string")
	}
}

// TestRegisterAgentUnauthorizedHostname tests that unknown hostnames are rejected
func TestRegisterAgentUnauthorizedHostname(t *testing.T) {
	_, pubKeyPEM := genRSAPubPEM(t, 2048)

	req := RegisterRequest{
		Hostname:     "unknown-host-99",
		PublicKeyPEM: pubKeyPEM,
	}

	body, _ := json.Marshal(req)
	httpReq := httptest.NewRequest("POST", "/api/register", bytes.NewReader(body))
	w := httptest.NewRecorder()

	RegisterAgent(w, httpReq)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}
}

// TestRegisterAgentKeyMismatch tests that a key different from the authorized one is rejected
func TestRegisterAgentKeyMismatch(t *testing.T) {
	_, authorizedPEM := genRSAPubPEM(t, 4096)
	_, differentPEM := genRSAPubPEM(t, 4096)

	hostname := "test-agent-mismatch"
	preAuthorize(t, hostname, authorizedPEM)

	req := RegisterRequest{
		Hostname:     hostname,
		PublicKeyPEM: differentPEM, // different from what was authorized
	}

	body, _ := json.Marshal(req)
	httpReq := httptest.NewRequest("POST", "/api/register", bytes.NewReader(body))
	w := httptest.NewRecorder()

	RegisterAgent(w, httpReq)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}

	var resp map[string]string
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["error"] != "public_key_mismatch" {
		t.Errorf("expected public_key_mismatch, got: %v", resp["error"])
	}
}

// TestRegisterAgentMissingFields tests validation of missing fields
func TestRegisterAgentMissingFields(t *testing.T) {
	tests := []struct {
		name     string
		req      RegisterRequest
		wantCode int
	}{
		{
			name:     "missing hostname",
			req:      RegisterRequest{Hostname: "", PublicKeyPEM: "key"},
			wantCode: http.StatusBadRequest,
		},
		{
			name:     "missing public_key_pem",
			req:      RegisterRequest{Hostname: "host", PublicKeyPEM: ""},
			wantCode: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, _ := json.Marshal(tt.req)
			httpReq := httptest.NewRequest("POST", "/api/register", bytes.NewReader(body))
			w := httptest.NewRecorder()

			RegisterAgent(w, httpReq)

			if w.Code != tt.wantCode {
				t.Errorf("expected %d, got %d", tt.wantCode, w.Code)
			}
		})
	}
}

// TestRegisterAgentInvalidJSON tests invalid JSON body
func TestRegisterAgentInvalidJSON(t *testing.T) {
	httpReq := httptest.NewRequest("POST", "/api/register", bytes.NewBufferString("invalid json"))
	w := httptest.NewRecorder()

	RegisterAgent(w, httpReq)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

// TestRegisterAgentMethodNotAllowed tests non-POST method
func TestRegisterAgentMethodNotAllowed(t *testing.T) {
	httpReq := httptest.NewRequest("GET", "/api/register", nil)
	w := httptest.NewRecorder()

	RegisterAgent(w, httpReq)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// TestAdminAuthorizeSuccess tests successful pre-authorization (with DB persistence)
func TestAdminAuthorizeSuccess(t *testing.T) {
	// 2048-bit is sufficient here (no JWT encryption needed for admin authorize)
	_, pubKeyPEM := genRSAPubPEM(t, 2048)

	req := AdminAuthorizeRequest{
		Hostname:     "test-agent-02",
		PublicKeyPEM: pubKeyPEM,
		ApprovedBy:   "ci-bot",
	}

	body, _ := json.Marshal(req)
	httpReq := httptest.NewRequest("POST", "/api/admin/authorize", bytes.NewReader(body))
	httpReq.Header.Set("Authorization", "Bearer "+server.AdminToken)
	w := httptest.NewRecorder()

	AdminAuthorize(w, httpReq)

	if w.Code != http.StatusCreated {
		t.Errorf("AdminAuthorize: expected 201, got %d — body: %s", w.Code, w.Body.String())
	}

	// Verify the key was actually persisted in DB
	stored, err := registerStore.GetAuthorizedKey(context.Background(), req.Hostname)
	if err != nil {
		t.Fatalf("GetAuthorizedKey: %v", err)
	}
	if stored == nil {
		t.Error("key was not persisted in authorized_keys table")
	}
}

// TestAdminAuthorizeMissingToken tests missing authorization header
func TestAdminAuthorizeMissingToken(t *testing.T) {
	req := AdminAuthorizeRequest{
		Hostname:     "test-agent-03",
		PublicKeyPEM: "key",
		ApprovedBy:   "ci-bot",
	}

	body, _ := json.Marshal(req)
	httpReq := httptest.NewRequest("POST", "/api/admin/authorize", bytes.NewReader(body))
	// No Authorization header
	w := httptest.NewRecorder()

	AdminAuthorize(w, httpReq)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

// TestAdminAuthorizeInvalidToken tests invalid admin token
func TestAdminAuthorizeInvalidToken(t *testing.T) {
	req := AdminAuthorizeRequest{
		Hostname:     "test-agent-04",
		PublicKeyPEM: "key",
		ApprovedBy:   "ci-bot",
	}

	body, _ := json.Marshal(req)
	httpReq := httptest.NewRequest("POST", "/api/admin/authorize", bytes.NewReader(body))
	httpReq.Header.Set("Authorization", "Bearer invalid-token")
	w := httptest.NewRecorder()

	AdminAuthorize(w, httpReq)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

// TestAdminAuthorizeMissingFields tests validation of missing fields
func TestAdminAuthorizeMissingFields(t *testing.T) {
	tests := []struct {
		name string
		req  AdminAuthorizeRequest
	}{
		{
			name: "missing hostname",
			req:  AdminAuthorizeRequest{Hostname: "", PublicKeyPEM: "key", ApprovedBy: "bot"},
		},
		{
			name: "missing public_key_pem",
			req:  AdminAuthorizeRequest{Hostname: "host", PublicKeyPEM: "", ApprovedBy: "bot"},
		},
		{
			name: "missing approved_by",
			req:  AdminAuthorizeRequest{Hostname: "host", PublicKeyPEM: "key", ApprovedBy: ""},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, _ := json.Marshal(tt.req)
			httpReq := httptest.NewRequest("POST", "/api/admin/authorize", bytes.NewReader(body))
			httpReq.Header.Set("Authorization", "Bearer "+server.AdminToken)
			w := httptest.NewRecorder()

			AdminAuthorize(w, httpReq)

			if w.Code != http.StatusBadRequest {
				t.Errorf("expected 400, got %d", w.Code)
			}
		})
	}
}

// TestAdminAuthorizeInvalidJSON tests invalid JSON body
func TestAdminAuthorizeInvalidJSON(t *testing.T) {
	httpReq := httptest.NewRequest("POST", "/api/admin/authorize", bytes.NewBufferString("invalid"))
	httpReq.Header.Set("Authorization", "Bearer "+server.AdminToken)
	w := httptest.NewRecorder()

	AdminAuthorize(w, httpReq)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

// TestAdminAuthorizeMethodNotAllowed tests non-POST method
func TestAdminAuthorizeMethodNotAllowed(t *testing.T) {
	httpReq := httptest.NewRequest("GET", "/api/admin/authorize", nil)
	w := httptest.NewRecorder()

	AdminAuthorize(w, httpReq)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// TestTokenRefreshSuccess tests successful token refresh with encrypted response
func TestTokenRefreshSuccess(t *testing.T) {
	if server == nil || server.PrivateKey == nil {
		t.Skip("server state not initialized")
	}

	// Pre-enroll an agent so TokenRefresh can look up the public key
	_, agentPubPEM := genRSAPubPEM(t, 4096)
	hostname := "test-agent-05"
	preAuthorize(t, hostname, agentPubPEM)
	if _, err := registerStore.RegisterAgent(context.Background(), hostname, agentPubPEM, "initial-jti"); err != nil {
		t.Fatalf("RegisterAgent (setup): %v", err)
	}

	// Create a challenge encrypted with server's public key using SHA-256
	challenge := "test-challenge"
	ciphertext, err := rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		&server.PrivateKey.PublicKey,
		[]byte(challenge),
		nil,
	)
	if err != nil {
		t.Fatalf("failed to encrypt challenge: %v", err)
	}

	req := TokenRefreshRequest{
		Hostname:           hostname,
		ChallengeEncrypted: base64.StdEncoding.EncodeToString(ciphertext),
	}

	body, _ := json.Marshal(req)
	httpReq := httptest.NewRequest("POST", "/api/token/refresh", bytes.NewReader(body))
	w := httptest.NewRecorder()

	TokenRefresh(w, httpReq)

	if w.Code != http.StatusOK {
		t.Errorf("TokenRefresh: expected 200, got %d — body: %s", w.Code, w.Body.String())
		return
	}

	var resp map[string]string
	json.Unmarshal(w.Body.Bytes(), &resp)

	if resp["token_encrypted"] == "" {
		t.Error("expected token_encrypted in response, got empty")
	}
	if resp["server_public_key_pem"] == "" {
		t.Error("expected server_public_key_pem in response, got empty")
	}
	// Ensure plain token is NOT returned
	if resp["token"] != "" {
		t.Error("response must not contain plaintext 'token' field")
	}
}

// TestTokenRefreshAgentNotFound tests token refresh for unknown agent
func TestTokenRefreshAgentNotFound(t *testing.T) {
	if server == nil || server.PrivateKey == nil {
		t.Skip("server state not initialized")
	}

	challenge := "test"
	ciphertext, _ := rsa.EncryptOAEP(sha256.New(), rand.Reader, &server.PrivateKey.PublicKey, []byte(challenge), nil)

	req := TokenRefreshRequest{
		Hostname:           "nonexistent-host-xyz",
		ChallengeEncrypted: base64.StdEncoding.EncodeToString(ciphertext),
	}

	body, _ := json.Marshal(req)
	httpReq := httptest.NewRequest("POST", "/api/token/refresh", bytes.NewReader(body))
	w := httptest.NewRecorder()

	TokenRefresh(w, httpReq)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}
}

// TestTokenRefreshInvalidChallenge tests invalid challenge encoding
func TestTokenRefreshInvalidChallenge(t *testing.T) {
	req := TokenRefreshRequest{
		Hostname:           "test-agent-06",
		ChallengeEncrypted: "not-base64!!!",
	}

	body, _ := json.Marshal(req)
	httpReq := httptest.NewRequest("POST", "/api/token/refresh", bytes.NewReader(body))
	w := httptest.NewRecorder()

	TokenRefresh(w, httpReq)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}
}

// TestTokenRefreshInvalidJSON tests invalid JSON body
func TestTokenRefreshInvalidJSON(t *testing.T) {
	httpReq := httptest.NewRequest("POST", "/api/token/refresh", bytes.NewBufferString("invalid"))
	w := httptest.NewRecorder()

	TokenRefresh(w, httpReq)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

// TestTokenRefreshMethodNotAllowed tests non-POST method
func TestTokenRefreshMethodNotAllowed(t *testing.T) {
	httpReq := httptest.NewRequest("GET", "/api/token/refresh", nil)
	w := httptest.NewRecorder()

	TokenRefresh(w, httpReq)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}
