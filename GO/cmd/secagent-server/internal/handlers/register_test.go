package handlers

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
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

// TestRegisterAgentSuccess tests a successful registration (enrollment token + nonce challenge, #192c)
func TestRegisterAgentSuccess(t *testing.T) {
	// Must use 4096-bit key: RSA-OAEP/SHA-256 with 2048-bit key can only
	// encrypt ~190 bytes, but a JWT is ~300 bytes.
	privKey, pubKeyPEM := genRSAPubPEM(t, 4096)
	// unique per execution: the store of the handler tests is process-wide, a test must be replayable (-count=N)
	run := uniqueRun()
	hostname := "test-agent-01-" + run
	token := "secagent_enr_register_success_" + run
	insertEnrollmentToken(t, "tok-register-success-"+run, token, hostname, false, nil)

	code, resp := fullEnrollment(t, hostname, token, privKey, pubKeyPEM)
	if code != http.StatusOK || resp == nil {
		t.Fatalf("RegisterAgent: expected 200, got %d", code)
	}
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

// TestRegisterAgentNoTokenWhateverTheKey: without an enrollment token the answer is the same 403
// whether the key is pre-authorized, different or unknown (#192c: no oracle, no tokenless flow).
func TestRegisterAgentNoTokenWhateverTheKey(t *testing.T) {
	_, authorizedPEM := genRSAPubPEM(t, 4096)
	_, differentPEM := genRSAPubPEM(t, 4096)
	hostname := "test-agent-mismatch"
	preAuthorize(t, hostname, authorizedPEM)
	for name, key := range map[string]string{"the authorized key": authorizedPEM, "a different key": differentPEM} {
		w := tokenlessRegister(hostname, key)
		var resp map[string]string
		mustUnmarshal(t, w.Body.Bytes(), &resp)
		if w.Code != http.StatusForbidden || resp["error"] != "enrollment_token_required" {
			t.Errorf("%s: %d %v, want 403 enrollment_token_required", name, w.Code, resp)
		}
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

// ── writeJSON content-type regression tests ───────────────────────────────────
// These tests guard against accidental removal of Content-Type: application/json
// on error paths after the errcheck fix (all fmt.Fprintf → writeJSON migration).

// TestRegisterAgent_ContentTypeOnError verifies that error responses from
// RegisterAgent carry Content-Type: application/json.
func TestRegisterAgent_ContentTypeOnError(t *testing.T) {
	// Missing body → 400 from RegisterAgent
	httpReq := httptest.NewRequest("POST", "/api/enroll", bytes.NewBufferString(""))
	w := httptest.NewRecorder()
	RegisterAgent(w, httpReq)

	ct := w.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("RegisterAgent error response: expected Content-Type application/json, got %q", ct)
	}
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 on empty body, got %d", w.Code)
	}
	// Body must be valid JSON with "error" key
	var body map[string]string
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Errorf("error response body is not valid JSON: %v", err)
	}
	if body["error"] == "" {
		t.Errorf("expected non-empty 'error' field in response JSON, got %v", body)
	}
}

// TestAdminAuthorize_ContentTypeOnError verifies Content-Type on AdminAuthorize errors.
func TestAdminAuthorize_ContentTypeOnError(t *testing.T) {
	httpReq := httptest.NewRequest("POST", "/api/admin/authorize", bytes.NewBufferString(""))
	w := httptest.NewRecorder()
	AdminAuthorize(w, httpReq)

	ct := w.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("AdminAuthorize error response: expected Content-Type application/json, got %q", ct)
	}
}

// spyReadCloser wraps an io.Reader and records how many times Close() was called.
// Used to verify that handlers always close the request body.
type spyReadCloser struct {
	io.Reader
	closeCalled int
}

func (s *spyReadCloser) Close() error {
	s.closeCalled++
	return nil
}

// TestRegisterAgent_BodyClosedOnDecodeError verifies that the request body is
// closed on the decode-error path (defer placed before decode).
// Discriminant: removing the defer makes closeCalled==0, failing the assertion.
func TestRegisterAgent_BodyClosedOnDecodeError(t *testing.T) {
	t.Run("decode_error_path", func(t *testing.T) {
		spy := &spyReadCloser{Reader: bytes.NewBufferString("invalid-json{")}
		httpReq := httptest.NewRequest("POST", "/api/enroll", nil)
		httpReq.Body = spy
		w := httptest.NewRecorder()
		RegisterAgent(w, httpReq)
		if w.Code != http.StatusBadRequest {
			t.Errorf("expected 400 on invalid JSON, got %d", w.Code)
		}
		if spy.closeCalled == 0 {
			t.Error("Body.Close() was NOT called on decode error — defer may be misplaced")
		}
	})

	t.Run("success_path", func(t *testing.T) {
		_, pubKeyPEM := genRSAPubPEM(t, 4096)
		run := uniqueRun()
		hostname := "spy-test-agent-01-" + run
		token := "secagent_enr_spy_body_closed_" + run
		insertEnrollmentToken(t, "tok-spy-"+run, token, hostname, false, nil)

		req := RegisterRequest{
			Hostname:        hostname,
			PublicKeyPEM:    pubKeyPEM,
			EnrollmentToken: token, // step 1: a valid token gets the nonce challenge (200)
		}
		body, _ := json.Marshal(req)
		spy := &spyReadCloser{Reader: bytes.NewReader(body)}
		httpReq := httptest.NewRequest("POST", "/api/enroll", nil)
		httpReq.Body = spy
		w := httptest.NewRecorder()
		RegisterAgent(w, httpReq)
		if w.Code != http.StatusOK {
			t.Errorf("expected 200 on a valid step 1, got %d — body: %s", w.Code, w.Body.String())
		}
		if spy.closeCalled == 0 {
			t.Error("Body.Close() was NOT called on success path — defer may be misplaced")
		}
	})
}

// uniqueRun is a short identifier unique per call (not per process): ids, tokens and hostnames built
// from it can be created again by a replayed test (-count=N) in the process-wide store.
func uniqueRun() string { return strconv.FormatInt(time.Now().UnixNano(), 36) }
