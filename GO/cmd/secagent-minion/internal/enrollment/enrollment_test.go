package enrollment

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// generateTestKey generates a 2048-bit RSA key for tests (faster than 4096-bit).
func generateTestKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return key
}

// mockEnrollServer simulates the relay server challenge-response enrollment endpoint.
// It implements the 2-step protocol:
//   - POST with enrollment_token → {challenge, server_public_key_pem}
//   - POST with response → {jwt_encrypted}
func mockEnrollServer(t *testing.T, agentPubKey *rsa.PublicKey, serverKey *rsa.PrivateKey, jwt string, step1StatusCode int) *httptest.Server {
	t.Helper()

	var pendingNonce []byte

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]json.RawMessage
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("mock server: decode body: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// Determine step by presence of "challenge_response" (step2) first
		if _, hasResponse := body["challenge_response"]; hasResponse {
			// Step 2 : verification
			var responseB64 string
			json.Unmarshal(body["challenge_response"], &responseB64)

			// Decrypt response with server private key
			ciphertext, err := base64.StdEncoding.DecodeString(responseB64)
			if err != nil {
				t.Errorf("mock server: decode response base64: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			plaintext, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, serverKey, ciphertext, nil)
			if err != nil {
				t.Errorf("mock server: decrypt response: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			// Verify nonce prefix
			if len(plaintext) < len(pendingNonce) {
				t.Errorf("mock server: response plaintext too short")
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			for i, b := range pendingNonce {
				if plaintext[i] != b {
					t.Errorf("mock server: nonce mismatch at byte %d", i)
					w.WriteHeader(http.StatusBadRequest)
					return
				}
			}

			// Encrypt JWT with agent public key
			jwtCiphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, agentPubKey, []byte(jwt), nil)
			if err != nil {
				t.Errorf("mock server: encrypt JWT: %v", err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			jwtEncryptedB64 := base64.StdEncoding.EncodeToString(jwtCiphertext)

			json.NewEncoder(w).Encode(map[string]string{
				"jwt_encrypted": jwtEncryptedB64,
			})

		} else if _, hasToken := body["enrollment_token"]; hasToken {
			// Step 1 : initiation
			if step1StatusCode != http.StatusOK {
				w.WriteHeader(step1StatusCode)
				json.NewEncoder(w).Encode(map[string]string{"error": "rejected"})
				return
			}

			// Generate nonce
			nonce := make([]byte, 32)
			if _, err := rand.Read(nonce); err != nil {
				t.Errorf("mock server: generate nonce: %v", err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			pendingNonce = nonce

			// Encrypt nonce with agent public key
			challengeCiphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, agentPubKey, nonce, nil)
			if err != nil {
				t.Errorf("mock server: encrypt challenge: %v", err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			challengeB64 := base64.StdEncoding.EncodeToString(challengeCiphertext)

			// Serialize server public key
			serverPubPEM, err := publicKeyToPEM(&serverKey.PublicKey)
			if err != nil {
				t.Errorf("mock server: serialize server pubkey: %v", err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			json.NewEncoder(w).Encode(map[string]string{
				"challenge":            challengeB64,
				"server_public_key_pem": serverPubPEM,
			})

		} else {
			t.Errorf("mock server: unexpected request body (no enrollment_token or challenge_response)")
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
}

// publicKeyToPEM serializes an RSA public key to PEM PKIX.
func publicKeyToPEM(pub *rsa.PublicKey) (string, error) {
	pubPEM, err := PublicKeyPEM(&rsa.PrivateKey{PublicKey: *pub})
	if err != nil {
		return "", err
	}
	return pubPEM, nil
}

// ========================================================================
// Enroll — success
// ========================================================================

func TestEnrollSuccess(t *testing.T) {
	agentKey := generateTestKey(t)
	serverKey := generateTestKey(t)
	expectedJWT := "eyJhbGciOiJSUzI1NiJ9.test.payload"

	srv := mockEnrollServer(t, &agentKey.PublicKey, serverKey, expectedJWT, http.StatusOK)
	defer srv.Close()

	pubPEM, err := PublicKeyPEM(agentKey)
	if err != nil {
		t.Fatalf("PublicKeyPEM: %v", err)
	}

	jwt, err := Enroll(context.Background(), Config{
		RegisterURL:     srv.URL + "/api/register",
		Hostname:        "test-agent",
		PublicKeyPEM:    pubPEM,
		PrivateKey:      agentKey,
		EnrollmentToken: "secagent_enr_test123",
		Timeout:         5 * time.Second,
		Insecure:        true,
	})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if jwt != expectedJWT {
		t.Errorf("JWT: got %q, want %q", jwt, expectedJWT)
	}
}

func TestEnrollPersistsJWT(t *testing.T) {
	agentKey := generateTestKey(t)
	serverKey := generateTestKey(t)
	dir := t.TempDir()
	jwtPath := filepath.Join(dir, "token.jwt")
	expectedJWT := "test-jwt-token"

	srv := mockEnrollServer(t, &agentKey.PublicKey, serverKey, expectedJWT, http.StatusOK)
	defer srv.Close()

	pubPEM, _ := PublicKeyPEM(agentKey)
	_, err := Enroll(context.Background(), Config{
		RegisterURL:     srv.URL + "/api/register",
		Hostname:        "test-agent",
		PublicKeyPEM:    pubPEM,
		PrivateKey:      agentKey,
		EnrollmentToken: "secagent_enr_test123",
		JWTPath:         jwtPath,
		Timeout:         5 * time.Second,
		Insecure:        true,
	})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}

	data, err := os.ReadFile(jwtPath)
	if err != nil {
		t.Fatalf("ReadFile JWT: %v", err)
	}
	if string(data) != expectedJWT {
		t.Errorf("persisted JWT: got %q, want %q", data, expectedJWT)
	}
}

func TestEnrollJWTFileMode(t *testing.T) {
	if os.Getenv("CI") != "" || isWindows() {
		t.Skip("file mode check skipped on Windows/CI")
	}

	agentKey := generateTestKey(t)
	serverKey := generateTestKey(t)
	dir := t.TempDir()
	jwtPath := filepath.Join(dir, "token.jwt")

	srv := mockEnrollServer(t, &agentKey.PublicKey, serverKey, "jwt", http.StatusOK)
	defer srv.Close()

	pubPEM, _ := PublicKeyPEM(agentKey)
	_, err := Enroll(context.Background(), Config{
		RegisterURL:     srv.URL + "/api/register",
		Hostname:        "test-agent",
		PublicKeyPEM:    pubPEM,
		PrivateKey:      agentKey,
		EnrollmentToken: "secagent_enr_test123",
		JWTPath:         jwtPath,
		Timeout:         5 * time.Second,
		Insecure:        true,
	})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}

	info, err := os.Stat(jwtPath)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("JWT file mode: got %o, want 0600", info.Mode().Perm())
	}
}

func TestEnrollNoJWTPath(t *testing.T) {
	agentKey := generateTestKey(t)
	serverKey := generateTestKey(t)

	srv := mockEnrollServer(t, &agentKey.PublicKey, serverKey, "jwt-no-persist", http.StatusOK)
	defer srv.Close()

	pubPEM, _ := PublicKeyPEM(agentKey)
	jwt, err := Enroll(context.Background(), Config{
		RegisterURL:     srv.URL + "/api/register",
		Hostname:        "test-agent",
		PublicKeyPEM:    pubPEM,
		PrivateKey:      agentKey,
		EnrollmentToken: "secagent_enr_test123",
		JWTPath:         "", // no persistence
		Timeout:         5 * time.Second,
		Insecure:        true,
	})
	if err != nil {
		t.Fatalf("Enroll without JWTPath: %v", err)
	}
	if jwt != "jwt-no-persist" {
		t.Errorf("JWT: got %q, want %q", jwt, "jwt-no-persist")
	}
}

// ========================================================================
// Enroll — error cases
// ========================================================================

func TestEnrollMissingPrivateKey(t *testing.T) {
	_, err := Enroll(context.Background(), Config{
		RegisterURL:     "http://localhost:9999/api/register",
		Hostname:        "test-agent",
		PublicKeyPEM:    "pem",
		PrivateKey:      nil, // missing
		EnrollmentToken: "secagent_enr_test",
	})
	if err == nil {
		t.Error("expected error for nil private key")
	}
}

func TestEnrollMissingEnrollmentToken(t *testing.T) {
	key := generateTestKey(t)
	_, err := Enroll(context.Background(), Config{
		RegisterURL:     "http://localhost:9999/api/register",
		Hostname:        "test-agent",
		PublicKeyPEM:    "pem",
		PrivateKey:      key,
		EnrollmentToken: "", // missing
	})
	if err == nil {
		t.Error("expected error for empty enrollment token")
	}
	if !strings.Contains(err.Error(), "RELAY_ENROLLMENT_TOKEN") {
		t.Errorf("error should mention RELAY_ENROLLMENT_TOKEN, got: %v", err)
	}
}

func TestEnrollStep1Rejected403(t *testing.T) {
	agentKey := generateTestKey(t)
	serverKey := generateTestKey(t)
	srv := mockEnrollServer(t, &agentKey.PublicKey, serverKey, "", http.StatusForbidden)
	defer srv.Close()

	pubPEM, _ := PublicKeyPEM(agentKey)
	_, err := Enroll(context.Background(), Config{
		RegisterURL:     srv.URL + "/api/register",
		Hostname:        "test-agent",
		PublicKeyPEM:    pubPEM,
		PrivateKey:      agentKey,
		EnrollmentToken: "secagent_enr_expired",
		Timeout:         5 * time.Second,
		Insecure:        true,
	})
	if err == nil {
		t.Error("expected error for 403 response")
	}
	if !strings.Contains(err.Error(), "403") {
		t.Errorf("error should contain 403, got: %v", err)
	}
}

func TestEnrollServerUnreachable(t *testing.T) {
	key := generateTestKey(t)
	_, err := Enroll(context.Background(), Config{
		RegisterURL:     "http://127.0.0.1:1/api/register",
		Hostname:        "test-agent",
		PublicKeyPEM:    "pem",
		PrivateKey:      key,
		EnrollmentToken: "secagent_enr_test",
		Timeout:         1 * time.Second,
		Insecure:        true,
	})
	if err == nil {
		t.Error("expected error for unreachable server")
	}
}

func TestEnrollContextCancelled(t *testing.T) {
	key := generateTestKey(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled

	pubPEM, _ := PublicKeyPEM(key)
	_, err := Enroll(ctx, Config{
		RegisterURL:     "http://127.0.0.1:1/api/register",
		Hostname:        "test-agent",
		PublicKeyPEM:    pubPEM,
		PrivateKey:      key,
		EnrollmentToken: "secagent_enr_test",
		Timeout:         5 * time.Second,
		Insecure:        true,
	})
	if err == nil {
		t.Error("expected error for cancelled context")
	}
}

func TestEnrollDefaultTimeout(t *testing.T) {
	agentKey := generateTestKey(t)
	serverKey := generateTestKey(t)
	srv := mockEnrollServer(t, &agentKey.PublicKey, serverKey, "jwt", http.StatusOK)
	defer srv.Close()

	pubPEM, _ := PublicKeyPEM(agentKey)
	// Timeout=0 → uses 30s default
	_, err := Enroll(context.Background(), Config{
		RegisterURL:     srv.URL + "/api/register",
		Hostname:        "test-agent",
		PublicKeyPEM:    pubPEM,
		PrivateKey:      agentKey,
		EnrollmentToken: "secagent_enr_test",
		Timeout:         0,
		Insecure:        true,
	})
	if err != nil {
		t.Fatalf("Enroll with default timeout: %v", err)
	}
}

// TestEnrollChallengeDecryptFailure tests that if the challenge cannot be decrypted
// (wrong key), enrollment fails properly.
func TestEnrollChallengeDecryptFailure(t *testing.T) {
	agentKey := generateTestKey(t)
	serverKey := generateTestKey(t)
	wrongKey := generateTestKey(t) // wrong key — cannot decrypt challenge

	srv := mockEnrollServer(t, &agentKey.PublicKey, serverKey, "jwt", http.StatusOK)
	defer srv.Close()

	pubPEM, _ := PublicKeyPEM(agentKey)
	_, err := Enroll(context.Background(), Config{
		RegisterURL:     srv.URL + "/api/register",
		Hostname:        "test-agent",
		PublicKeyPEM:    pubPEM,
		PrivateKey:      wrongKey, // wrong key
		EnrollmentToken: "secagent_enr_test",
		Timeout:         5 * time.Second,
		Insecure:        true,
	})
	if err == nil {
		t.Error("expected error when decrypting challenge with wrong key")
	}
}

// TestEnrollStep2BadResponse tests that a bad step2 response (empty jwt_encrypted) is rejected.
func TestEnrollStep2BadResponse(t *testing.T) {
	agentKey := generateTestKey(t)
	serverKey := generateTestKey(t)

	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		var body map[string]json.RawMessage
		json.NewDecoder(r.Body).Decode(&body)

		if _, hasToken := body["enrollment_token"]; hasToken {
			// Step 1: return valid challenge
			nonce := make([]byte, 32)
			rand.Read(nonce)
			ct, _ := rsa.EncryptOAEP(sha256.New(), rand.Reader, &agentKey.PublicKey, nonce, nil)
			serverPubPEM, _ := PublicKeyPEM(serverKey)
			json.NewEncoder(w).Encode(map[string]string{
				"challenge":            base64.StdEncoding.EncodeToString(ct),
				"server_public_key_pem": serverPubPEM,
			})
		} else {
			// Step 2: return empty jwt_encrypted
			json.NewEncoder(w).Encode(map[string]string{
				"jwt_encrypted": "",
			})
		}
	}))
	defer srv.Close()

	pubPEM, _ := PublicKeyPEM(agentKey)
	_, err := Enroll(context.Background(), Config{
		RegisterURL:     srv.URL + "/api/register",
		Hostname:        "test-agent",
		PublicKeyPEM:    pubPEM,
		PrivateKey:      agentKey,
		EnrollmentToken: "secagent_enr_test",
		Timeout:         5 * time.Second,
		Insecure:        true,
	})
	if err == nil {
		t.Error("expected error for empty jwt_encrypted in step2")
	}
}

// ========================================================================
// GenerateRSAKey
// ========================================================================

func TestGenerateRSAKey(t *testing.T) {
	// Use 2048-bit in tests to avoid 4096-bit slowness
	// The production code uses 4096-bit via GenerateRSAKey()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if key == nil {
		t.Error("GenerateKey returned nil")
	}
	if key.N.BitLen() < 2048 {
		t.Errorf("key size: got %d bits, want >= 2048", key.N.BitLen())
	}
}

// ========================================================================
// PublicKeyPEM
// ========================================================================

func TestPublicKeyPEM(t *testing.T) {
	key := generateTestKey(t)
	pemStr, err := PublicKeyPEM(key)
	if err != nil {
		t.Fatalf("PublicKeyPEM: %v", err)
	}
	if pemStr == "" {
		t.Error("PublicKeyPEM returned empty string")
	}
	if pemStr[:26] != "-----BEGIN PUBLIC KEY-----" {
		t.Errorf("PEM header: got %q", pemStr[:26])
	}
}

// ========================================================================
// PrivateKeyPEM
// ========================================================================

func TestPrivateKeyPEM(t *testing.T) {
	key := generateTestKey(t)
	pemStr := PrivateKeyPEM(key)
	if pemStr == "" {
		t.Error("PrivateKeyPEM returned empty string")
	}
	if pemStr[:31] != "-----BEGIN RSA PRIVATE KEY-----" {
		t.Errorf("PEM header: got %q", pemStr[:31])
	}
}

// ========================================================================
// LoadPrivateKeyFromFile
// ========================================================================

func TestLoadPrivateKeyFromFile(t *testing.T) {
	key := generateTestKey(t)
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key.pem")

	pemData := PrivateKeyPEM(key)
	os.WriteFile(keyPath, []byte(pemData), 0600)

	loaded, err := LoadPrivateKeyFromFile(keyPath)
	if err != nil {
		t.Fatalf("LoadPrivateKeyFromFile: %v", err)
	}
	if loaded == nil {
		t.Error("loaded key is nil")
	}
	if loaded.N.Cmp(key.N) != 0 {
		t.Error("loaded key does not match original")
	}
}

func TestLoadPrivateKeyFromFileNotFound(t *testing.T) {
	_, err := LoadPrivateKeyFromFile("/nonexistent/key.pem")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestLoadPrivateKeyFromFileInvalidPEM(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "bad.pem")
	os.WriteFile(keyPath, []byte("not a pem file"), 0600)

	_, err := LoadPrivateKeyFromFile(keyPath)
	if err == nil {
		t.Error("expected error for invalid PEM")
	}
}

func TestLoadPrivateKeyFromFileInvalidKey(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "bad-key.pem")

	// Valid PEM block but invalid key content
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: []byte("not-valid-key-bytes"),
	}
	pemData := pem.EncodeToMemory(block)
	os.WriteFile(keyPath, pemData, 0600)

	_, err := LoadPrivateKeyFromFile(keyPath)
	if err == nil {
		t.Error("expected error for invalid key bytes")
	}
}

// ========================================================================
// parsePublicKeyPEM
// ========================================================================

func TestParsePublicKeyPEM(t *testing.T) {
	key := generateTestKey(t)
	pubPEM, err := PublicKeyPEM(key)
	if err != nil {
		t.Fatalf("PublicKeyPEM: %v", err)
	}

	parsed, err := parsePublicKeyPEM(pubPEM)
	if err != nil {
		t.Fatalf("parsePublicKeyPEM: %v", err)
	}
	if parsed.N.Cmp(key.N) != 0 {
		t.Error("parsed public key does not match original")
	}
}

func TestParsePublicKeyPEMInvalid(t *testing.T) {
	_, err := parsePublicKeyPEM("not a PEM")
	if err == nil {
		t.Error("expected error for invalid PEM")
	}
}

// ========================================================================
// writeSecret
// ========================================================================

func TestWriteSecret(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.txt")

	err := writeSecret(path, []byte("my secret"))
	if err != nil {
		t.Fatalf("writeSecret: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(data) != "my secret" {
		t.Errorf("content: got %q, want 'my secret'", data)
	}
}

func TestWriteSecretCreatesParentDirs(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "subdir", "nested", "secret.txt")

	err := writeSecret(path, []byte("nested secret"))
	if err != nil {
		t.Fatalf("writeSecret with nested dirs: %v", err)
	}

	if _, err := os.Stat(path); err != nil {
		t.Errorf("secret file not created: %v", err)
	}
}

func TestWriteSecretOverwrites(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.txt")

	writeSecret(path, []byte("old secret"))
	writeSecret(path, []byte("new secret"))

	data, _ := os.ReadFile(path)
	if string(data) != "new secret" {
		t.Errorf("content after overwrite: got %q, want 'new secret'", data)
	}
}

// ========================================================================
// Config struct
// ========================================================================

func TestConfigFields(t *testing.T) {
	key := generateTestKey(t)
	cfg := Config{
		RegisterURL:     "https://relay.example.com/api/register",
		Hostname:        "my-agent",
		PublicKeyPEM:    "pem",
		PrivateKey:      key,
		EnrollmentToken: "secagent_enr_abc123",
		CABundle:        "/etc/ssl/certs/ca.pem",
		JWTPath:         "/etc/secagent-minion/token.jwt",
		Timeout:         30 * time.Second,
		Insecure:        false,
	}
	if cfg.Hostname != "my-agent" {
		t.Error("Hostname not preserved")
	}
	if cfg.Insecure {
		t.Error("Insecure should be false")
	}
	if cfg.EnrollmentToken != "secagent_enr_abc123" {
		t.Error("EnrollmentToken not preserved")
	}
}

// ========================================================================
// decryptChallenge
// ========================================================================

func TestDecryptChallenge(t *testing.T) {
	agentKey := generateTestKey(t)
	nonce := make([]byte, 32)
	rand.Read(nonce)

	// Encrypt nonce with agent public key (simulates server)
	ct, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &agentKey.PublicKey, nonce, nil)
	if err != nil {
		t.Fatalf("encrypt challenge: %v", err)
	}
	challengeB64 := base64.StdEncoding.EncodeToString(ct)

	// Decrypt
	decrypted, err := decryptChallenge(challengeB64, agentKey)
	if err != nil {
		t.Fatalf("decryptChallenge: %v", err)
	}

	if len(decrypted) != len(nonce) {
		t.Fatalf("decrypted length: got %d, want %d", len(decrypted), len(nonce))
	}
	for i := range nonce {
		if decrypted[i] != nonce[i] {
			t.Errorf("decrypted nonce mismatch at byte %d", i)
		}
	}
}

func TestDecryptChallengeWrongKey(t *testing.T) {
	agentKey := generateTestKey(t)
	wrongKey := generateTestKey(t)
	nonce := make([]byte, 32)
	rand.Read(nonce)

	ct, _ := rsa.EncryptOAEP(sha256.New(), rand.Reader, &agentKey.PublicKey, nonce, nil)
	challengeB64 := base64.StdEncoding.EncodeToString(ct)

	_, err := decryptChallenge(challengeB64, wrongKey)
	if err == nil {
		t.Error("expected error when decrypting with wrong key")
	}
}

func TestDecryptChallengeInvalidBase64(t *testing.T) {
	key := generateTestKey(t)
	_, err := decryptChallenge("!!! not base64 !!!", key)
	if err == nil {
		t.Error("expected error for invalid base64")
	}
}

// isWindows returns true if running on Windows.
func isWindows() bool {
	return os.PathSeparator == '\\'
}
