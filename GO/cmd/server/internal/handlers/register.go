package handlers

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"relay-server/cmd/server/internal/crypto"
	"relay-server/cmd/server/internal/storage"
)

// RegisterRequest represents agent enrollment request.
// If EnrollmentToken is set, the enrollment-token flow is used (SECURITY.md §3).
// If ChallengeResponse is set, this is phase-2 of the challenge-response flow.
// If neither is set, the legacy authorized_keys flow is used.
type RegisterRequest struct {
	Hostname          string `json:"hostname"`
	PublicKeyPEM      string `json:"public_key_pem"`
	EnrollmentToken   string `json:"enrollment_token,omitempty"`
	ChallengeResponse string `json:"challenge_response,omitempty"` // base64 RSA-OAEP(nonce+token, server_pubkey)
}

// RegisterResponse returns encrypted JWT and server public key
type RegisterResponse struct {
	TokenEncrypted     string `json:"token_encrypted"`
	JWTEncrypted       string `json:"jwt_encrypted"`      // alias — same value, for enrollment-token flow compatibility
	ServerPublicKeyPEM string `json:"server_public_key_pem"`
}

// ChallengeResponse is returned in phase-1 of the enrollment-token flow.
type ChallengeResponse struct {
	Challenge        string `json:"challenge"`              // base64 RSA-OAEP(nonce, agent_pubkey)
	ServerPublicKey  string `json:"server_public_key_pem"` // server RSA public key for step2 encryption
}

// AdminAuthorizeRequest pre-authorizes a public key
type AdminAuthorizeRequest struct {
	Hostname     string `json:"hostname"`
	PublicKeyPEM string `json:"public_key_pem"`
	ApprovedBy   string `json:"approved_by"`
}

// TokenRefreshRequest refreshes an agent JWT
type TokenRefreshRequest struct {
	Hostname           string `json:"hostname"`
	ChallengeEncrypted string `json:"challenge_encrypted"`
}

// ServerState holds global server state (RSA keypair + JWT secrets).
// Loaded from DB at startup; updated in-memory during rotation.
type ServerState struct {
	mu sync.RWMutex

	// RSA keypair — current (always set), previous (set during rotation)
	PrivateKey         *rsa.PrivateKey
	PublicPEM          string
	PreviousPrivateKey *rsa.PrivateKey // nil if no rotation in progress

	// JWT secrets — current always set, previous set during grace period
	JWTSecret         string
	JWTPreviousSecret string // empty if no rotation in progress

	// Rotation deadline — zero value = no rotation in progress
	KeyRotationDeadline time.Time

	AdminToken string
	JWTttl     time.Duration
}

// GetJWTSecrets returns (current, previous, deadline) for dual-key validation.
// previous is empty string if no rotation is active.
// deadline is zero if no rotation is active.
func (s *ServerState) GetJWTSecrets() (current, previous string, deadline time.Time) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.JWTSecret, s.JWTPreviousSecret, s.KeyRotationDeadline
}

// GetServerJWTSecrets is the package-level function injected into ws.SetJWTSecretsFunc.
func GetServerJWTSecrets() (current, previous string, deadline time.Time) {
	return server.GetJWTSecrets()
}

var server *ServerState

// registerStore is the shared store injected at server startup.
var registerStore *storage.Store

// SetRegisterStore injects the storage.Store instance used by register/token handlers.
// Must be called once at server startup before serving requests.
func SetRegisterStore(s *storage.Store) {
	registerStore = s
}

func init() {
	// Minimal init: load admin token from env.
	// RSA + JWT secrets are loaded from DB via InitServerState().
	adminToken := os.Getenv("ADMIN_TOKEN")
	if adminToken == "" {
		log.Fatal("ADMIN_TOKEN environment variable not set")
	}
	secret := os.Getenv("JWT_SECRET_KEY")
	if secret == "" {
		log.Fatal("JWT_SECRET_KEY environment variable not set")
	}

	// Bootstrap server state with env-provided secret (overridden by DB in InitServerState).
	// This allows tests that don't call InitServerState to still work.
	server = &ServerState{
		JWTSecret:  secret,
		AdminToken: adminToken,
		JWTttl:     time.Hour,
	}
}

// rsaMasterKey returns the RSA_MASTER_KEY env var.
// Returns ("", false) when the variable is absent (dev/test mode — keys stored unencrypted).
// In production the variable must be set; InitServerState will log a warning if absent.
func rsaMasterKey() (string, bool) {
	v := os.Getenv("RSA_MASTER_KEY")
	return v, v != ""
}

// persistRSAKey encrypts privPEM with AES-256-GCM (when masterKey is set) and stores it.
func persistRSAKey(ctx context.Context, store *storage.Store, configKey, privPEM string) error {
	masterKey, hasMaster := rsaMasterKey()
	var toStore string
	if hasMaster {
		encrypted, err := crypto.EncryptAESGCM(privPEM, masterKey)
		if err != nil {
			return fmt.Errorf("encrypt %s: %w", configKey, err)
		}
		toStore = "enc:" + encrypted // prefix to distinguish encrypted from plaintext
	} else {
		toStore = privPEM // unencrypted — dev/test mode
	}
	return store.ConfigSet(ctx, configKey, toStore)
}

// loadRSAKey retrieves and decrypts (if needed) a stored RSA private key PEM.
func loadRSAKey(ctx context.Context, store *storage.Store, configKey string) (string, error) {
	stored, err := store.ConfigGet(ctx, configKey)
	if err != nil || stored == "" {
		return stored, err
	}

	if len(stored) > 4 && stored[:4] == "enc:" {
		masterKey, hasMaster := rsaMasterKey()
		if !hasMaster {
			return "", fmt.Errorf("RSA_MASTER_KEY required to decrypt %s", configKey)
		}
		plaintext, err := crypto.DecryptAESGCM(stored[4:], masterKey)
		if err != nil {
			return "", fmt.Errorf("decrypt %s: %w", configKey, err)
		}
		return plaintext, nil
	}

	// Unencrypted (dev/test mode or legacy)
	return stored, nil
}

// InitServerState loads (or generates) RSA keypair and JWT secret from DB.
// Must be called once at server startup, after the store is ready.
// If keys are absent in DB they are generated and persisted.
// RSA private key is encrypted with AES-256-GCM when RSA_MASTER_KEY is set.
func InitServerState(ctx context.Context, store *storage.Store) error {
	server.mu.Lock()
	defer server.mu.Unlock()

	masterKey, hasMaster := rsaMasterKey()
	_ = masterKey
	if !hasMaster {
		log.Println("[WARN] RSA_MASTER_KEY not set — RSA private key stored unencrypted (dev mode only)")
	}

	// --- JWT secret ---
	jwtCurrent, err := store.ConfigGet(ctx, "jwt_secret_current")
	if err != nil {
		return fmt.Errorf("ConfigGet jwt_secret_current: %w", err)
	}
	if jwtCurrent == "" {
		// First boot: persist the env-provided secret
		jwtCurrent = server.JWTSecret
		if err := store.ConfigSet(ctx, "jwt_secret_current", jwtCurrent); err != nil {
			return fmt.Errorf("ConfigSet jwt_secret_current: %w", err)
		}
		log.Println("[INIT] JWT secret persisted to DB")
	} else {
		server.JWTSecret = jwtCurrent
		log.Println("[INIT] JWT secret loaded from DB")
	}

	// Load previous JWT secret (may be empty)
	jwtPrev, err := store.ConfigGet(ctx, "jwt_secret_previous")
	if err != nil {
		return fmt.Errorf("ConfigGet jwt_secret_previous: %w", err)
	}
	server.JWTPreviousSecret = jwtPrev

	// Load rotation deadline (may be empty)
	deadlineStr, err := store.ConfigGet(ctx, "key_rotation_deadline")
	if err != nil {
		return fmt.Errorf("ConfigGet key_rotation_deadline: %w", err)
	}
	if deadlineStr != "" {
		if t, err := time.Parse(time.RFC3339, deadlineStr); err == nil {
			server.KeyRotationDeadline = t
		}
	}

	// --- RSA keypair (current) ---
	rsaCurrentPEM, err := loadRSAKey(ctx, store, "rsa_key_current")
	if err != nil {
		return fmt.Errorf("load rsa_key_current: %w", err)
	}

	if rsaCurrentPEM == "" {
		// First boot: generate RSA-4096 and persist (encrypted if RSA_MASTER_KEY set)
		log.Println("[INIT] Generating RSA-4096 keypair (first boot)...")
		privKey, err := rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			return fmt.Errorf("RSA key generation: %w", err)
		}

		privPEM, pubPEM, err := encodeRSAKeyPair(privKey)
		if err != nil {
			return fmt.Errorf("RSA key encoding: %w", err)
		}

		if err := persistRSAKey(ctx, store, "rsa_key_current", privPEM); err != nil {
			return fmt.Errorf("persist rsa_key_current: %w", err)
		}

		server.PrivateKey = privKey
		server.PublicPEM = pubPEM
		log.Printf("[OK] RSA-4096 keypair generated and persisted (encrypted=%v)", hasMaster)
	} else {
		// Load and decode existing keypair
		privKey, pubPEM, err := decodeRSAPrivateKey(rsaCurrentPEM)
		if err != nil {
			return fmt.Errorf("decode rsa_key_current: %w", err)
		}
		server.PrivateKey = privKey
		server.PublicPEM = pubPEM
		log.Println("[OK] RSA keypair loaded from DB")
	}

	// --- RSA keypair (previous, may be absent) ---
	rsaPrevPEM, err := loadRSAKey(ctx, store, "rsa_key_previous")
	if err != nil {
		log.Printf("[WARN] Could not load rsa_key_previous: %v", err)
	} else if rsaPrevPEM != "" {
		prevKey, _, err := decodeRSAPrivateKey(rsaPrevPEM)
		if err != nil {
			log.Printf("[WARN] Could not decode rsa_key_previous: %v", err)
		} else {
			server.PreviousPrivateKey = prevKey
		}
	}

	return nil
}

// encodeRSAKeyPair encodes a private key to PKCS8 PEM and derives the public PEM.
func encodeRSAKeyPair(privKey *rsa.PrivateKey) (privPEM, pubPEM string, err error) {
	privDER, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return "", "", fmt.Errorf("MarshalPKCS8PrivateKey: %w", err)
	}
	privPEM = string(pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privDER,
	}))

	pubDER, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return "", "", fmt.Errorf("MarshalPKIXPublicKey: %w", err)
	}
	pubPEM = string(pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubDER,
	}))

	return privPEM, pubPEM, nil
}

// decodeRSAPrivateKey parses a PKCS8 PEM private key and returns the key + derived public PEM.
func decodeRSAPrivateKey(privPEM string) (*rsa.PrivateKey, string, error) {
	block, _ := pem.Decode([]byte(privPEM))
	if block == nil {
		return nil, "", fmt.Errorf("invalid PEM block")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, "", fmt.Errorf("ParsePKCS8PrivateKey: %w", err)
	}

	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, "", fmt.Errorf("not an RSA private key")
	}

	pubDER, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	if err != nil {
		return nil, "", fmt.Errorf("MarshalPKIXPublicKey: %w", err)
	}
	pubPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubDER,
	}))

	return rsaKey, pubPEM, nil
}

// ========================================================================
// Pending-nonce store — ephemeral state between challenge phase-1 and phase-2
// ========================================================================

type pendingNonce struct {
	nonce     []byte
	token     string // original enrollment token (plain text)
	expiresAt time.Time
}

var (
	pendingNonces   = map[string]*pendingNonce{} // key: hostname
	pendingNoncesMu sync.Mutex
	nonceTTL        = 60 * time.Second
)

// storePendingNonce saves the nonce and token for a hostname.
func storePendingNonce(hostname string, nonce []byte, token string) {
	pendingNoncesMu.Lock()
	defer pendingNoncesMu.Unlock()
	pendingNonces[hostname] = &pendingNonce{
		nonce:     nonce,
		token:     token,
		expiresAt: time.Now().Add(nonceTTL),
	}
}

// consumePendingNonce removes and returns the pending nonce for a hostname, if valid.
func consumePendingNonce(hostname string) (nonce []byte, token string, ok bool) {
	pendingNoncesMu.Lock()
	defer pendingNoncesMu.Unlock()
	p, exists := pendingNonces[hostname]
	if !exists {
		return nil, "", false
	}
	delete(pendingNonces, hostname)
	if time.Now().After(p.expiresAt) {
		return nil, "", false
	}
	return p.nonce, p.token, true
}

// ========================================================================
// Enrollment token validation — SECURITY.md §3
// ========================================================================

// validateEnrollmentToken looks up and validates an enrollment token.
// Returns the token record on success, or an error code string on failure.
// Error codes: "token_not_found", "token_expired", "token_already_used", "hostname_not_allowed".
func validateEnrollmentToken(ctx context.Context, tokenPlain, hostname string) (*storage.EnrollmentToken, string) {
	// SHA-256 the raw token for DB lookup
	h := sha256.Sum256([]byte(tokenPlain))
	tokenHash := fmt.Sprintf("%x", h)

	tok, err := registerStore.GetEnrollmentTokenByHash(ctx, tokenHash)
	if err != nil {
		log.Printf("validateEnrollmentToken db: %v", err)
		return nil, "db_error"
	}
	if tok == nil {
		return nil, "token_not_found"
	}

	// Check expiry
	if tok.ExpiresAt != nil && time.Now().UTC().After(*tok.ExpiresAt) {
		return nil, "token_expired"
	}

	// Check one-shot
	if !tok.Reusable && tok.UseCount > 0 {
		return nil, "token_already_used"
	}

	// Check hostname pattern (anchored regexp ^...$)
	matched, err := storage.PluginTokenCheckHostname(tok.HostnamePattern, hostname)
	if err != nil || !matched {
		return nil, "hostname_not_allowed"
	}

	return tok, ""
}

// ========================================================================
// RegisterAgent — enrollment-token flow (SECURITY.md §3) + legacy flow
// ========================================================================

// RegisterAgent enrolls a relay-agent
// POST /api/register
func RegisterAgent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, `{"error":"invalid_request"}`)
		return
	}
	defer r.Body.Close()

	// Validate base fields
	req.Hostname = strings.TrimSpace(req.Hostname)
	req.PublicKeyPEM = strings.TrimSpace(req.PublicKeyPEM)

	if req.Hostname == "" || req.PublicKeyPEM == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, `{"error":"missing_fields"}`)
		return
	}

	if registerStore == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, `{"error":"store_not_initialized"}`)
		return
	}

	ctx := r.Context()

	// Route: enrollment-token flow vs legacy authorized_keys flow
	if req.EnrollmentToken != "" {
		registerAgentWithToken(w, r, ctx, req)
		return
	}

	// -----------------------------------------------------------------------
	// Legacy flow: authorized_keys lookup (backward-compatible)
	// -----------------------------------------------------------------------
	registerAgentLegacy(w, ctx, req)
}

// registerAgentWithToken handles enrollment-token based registration (SECURITY.md §3).
// Two phases:
//   - Phase 1: token present, no challenge_response → validate token, issue challenge
//   - Phase 2: token + challenge_response present   → verify response, issue JWT
func registerAgentWithToken(w http.ResponseWriter, r *http.Request, ctx context.Context, req RegisterRequest) {
	// Validate the enrollment token on every request (both phases)
	tok, errCode := validateEnrollmentToken(ctx, req.EnrollmentToken, req.Hostname)
	if errCode != "" {
		status := http.StatusForbidden
		if errCode == "db_error" {
			status = http.StatusInternalServerError
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		fmt.Fprintf(w, `{"error":%q}`, errCode)
		return
	}

	server.mu.RLock()
	serverPrivKey := server.PrivateKey
	pubPEM := server.PublicPEM
	jwtSecret := server.JWTSecret
	jwtTTL := server.JWTttl
	server.mu.RUnlock()

	if serverPrivKey == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, `{"error":"server_key_not_initialized"}`)
		return
	}

	// -----------------------------------------------------------------------
	// Phase 2: challenge_response present → verify, issue JWT
	// -----------------------------------------------------------------------
	if req.ChallengeResponse != "" {
		pendingNonce, pendingToken, ok := consumePendingNonce(req.Hostname)
		if !ok {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprintf(w, `{"error":"challenge_expired_or_not_issued"}`)
			return
		}

		// Decrypt response with server private key
		responseBytes, err := base64.StdEncoding.DecodeString(req.ChallengeResponse)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprintf(w, `{"error":"challenge_response_invalid_encoding"}`)
			return
		}

		decrypted, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, serverPrivKey, responseBytes, nil)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprintf(w, `{"error":"challenge_response_decryption_failed"}`)
			return
		}

		// Expected payload: nonce (16 bytes) + token (plain text)
		expected := append(pendingNonce, []byte(pendingToken)...)
		if string(decrypted) != string(expected) {
			log.Printf("RegisterAgent challenge mismatch: hostname=%s", req.Hostname)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprintf(w, `{"error":"challenge_response_mismatch"}`)
			return
		}

		// Challenge passed — issue JWT and finalize enrollment
		jti := uuid.New().String()
		now := time.Now()
		claims := jwt.MapClaims{
			"sub":  req.Hostname,
			"role": "agent",
			"jti":  jti,
			"iat":  now.Unix(),
			"exp":  now.Add(jwtTTL).Unix(),
		}
		jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		rawJWT, err := jwtToken.SignedString([]byte(jwtSecret))
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, `{"error":"jwt_generation_failed"}`)
			return
		}

		tokenEncrypted, err := encryptWithPublicKey(rawJWT, req.PublicKeyPEM)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, `{"error":"invalid_public_key"}`)
			return
		}

		// Persist: consume token (increment use_count), store authorized_key, register agent
		if err := registerStore.ConsumeEnrollmentToken(ctx, tok.ID); err != nil {
			log.Printf("RegisterAgent ConsumeEnrollmentToken: %v", err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, `{"error":"db_error"}`)
			return
		}
		if err := registerStore.AddAuthorizedKey(ctx, req.Hostname, req.PublicKeyPEM, "enrollment_token:"+tok.ID); err != nil {
			log.Printf("RegisterAgent AddAuthorizedKey: %v", err)
			// Non-fatal: continue (key may already exist from prior enrollment)
		}
		if _, err := registerStore.RegisterAgent(ctx, req.Hostname, req.PublicKeyPEM, jti); err != nil {
			log.Printf("RegisterAgent persist: %v", err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, `{"error":"db_error"}`)
			return
		}

		log.Printf("RegisterAgent enrollment complete: hostname=%s token_id=%s", req.Hostname, tok.ID)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(RegisterResponse{
			TokenEncrypted:     tokenEncrypted,
			JWTEncrypted:       tokenEncrypted,
			ServerPublicKeyPEM: pubPEM,
		})
		return
	}

	// -----------------------------------------------------------------------
	// Phase 1: no challenge_response → generate and return challenge
	// -----------------------------------------------------------------------
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, `{"error":"nonce_generation_failed"}`)
		return
	}

	// Encrypt nonce with agent's public key
	challengeEncrypted, err := encryptWithPublicKey(string(nonce), req.PublicKeyPEM)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, `{"error":"invalid_public_key"}`)
		return
	}

	// Store nonce for phase-2 verification
	storePendingNonce(req.Hostname, nonce, req.EnrollmentToken)

	log.Printf("RegisterAgent challenge issued: hostname=%s token_id=%s", req.Hostname, tok.ID)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(ChallengeResponse{
		Challenge:       challengeEncrypted,
		ServerPublicKey: pubPEM,
	})
}

// registerAgentLegacy handles the legacy authorized_keys enrollment flow (backward-compat).
func registerAgentLegacy(w http.ResponseWriter, ctx context.Context, req RegisterRequest) {
	authKey, err := registerStore.GetAuthorizedKey(ctx, req.Hostname)
	if err != nil {
		log.Printf("RegisterAgent GetAuthorizedKey: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, `{"error":"db_error"}`)
		return
	}
	if authKey == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprintf(w, `{"error":"unauthorized_hostname"}`)
		return
	}

	if strings.TrimSpace(authKey.PublicKeyPEM) != req.PublicKeyPEM {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprintf(w, `{"error":"public_key_mismatch"}`)
		return
	}

	server.mu.RLock()
	jwtSecret := server.JWTSecret
	pubPEM := server.PublicPEM
	jwtTTL := server.JWTttl
	server.mu.RUnlock()

	jti := uuid.New().String()
	now := time.Now()
	claims := jwt.MapClaims{
		"sub":  req.Hostname,
		"role": "agent",
		"jti":  jti,
		"iat":  now.Unix(),
		"exp":  now.Add(jwtTTL).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	rawJWT, err := token.SignedString([]byte(jwtSecret))
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, `{"error":"jwt_generation_failed"}`)
		return
	}

	tokenEncrypted, err := encryptWithPublicKey(rawJWT, req.PublicKeyPEM)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, `{"error":"invalid_public_key"}`)
		return
	}

	if _, err := registerStore.RegisterAgent(ctx, req.Hostname, req.PublicKeyPEM, jti); err != nil {
		log.Printf("RegisterAgent persist: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, `{"error":"db_error"}`)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(RegisterResponse{
		TokenEncrypted:     tokenEncrypted,
		ServerPublicKeyPEM: pubPEM,
	})
}

// AdminAuthorize pre-authorizes a public key (CI/CD pipeline)
// POST /api/admin/authorize
func AdminAuthorize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Check admin authorization header
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" || len(authHeader) < 7 || !strings.HasPrefix(authHeader, "Bearer ") {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, `{"error":"missing_authorization"}`)
		return
	}

	tok := authHeader[7:]
	if tok != server.AdminToken {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, `{"error":"invalid_admin_token"}`)
		return
	}

	var req AdminAuthorizeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, `{"error":"invalid_request"}`)
		return
	}
	defer r.Body.Close()

	// Validate input
	if strings.TrimSpace(req.Hostname) == "" || strings.TrimSpace(req.PublicKeyPEM) == "" || strings.TrimSpace(req.ApprovedBy) == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, `{"error":"missing_fields"}`)
		return
	}

	if registerStore == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, `{"error":"store_not_initialized"}`)
		return
	}

	if err := registerStore.AddAuthorizedKey(r.Context(), req.Hostname, req.PublicKeyPEM, req.ApprovedBy); err != nil {
		log.Printf("AdminAuthorize AddAuthorizedKey: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, `{"error":"db_error"}`)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{
		"hostname": req.Hostname,
		"status":   "authorized",
	})
}

// TokenRefresh refreshes an agent JWT
// POST /api/token/refresh
func TokenRefresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req TokenRefreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, `{"error":"invalid_request"}`)
		return
	}
	defer r.Body.Close()

	server.mu.RLock()
	privKey := server.PrivateKey
	pubPEM := server.PublicPEM
	jwtSecret := server.JWTSecret
	jwtTTL := server.JWTttl
	server.mu.RUnlock()

	if privKey == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, `{"error":"server_key_not_initialized"}`)
		return
	}

	// Step 1: Decrypt challenge with server private key
	ciphertextBytes, err := base64.StdEncoding.DecodeString(req.ChallengeEncrypted)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprintf(w, `{"error":"challenge_decryption_failed"}`)
		return
	}

	_, err = rsa.DecryptOAEP(sha256.New(), rand.Reader, privKey, ciphertextBytes, nil)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprintf(w, `{"error":"challenge_decryption_failed"}`)
		return
	}

	// Step 2: Issue new JWT with current secret
	newJTI := uuid.New().String()
	now := time.Now()
	claims := jwt.MapClaims{
		"sub":  req.Hostname,
		"role": "agent",
		"jti":  newJTI,
		"iat":  now.Unix(),
		"exp":  now.Add(jwtTTL).Unix(),
	}

	jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	rawJWT, err := jwtToken.SignedString([]byte(jwtSecret))
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, `{"error":"jwt_generation_failed"}`)
		return
	}

	// Step 3: Lookup agent public key from DB to encrypt the new JWT
	if registerStore == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, `{"error":"store_not_initialized"}`)
		return
	}

	agent, err := registerStore.GetAgent(r.Context(), req.Hostname)
	if err != nil {
		log.Printf("TokenRefresh GetAgent: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, `{"error":"db_error"}`)
		return
	}
	if agent == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprintf(w, `{"error":"agent_not_found"}`)
		return
	}

	// Step 4: Encrypt new JWT with agent's RSA public key (RSA-OAEP / SHA-256)
	tokenEncrypted, err := encryptWithPublicKey(rawJWT, agent.PublicKeyPEM)
	if err != nil {
		log.Printf("TokenRefresh encrypt: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, `{"error":"encryption_failed"}`)
		return
	}

	// Step 5: Update token JTI in DB
	if _, err := registerStore.UpdateTokenJTI(r.Context(), req.Hostname, newJTI); err != nil {
		log.Printf("TokenRefresh UpdateTokenJTI: %v", err)
		// Non-fatal: token was issued, log and continue
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"token_encrypted":       tokenEncrypted,
		"server_public_key_pem": pubPEM,
	})
}

// Helper functions

func encryptWithPublicKey(plaintext string, publicKeyPEM string) (string, error) {
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return "", fmt.Errorf("invalid PEM block")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return "", err
	}

	publicKey, ok := pub.(*rsa.PublicKey)
	if !ok {
		return "", fmt.Errorf("not an RSA public key")
	}

	ciphertext, err := rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		publicKey,
		[]byte(plaintext),
		nil,
	)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}
