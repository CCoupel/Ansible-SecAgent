package handlers

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
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

	"secagent-server/cmd/secagent-server/internal/hooks"
	"secagent-server/cmd/secagent-server/internal/state"
	"secagent-server/cmd/secagent-server/internal/storage"
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
	JWTEncrypted       string `json:"jwt_encrypted"` // alias — same value, for enrollment-token flow compatibility
	ServerPublicKeyPEM string `json:"server_public_key_pem"`
}

// ChallengeResponse is returned in phase-1 of the enrollment-token flow.
type ChallengeResponse struct {
	Challenge       string `json:"challenge"`             // base64 RSA-OAEP(nonce, agent_pubkey)
	ServerPublicKey string `json:"server_public_key_pem"` // server RSA public key for step2 encryption
}

// AdminAuthorizeRequest pre-authorizes a public key
type AdminAuthorizeRequest struct {
	Hostname     string `json:"hostname"`
	PublicKeyPEM string `json:"public_key_pem"`
	ApprovedBy   string `json:"approved_by"`
}

// TokenRefreshRequest is the (optional) body of POST /api/token/refresh (#192). The caller is
// identified by its Bearer JWT, never by the body: Hostname, when present, must equal the JWT subject.
// ChallengeEncrypted is DEPRECATED and ignored (the old challenge proved nothing).
type TokenRefreshRequest struct {
	Hostname           string `json:"hostname,omitempty"`
	ChallengeEncrypted string `json:"challenge_encrypted,omitempty"`
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
	// Bootstrap server state from the environment. Nothing is required here: local commands
	// (`state init`, `--help`, ...) import this package and must not need the server secrets.
	// server.Build / ConfigureServer install the validated values (server.ConfigFromEnv refuses a
	// missing JWT_SECRET_KEY or ADMIN_TOKEN), and an empty admin token never authenticates
	// (adminTokenMatches). RSA + JWT secrets are loaded from DB via InitServerState().
	server = &ServerState{
		JWTSecret:  os.Getenv("JWT_SECRET_KEY"),
		AdminToken: os.Getenv("ADMIN_TOKEN"),
		JWTttl:     time.Hour,
	}
}

// adminTokenMatches reports whether tok is the configured admin token. An empty configured token
// matches nothing (fail closed: a server that never received its ADMIN_TOKEN has no admin).
func adminTokenMatches(tok string) bool {
	server.mu.RLock()
	want := server.AdminToken
	server.mu.RUnlock()
	return want != "" && subtle.ConstantTimeCompare([]byte(tok), []byte(want)) == 1
}

// ConfigureServer sets the bootstrap JWT secret and the admin token from the server Config
// (they are otherwise read from the environment by init()). Called by server.Build before
// anything is served; with the same values as the environment it changes nothing in production.
func ConfigureServer(jwtSecret, adminToken string) {
	server.mu.Lock()
	server.JWTSecret = jwtSecret
	server.AdminToken = adminToken
	server.mu.Unlock()
}

// rsaMasterKey returns the RSA_MASTER_KEY env var.
// Returns ("", false) when the variable is absent (dev/test mode — keys stored unencrypted).
// In production the variable must be set; InitServerState will log a warning if absent.
func rsaMasterKey() (string, bool) {
	v := os.Getenv("RSA_MASTER_KEY")
	return v, v != ""
}

// persistConfigSecret stores a server_config secret (RSA private key, JWT secret): sealed with
// AES-256-GCM under RSA_MASTER_KEY and bound to its field name (AAD) when a master key is set; in
// clear only without master key (dev/test: the state engine accepts that only in its explicit
// insecure test mode).
func persistConfigSecret(ctx context.Context, store *storage.Store, configKey, plain string) error {
	toStore := plain
	if masterKey, hasMaster := rsaMasterKey(); hasMaster {
		sealed, err := state.SealSecret(plain, masterKey, state.ConfigAAD(configKey))
		if err != nil {
			return fmt.Errorf("encrypt %s: %w", configKey, err)
		}
		toStore = sealed
	}
	return store.ConfigSet(ctx, configKey, toStore)
}

// loadConfigSecret retrieves and decrypts a server_config secret ("" when absent).
func loadConfigSecret(ctx context.Context, store *storage.Store, configKey string) (string, error) {
	stored, err := store.ConfigGet(ctx, configKey)
	if err != nil || stored == "" {
		return stored, err
	}
	if strings.HasPrefix(stored, state.EncPrefix) {
		masterKey, hasMaster := rsaMasterKey()
		if !hasMaster {
			return "", fmt.Errorf("RSA_MASTER_KEY required to decrypt %s", configKey)
		}
		plaintext, err := state.OpenSecret(stored, masterKey, state.ConfigAAD(configKey))
		if err != nil {
			return "", fmt.Errorf("decrypt %s: %w", configKey, err)
		}
		return plaintext, nil
	}
	return stored, nil // clear: dev/test mode
}

// persistRSAKey / loadRSAKey: the RSA private keys of server_config.
func persistRSAKey(ctx context.Context, store *storage.Store, configKey, privPEM string) error {
	return persistConfigSecret(ctx, store, configKey, privPEM)
}

func loadRSAKey(ctx context.Context, store *storage.Store, configKey string) (string, error) {
	return loadConfigSecret(ctx, store, configKey)
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
	jwtCurrent, err := loadConfigSecret(ctx, store, "jwt_secret_current")
	if err != nil {
		return fmt.Errorf("ConfigGet jwt_secret_current: %w", err)
	}
	if jwtCurrent == "" {
		// First boot: persist the env-provided secret
		jwtCurrent = server.JWTSecret
		if err := persistConfigSecret(ctx, store, "jwt_secret_current", jwtCurrent); err != nil {
			return fmt.Errorf("ConfigSet jwt_secret_current: %w", err)
		}
		log.Println("[INIT] JWT secret persisted to DB")
	} else {
		server.JWTSecret = jwtCurrent
		log.Println("[INIT] JWT secret loaded from DB")
	}

	// Load previous JWT secret (may be empty)
	jwtPrev, err := loadConfigSecret(ctx, store, "jwt_secret_previous")
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

// RegisterAgent enrolls a secagent-minion
// POST /api/register
func RegisterAgent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	defer func() { _ = r.Body.Close() }()

	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}

	// Validate base fields
	req.Hostname = strings.TrimSpace(req.Hostname)
	req.PublicKeyPEM = strings.TrimSpace(req.PublicKeyPEM)

	if req.Hostname == "" || req.PublicKeyPEM == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing_fields"})
		return
	}

	if registerStore == nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "store_not_initialized"})
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
		writeJSON(w, status, map[string]string{"error": errCode})
		return
	}

	server.mu.RLock()
	serverPrivKey := server.PrivateKey
	pubPEM := server.PublicPEM
	jwtSecret := server.JWTSecret
	jwtTTL := server.JWTttl
	server.mu.RUnlock()

	if serverPrivKey == nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_key_not_initialized"})
		return
	}

	// -----------------------------------------------------------------------
	// Phase 2: challenge_response present → verify, issue JWT
	// -----------------------------------------------------------------------
	if req.ChallengeResponse != "" {
		pendingNonce, pendingToken, ok := consumePendingNonce(req.Hostname)
		if !ok {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "challenge_expired_or_not_issued"})
			return
		}

		// Decrypt response with server private key
		responseBytes, err := base64.StdEncoding.DecodeString(req.ChallengeResponse)
		if err != nil {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "challenge_response_invalid_encoding"})
			return
		}

		decrypted, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, serverPrivKey, responseBytes, nil)
		if err != nil {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "challenge_response_decryption_failed"})
			return
		}

		// Expected payload: nonce (16 bytes) + token (plain text)
		expected := append(pendingNonce, []byte(pendingToken)...)
		if string(decrypted) != string(expected) {
			log.Printf("RegisterAgent challenge mismatch: hostname=%q", req.Hostname)
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "challenge_response_mismatch"})
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
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "jwt_generation_failed"})
			return
		}

		tokenEncrypted, err := encryptWithPublicKey(rawJWT, req.PublicKeyPEM)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_public_key"})
			return
		}

		// Persist: consume token (increment use_count), store authorized_key, register agent
		// ONE mutation (#160): the token is consumed, the key authorized and the agent registered,
		// or nothing happens (a failure between the steps can not leave a consumed token without
		// agent, nor an agent without key).
		if err := registerStore.EnrollAgent(ctx, tok.ID, req.Hostname, req.PublicKeyPEM, jti, "enrollment_token:"+tok.ID); err != nil {
			log.Printf("RegisterAgent EnrollAgent: %v", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db_error"})
			return
		}

		log.Printf("RegisterAgent enrollment complete: hostname=%q token_id=%q", req.Hostname, tok.ID)

		// Dispatch host.new event (async, nil-safe during tests)
		if hooks.GlobalDispatcher != nil {
			enrolledAt := time.Now().UTC().Format(time.RFC3339)
			hooks.GlobalDispatcher.Dispatch("host.new", req.Hostname, "disconnected", enrolledAt)
		}

		writeJSON(w, http.StatusOK, RegisterResponse{
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
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "nonce_generation_failed"})
		return
	}

	// Encrypt nonce with agent's public key
	challengeEncrypted, err := encryptWithPublicKey(string(nonce), req.PublicKeyPEM)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_public_key"})
		return
	}

	// Store nonce for phase-2 verification
	storePendingNonce(req.Hostname, nonce, req.EnrollmentToken)

	log.Printf("RegisterAgent challenge issued: hostname=%q token_id=%q", req.Hostname, tok.ID)

	writeJSON(w, http.StatusOK, ChallengeResponse{
		Challenge:       challengeEncrypted,
		ServerPublicKey: pubPEM,
	})
}

// registerAgentLegacy handles the legacy authorized_keys enrollment flow (backward-compat).
func registerAgentLegacy(w http.ResponseWriter, ctx context.Context, req RegisterRequest) {
	authKey, err := registerStore.GetAuthorizedKey(ctx, req.Hostname)
	if err != nil {
		log.Printf("RegisterAgent GetAuthorizedKey: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db_error"})
		return
	}
	if authKey == nil {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "unauthorized_hostname"})
		return
	}

	if strings.TrimSpace(authKey.PublicKeyPEM) != req.PublicKeyPEM {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "public_key_mismatch"})
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
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "jwt_generation_failed"})
		return
	}

	tokenEncrypted, err := encryptWithPublicKey(rawJWT, req.PublicKeyPEM)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_public_key"})
		return
	}

	if _, err := registerStore.RegisterAgent(ctx, req.Hostname, req.PublicKeyPEM, jti); err != nil {
		log.Printf("RegisterAgent persist: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db_error"})
		return
	}

	writeJSON(w, http.StatusOK, RegisterResponse{
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
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing_authorization"})
		return
	}

	tok := authHeader[7:]
	if !adminTokenMatches(tok) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_admin_token"})
		return
	}

	defer func() { _ = r.Body.Close() }()

	var req AdminAuthorizeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}

	// Validate input
	if strings.TrimSpace(req.Hostname) == "" || strings.TrimSpace(req.PublicKeyPEM) == "" || strings.TrimSpace(req.ApprovedBy) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing_fields"})
		return
	}

	if registerStore == nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "store_not_initialized"})
		return
	}

	if err := registerStore.AddAuthorizedKey(r.Context(), req.Hostname, req.PublicKeyPEM, req.ApprovedBy); err != nil {
		log.Printf("AdminAuthorize AddAuthorizedKey: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db_error"})
		return
	}

	writeJSON(w, http.StatusCreated, map[string]string{
		"hostname": req.Hostname,
		"status":   "authorized",
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
