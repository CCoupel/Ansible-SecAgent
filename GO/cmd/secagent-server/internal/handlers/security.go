package handlers

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"secagent-server/cmd/secagent-server/internal/storage"
	"secagent-server/cmd/secagent-server/internal/ws"
)

// ========================================================================
// POST /api/admin/keys/rotate
// ========================================================================

// RotateKeysRequest is the optional body for key rotation.
type RotateKeysRequest struct {
	Grace string `json:"grace"` // e.g. "24h", "2h30m" — defaults to "24h"
}

// RotateKeysResponse is returned after a successful rotation.
type RotateKeysResponse struct {
	CurrentKeySHA256  string `json:"current_key_sha256"`
	PreviousKeySHA256 string `json:"previous_key_sha256"`
	Deadline          string `json:"deadline"`
	AgentsMigrated    int    `json:"agents_migrated"`
	AgentsTotal       int    `json:"agents_total"`
}

// AdminRotateKeys rotates JWT secrets and RSA keypair, then sends rekey to connected agents.
// POST /api/admin/keys/rotate
// Body: { "grace": "24h" }  (optional)
func AdminRotateKeys(w http.ResponseWriter, r *http.Request) {
	if !requireAdminAuth(w, r) {
		return
	}

	if adminStore == nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "store_not_initialized"})
		return
	}

	// Parse optional grace period (body optional — ignore decode errors)
	graceDuration := 24 * time.Hour
	var req RotateKeysRequest
	if r.Body != nil && r.ContentLength != 0 {
		if err := json.NewDecoder(r.Body).Decode(&req); err == nil && req.Grace != "" {
			d, err := time.ParseDuration(req.Grace)
			if err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grace_duration"})
				return
			}
			graceDuration = d
		}
	}

	ctx := context.Background()

	// === Step 1: Generate new JWT secret (HMAC-SHA256 random 32 bytes) ===
	newJWTBytes := make([]byte, 32)
	if _, err := rand.Read(newJWTBytes); err != nil {
		log.Printf("AdminRotateKeys: rand.Read JWT secret: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "key_generation_failed"})
		return
	}
	newJWTSecret := hex.EncodeToString(newJWTBytes)

	// === Step 2: Generate new RSA-4096 keypair ===
	newRSAKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Printf("AdminRotateKeys: RSA GenerateKey: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "key_generation_failed"})
		return
	}
	newRSAPrivPEM, newRSAPubPEM, err := encodeRSAKeyPair(newRSAKey)
	if err != nil {
		log.Printf("AdminRotateKeys: encodeRSAKeyPair: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "key_generation_failed"})
		return
	}

	// === Steps 3-8: Rotate in-memory state (under write lock) ===
	deadline := time.Now().Add(graceDuration)

	server.mu.Lock()
	oldJWTSecret := server.JWTSecret
	oldRSAKey := server.PrivateKey

	// jwt_secret_previous ← old current
	server.JWTPreviousSecret = oldJWTSecret
	// jwt_secret_current ← new
	server.JWTSecret = newJWTSecret
	// rsa_key_previous ← old current
	server.PreviousPrivateKey = oldRSAKey
	// rsa_key_current ← new
	server.PrivateKey = newRSAKey
	server.PublicPEM = newRSAPubPEM
	// key_rotation_deadline ← now + grace
	server.KeyRotationDeadline = deadline
	jwtTTL := server.JWTttl
	server.mu.Unlock()

	// === Step 8: Persist all values to DB ===
	deadlineStr := deadline.UTC().Format(time.RFC3339)

	if err := persistConfigSecret(ctx, adminStore, "jwt_secret_previous", oldJWTSecret); err != nil {
		log.Printf("AdminRotateKeys: persist jwt_secret_previous: %v", err)
	}
	if err := persistConfigSecret(ctx, adminStore, "jwt_secret_current", newJWTSecret); err != nil {
		log.Printf("AdminRotateKeys: persist jwt_secret_current: %v", err)
	}
	if err := adminStore.ConfigSet(ctx, "key_rotation_deadline", deadlineStr); err != nil {
		log.Printf("AdminRotateKeys: persist key_rotation_deadline: %v", err)
	}

	// Persist RSA keys
	if oldRSAKey != nil {
		oldPrivPEM := mustEncodeRSAPrivPEM(oldRSAKey)
		if oldPrivPEM != "" {
			if err := persistRSAKey(ctx, adminStore, "rsa_key_previous", oldPrivPEM); err != nil {
				log.Printf("AdminRotateKeys: persist rsa_key_previous: %v", err)
			}
		}
	}
	if err := persistRSAKey(ctx, adminStore, "rsa_key_current", newRSAPrivPEM); err != nil {
		log.Printf("AdminRotateKeys: persist rsa_key_current: %v", err)
	}

	log.Printf("Key rotation initiated: deadline=%s grace=%s", deadlineStr, graceDuration)

	// === Step 9: Send rekey to all connected agents ===
	connectedHosts := ws.GetConnectedHostnames()
	agentsMigrated := 0

	for _, hostname := range connectedHosts {
		if sendRekeyToAgent(ctx, hostname, newJWTSecret, jwtTTL) {
			agentsMigrated++
		}
	}

	log.Printf("Rekey sent: agents_migrated=%d agents_total=%d", agentsMigrated, len(connectedHosts))

	writeJSON(w, http.StatusOK, RotateKeysResponse{
		CurrentKeySHA256:  sha256Hex(newJWTSecret),
		PreviousKeySHA256: sha256Hex(oldJWTSecret),
		Deadline:          deadlineStr,
		AgentsMigrated:    agentsMigrated,
		AgentsTotal:       len(connectedHosts),
	})
}

// sendToAgentFn delivers a control message to a connected agent (replaced in tests).
var sendToAgentFn = ws.SendToAgent

// sendRekeyToAgent issues a new JWT for hostname, encrypts it with the agent's
// RSA public key, and sends a WS "rekey" message. Returns true on success.
func sendRekeyToAgent(ctx context.Context, hostname, jwtSecret string, jwtTTL time.Duration) bool {
	_, err := issueRekey(ctx, hostname, jwtSecret, jwtTTL)
	return err == nil
}

// errRekeyNotSent is the generic failure of issueRekey (details are logged, never returned: they
// could carry token material).
var errRekeyNotSent = errors.New("rekey not sent")

// issueRekey is the single path that renews the JWT of a connected agent: the rotation of
// JWT_SECRET_KEY, the reconnection with the previous secret and the periodic renewal (#217) all go
// through it, so that the revocation rules (#193) and the "persist the JTI before sending" rule
// (#192) cannot diverge. It returns the expiry of the token it sent.
//
// Errors: ws.ErrRenewStop when the agent is gone or revoked (nothing was sent, do not retry);
// errRekeyNotSent otherwise (read-only state, no connection, ...: nothing sent, may be retried).
// The JWT itself is never logged, the JTI only truncated.
func issueRekey(ctx context.Context, hostname, jwtSecret string, jwtTTL time.Duration) (time.Time, error) {
	if adminStore == nil {
		return time.Time{}, errRekeyNotSent
	}

	// Fetch agent's public key from DB
	agent, err := adminStore.GetAgent(ctx, hostname)
	if err != nil || agent == nil {
		log.Printf("sendRekeyToAgent: GetAgent %q: err=%v found=%v", hostname, err, agent != nil)
		if err == nil {
			return time.Time{}, fmt.Errorf("%w: unknown agent", ws.ErrRenewStop)
		}
		return time.Time{}, errRekeyNotSent
	}

	if agent.Revoked { // a revoked host never gets a new token (#193)
		log.Printf("[SECURITY WARNING] sendRekeyToAgent: %q is revoked, no token issued", hostname)
		return time.Time{}, fmt.Errorf("%w: revoked", ws.ErrRenewStop)
	}

	// Sign new JWT with the new current secret
	rawJWT, newJTI, err := signAgentJWT(hostname, jwtSecret, jwtTTL)
	if err != nil {
		log.Printf("sendRekeyToAgent: signAgentJWT %q: %v", hostname, err)
		return time.Time{}, errRekeyNotSent
	}
	exp := time.Now().Add(effectiveJWTTTL(jwtTTL))

	// Encrypt JWT with agent's RSA public key (RSAES-OAEP SHA-256)
	tokenEncrypted, err := encryptWithPublicKey(rawJWT, agent.PublicKeyPEM)
	if err != nil {
		log.Printf("sendRekeyToAgent: encryptWithPublicKey %q: %v", hostname, err)
		return time.Time{}, errRekeyNotSent
	}

	// Persist the new JTI BEFORE sending the token: a token whose JTI is not stored would be refused
	// at the next handshake (token_replaced), and the old one would stay valid. A refused write
	// (read-only state, lost lock) therefore sends nothing (#192 audit).
	// The revocation check and the write are one transaction: an agent revoked since the read above
	// gets no new JTI (a renewal racing a revocation, #217).
	found, err := adminStore.UpdateTokenJTIUnlessRevoked(ctx, hostname, newJTI)
	if errors.Is(err, storage.ErrAgentRevoked) {
		log.Printf("[SECURITY WARNING] sendRekeyToAgent: %q was revoked during the renewal, no token issued", hostname)
		return time.Time{}, fmt.Errorf("%w: revoked", ws.ErrRenewStop)
	}
	if err != nil {
		log.Printf("sendRekeyToAgent: UpdateTokenJTI %q: %v — rekey not sent", hostname, err)
		return time.Time{}, errRekeyNotSent
	}
	if !found {
		return time.Time{}, fmt.Errorf("%w: unknown agent", ws.ErrRenewStop)
	}

	// Send rekey message over WebSocket (no task_id — control message)
	rekeyMsg := map[string]interface{}{
		"type":            "rekey",
		"token_encrypted": tokenEncrypted,
	}
	if err := sendToAgentFn(hostname, rekeyMsg); err != nil {
		log.Printf("sendRekeyToAgent: SendToAgent %q: %v", hostname, err)
		return time.Time{}, errRekeyNotSent
	}

	log.Printf("Rekey sent to agent: hostname=%q jti=%q", hostname, truncateJTI(newJTI))
	return exp, nil
}

// truncateJTI keeps the first 8 characters of a JTI for the logs.
func truncateJTI(jti string) string {
	if len(jti) > 8 {
		return jti[:8] + "…"
	}
	return jti
}

// DefaultAgentJWTTTL is the lifetime of an agent JWT when AGENT_JWT_TTL is not set (#217).
const DefaultAgentJWTTTL = 24 * time.Hour

// effectiveJWTTTL maps the zero value to the default lifetime.
func effectiveJWTTTL(ttl time.Duration) time.Duration {
	if ttl <= 0 {
		return DefaultAgentJWTTTL
	}
	return ttl
}

// signAgentJWT signs a fresh agent JWT and returns (rawJWT, jti, error).
func signAgentJWT(hostname, jwtSecret string, ttl time.Duration) (string, string, error) {
	ttl = effectiveJWTTTL(ttl)
	jti := uuid.New().String()
	now := time.Now()
	claims := jwt.MapClaims{
		"sub":  hostname,
		"role": "agent",
		"jti":  jti,
		"iat":  now.Unix(),
		"exp":  now.Add(ttl).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	rawJWT, err := token.SignedString([]byte(jwtSecret))
	if err != nil {
		return "", "", fmt.Errorf("SignedString: %w", err)
	}
	return rawJWT, jti, nil
}

// ========================================================================
// GET /api/admin/security/keys/status
// ========================================================================

// KeysStatusResponse describes the current key rotation status.
type KeysStatusResponse struct {
	CurrentKeySHA256  string `json:"current_key_sha256"`
	PreviousKeySHA256 string `json:"previous_key_sha256"` // empty if no rotation
	Deadline          string `json:"deadline"`            // empty if no rotation
	RotationActive    bool   `json:"rotation_active"`
	AgentsTotal       int    `json:"agents_total"`
}

// AdminSecurityKeysStatus returns the current key rotation state.
// GET /api/admin/security/keys/status
func AdminSecurityKeysStatus(w http.ResponseWriter, r *http.Request) {
	if !requireAdminAuth(w, r) {
		return
	}

	server.mu.RLock()
	current := server.JWTSecret
	previous := server.JWTPreviousSecret
	deadline := server.KeyRotationDeadline
	server.mu.RUnlock()

	rotationActive := previous != "" && !deadline.IsZero() && time.Now().Before(deadline)

	prevHash := ""
	if previous != "" {
		prevHash = sha256Hex(previous)
	}

	deadlineStr := ""
	if !deadline.IsZero() {
		deadlineStr = deadline.UTC().Format(time.RFC3339)
	}

	writeJSON(w, http.StatusOK, KeysStatusResponse{
		CurrentKeySHA256:  sha256Hex(current),
		PreviousKeySHA256: prevHash,
		Deadline:          deadlineStr,
		RotationActive:    rotationActive,
		AgentsTotal:       ws.GetConnectedCount(),
	})
}

// ========================================================================
// GET /api/admin/security/tokens
// ========================================================================

// TokenInfo describes an active agent JWT.
type TokenInfo struct {
	Hostname   string `json:"hostname"`
	JTI        string `json:"jti"`
	EnrolledAt string `json:"enrolled_at"`
	LastSeen   string `json:"last_seen"`
	Status     string `json:"status"`
}

// AdminSecurityTokens lists all agent JTIs (active tokens).
// GET /api/admin/security/tokens
func AdminSecurityTokens(w http.ResponseWriter, r *http.Request) {
	if !requireAdminAuth(w, r) {
		return
	}

	if adminStore == nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "store_not_initialized"})
		return
	}

	agents, err := adminStore.ListAgents(context.Background(), false)
	if err != nil {
		log.Printf("AdminSecurityTokens: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db_error"})
		return
	}

	tokens := make([]TokenInfo, 0, len(agents))
	for _, a := range agents {
		if a.TokenJTI == "" {
			continue
		}
		tokens = append(tokens, TokenInfo{
			Hostname:   a.Hostname,
			JTI:        a.TokenJTI,
			EnrolledAt: a.EnrolledAt.UTC().Format(time.RFC3339),
			LastSeen:   a.LastSeen.UTC().Format(time.RFC3339),
			Status:     a.Status,
		})
	}

	writeJSON(w, http.StatusOK, tokens)
}

// ========================================================================
// GET /api/admin/security/blacklist
// POST /api/admin/security/blacklist/purge
// ========================================================================

// BlacklistEntryResponse is the public view of a blacklist entry.
type BlacklistEntryResponse struct {
	JTI       string `json:"jti"`
	Hostname  string `json:"hostname"`
	RevokedAt string `json:"revoked_at"`
	ExpiresAt string `json:"expires_at"`
	Reason    string `json:"reason"`
}

// AdminSecurityBlacklist returns all entries in the JTI blacklist.
// GET /api/admin/security/blacklist
func AdminSecurityBlacklist(w http.ResponseWriter, r *http.Request) {
	if !requireAdminAuth(w, r) {
		return
	}

	if adminStore == nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "store_not_initialized"})
		return
	}

	entries, err := adminStore.ListBlacklistEntries(context.Background())
	if err != nil {
		log.Printf("AdminSecurityBlacklist: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db_error"})
		return
	}

	result := make([]BlacklistEntryResponse, 0, len(entries))
	for _, e := range entries {
		result = append(result, BlacklistEntryResponse{
			JTI:       e.JTI,
			Hostname:  e.Hostname,
			RevokedAt: e.RevokedAt.UTC().Format(time.RFC3339),
			ExpiresAt: e.ExpiresAt.UTC().Format(time.RFC3339),
			Reason:    e.Reason,
		})
	}

	writeJSON(w, http.StatusOK, result)
}

// PurgeBlacklistResponse reports how many entries were deleted.
type PurgeBlacklistResponse struct {
	Deleted int64 `json:"deleted"`
}

// AdminSecurityBlacklistPurge deletes expired blacklist entries (expires_at < now).
// POST /api/admin/security/blacklist/purge
func AdminSecurityBlacklistPurge(w http.ResponseWriter, r *http.Request) {
	if !requireAdminAuth(w, r) {
		return
	}

	if adminStore == nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "store_not_initialized"})
		return
	}

	deleted, err := adminStore.PurgeExpiredBlacklist(context.Background())
	if err != nil {
		log.Printf("AdminSecurityBlacklistPurge: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db_error"})
		return
	}

	log.Printf("Blacklist purged: deleted=%d", deleted)
	writeJSON(w, http.StatusOK, PurgeBlacklistResponse{Deleted: deleted})
}

// ========================================================================
// RekeyFunc for ws.SetRekeyFunc injection
// ========================================================================

// RekeyAgent is the function injected into ws.SetRekeyFunc at server startup.
// It sends an encrypted new JWT to the named agent.
func RekeyAgent(hostname string) bool {
	server.mu.RLock()
	jwtSecret := server.JWTSecret
	jwtTTL := server.JWTttl
	server.mu.RUnlock()

	return sendRekeyToAgent(context.Background(), hostname, jwtSecret, jwtTTL)
}

// RenewAgentJWT is the function injected into ws.SetRenewal (#217): it sends the connected agent a
// fresh JWT in a "rekey" frame (same format as the rotation) and returns its expiry. A revoked or
// unknown agent gets nothing and ws.ErrRenewStop; a read-only state gets nothing and a retryable error.
func RenewAgentJWT(hostname string) (time.Time, error) {
	server.mu.RLock()
	jwtSecret := server.JWTSecret
	jwtTTL := server.JWTttl
	server.mu.RUnlock()

	exp, err := issueRekey(context.Background(), hostname, jwtSecret, jwtTTL)
	if err != nil && !errors.Is(err, ws.ErrRenewStop) {
		log.Printf("[WARN] agent JWT renewal skipped: hostname=%q (state read-only or agent not reachable): will retry", hostname)
	}
	return exp, err
}

// ========================================================================
// Helpers
// ========================================================================

// sha256Hex returns the hex-encoded SHA-256 digest of s.
func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// mustEncodeRSAPrivPEM encodes a private RSA key to PKCS8 PEM, returning "" on error.
func mustEncodeRSAPrivPEM(privKey *rsa.PrivateKey) string {
	if privKey == nil {
		return ""
	}
	privPEM, _, err := encodeRSAKeyPair(privKey)
	if err != nil {
		log.Printf("mustEncodeRSAPrivPEM: %v", err)
		return ""
	}
	return privPEM
}
