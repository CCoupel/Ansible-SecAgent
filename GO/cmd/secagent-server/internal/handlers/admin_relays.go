// Phase 12 — admin_relays.go
// Admin REST endpoints for managing relay nodes in proxy/gateway mode.
//
//	POST   /api/admin/relays           — register a relay (push or pull mode)
//	GET    /api/admin/relays           — list all relay nodes
//	GET    /api/admin/relays/status    — live connectivity status
//	DELETE /api/admin/relays/{id}      — remove a relay node
package handlers

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"secagent-server/cmd/secagent-server/internal/auth"
	"secagent-server/cmd/secagent-server/internal/crypto"
	"secagent-server/cmd/secagent-server/internal/repeater"
	"secagent-server/cmd/secagent-server/internal/storage"
	"secagent-server/cmd/secagent-server/internal/ws"
)

// ── Push-mode dial-out hooks (#140) ──────────────────────────────────────────

var (
	pushHooksMu sync.RWMutex
	pushStartFn func(relayID, url, token string) error
	pushStopFn  func(relayID string)
)

// SetRelayPushHooks wires the dial-out manager: start (hot) / stop a Dialer for a push relay.
func SetRelayPushHooks(start func(relayID, url, token string) error, stop func(relayID string)) {
	pushHooksMu.Lock()
	pushStartFn, pushStopFn = start, stop
	pushHooksMu.Unlock()
}

const pushTokenPrefix = "enc:"

// ErrPushTokenKeyMissing is returned when a push token must be stored but RSA_MASTER_KEY is unset.
var ErrPushTokenKeyMissing = errors.New("RSA_MASTER_KEY is required to store a push relay token")

// SealPushToken encrypts a push-mode token for storage in relay_nodes.token_hash
// (AES-256-GCM with RSA_MASTER_KEY, "enc:" prefix). Fail closed: without a master key the
// token is never stored in clear. (The column is named token_hash for historical reasons:
// for push nodes it holds the encrypted token, not a hash.)
func SealPushToken(token string) (string, error) {
	key, ok := rsaMasterKey()
	if !ok {
		log.Printf("[SECURITY WARNING] push relay registration refused: RSA_MASTER_KEY is not set")
		return "", ErrPushTokenKeyMissing
	}
	enc, err := crypto.EncryptAESGCM(token, key)
	if err != nil {
		return "", fmt.Errorf("encrypt push token: %w", err)
	}
	return pushTokenPrefix + enc, nil
}

// OpenPushToken returns the clear token from its stored form (legacy rows are plaintext).
func OpenPushToken(stored string) (string, error) {
	if !strings.HasPrefix(stored, pushTokenPrefix) {
		return stored, nil
	}
	key, ok := rsaMasterKey()
	if !ok {
		return "", errors.New("push token is encrypted but RSA_MASTER_KEY is not set")
	}
	token, err := crypto.DecryptAESGCM(strings.TrimPrefix(stored, pushTokenPrefix), key)
	if err != nil {
		return "", fmt.Errorf("decrypt push token: %w", err)
	}
	return token, nil
}

// ========================================================================
// Request / Response types
// ========================================================================

// RelayCreateRequest is the body for POST /api/admin/relays.
type RelayCreateRequest struct {
	RelayID     string `json:"relay_id"`        // required, unique name e.g. "dmz1"
	Mode        string `json:"mode,omitempty"`  // "pull" (default) or "push"
	URL         string `json:"url,omitempty"`   // push mode: relay HTTP base URL
	Token       string `json:"token,omitempty"` // push mode: bearer token to auth to the relay
	Description string `json:"description,omitempty"`
}

// RelayCreateResponse is returned from POST /api/admin/relays.
// For pull mode, JWTToken is set (shown only once).
type RelayCreateResponse struct {
	ID          string `json:"id"`
	RelayID     string `json:"relay_id"`
	Mode        string `json:"mode"`
	Status      string `json:"status"`
	Description string `json:"description,omitempty"`
	// pull mode only — shown ONCE, never stored in plain text
	JWTToken string `json:"jwt_token,omitempty"`
	// push mode only
	URL       string `json:"url,omitempty"`
	CreatedAt string `json:"created_at"`
}

// RelaySummary is the list view for a relay node (no token plain text).
type RelaySummary struct {
	ID          string  `json:"id"`
	RelayID     string  `json:"relay_id"`
	Mode        string  `json:"mode"`
	IsProxy     bool    `json:"is_proxy"`
	Status      string  `json:"status"`
	Description string  `json:"description,omitempty"`
	URL         string  `json:"url,omitempty"`
	LastSeen    *string `json:"last_seen,omitempty"`
	CreatedAt   string  `json:"created_at"`
}

// RelayStatusResponse is returned from GET /api/admin/relays/status.
type RelayStatusResponse struct {
	Relays    []RelaySummary `json:"relays"`
	Timestamp string         `json:"timestamp"`
}

// ========================================================================
// POST /api/admin/relays
// ========================================================================

// AdminCreateRelay registers a new relay node.
//
// Pull mode (default): generates a JWT relay token (role=relay) that the relay
// will use to authenticate to /ws/relay. The token is returned once in jwt_token.
//
// Push mode: the admin provides the relay's base URL and a bearer token.
// The proxy will call the relay's REST API using these credentials.
func AdminCreateRelay(w http.ResponseWriter, r *http.Request) {
	if !requireAdminAuth(w, r) {
		return
	}

	defer func() { _ = r.Body.Close() }()

	var req RelayCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json"})
		return
	}

	req.RelayID = strings.TrimSpace(req.RelayID)
	if req.RelayID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing_relay_id"})
		return
	}
	// The id lands in logs, environment variables, hook files and Ansible group names: only
	// [A-Za-z0-9][A-Za-z0-9_-]{0,62}. The raw value is never echoed.
	if !relayIDPattern.MatchString(req.RelayID) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_relay_id", "message": "relay_id must match [A-Za-z0-9][A-Za-z0-9_-]{0,62}"})
		return
	}

	if req.Mode == "" {
		req.Mode = "pull"
	}
	req.Mode = strings.ToLower(req.Mode)
	if req.Mode != "pull" && req.Mode != "push" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_mode_use_pull_or_push"})
		return
	}

	if req.Mode == "push" {
		if strings.TrimSpace(req.URL) == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "url_required_for_push_mode"})
			return
		}
		if strings.TrimSpace(req.Token) == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "token_required_for_push_mode"})
			return
		}
		// wss:// only, no userinfo, valid id (the error never echoes url userinfo or the token).
		if err := repeater.ValidateDialTarget(repeater.DialTarget{RelayID: req.RelayID, URL: req.URL, Token: req.Token}); err != nil {
			log.Printf("AdminCreateRelay push target rejected: relay_id=%q: %v", req.RelayID, err)
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_push_target"})
			return
		}
		if ws.RelayWouldLoop(req.RelayID) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "relay_id_would_create_loop"})
			return
		}
	}

	if adminStore == nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "store_not_initialized"})
		return
	}

	id := uuid.New().String()
	now := time.Now().UTC()

	node := storage.RelayNode{
		ID:          id,
		RelayID:     req.RelayID,
		Mode:        req.Mode,
		Description: req.Description,
		CreatedAt:   now.Unix(),
		Status:      "pending",
	}

	var jwtToken string
	var newJTI string
	var newJTIExp int64
	var previous storage.RelayTokenInfo

	switch req.Mode {
	case "pull":
		// Generate a long-lived JWT relay token (30 days)
		jwtSvc := auth.New(GetServerJWTSecrets, 720*time.Hour)
		rawJWT, jti, err := jwtSvc.SignRelay(req.RelayID)
		if err != nil {
			log.Printf("AdminCreateRelay SignRelay: %v", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "jwt_generation_failed"})
			return
		}
		jwtToken = rawJWT
		newJTI, newJTIExp = jti, time.Now().Add(720*time.Hour).Unix() // SignRelay lifetime
		// Store SHA-256 of the JWT for future reference (not strictly required for pull)
		h := sha256.Sum256([]byte(rawJWT))
		node.TokenHash = fmt.Sprintf("%x", h)

	case "push":
		node.URL = req.URL
		// The dialer needs the clear token: stored encrypted (RSA_MASTER_KEY), never returned.
		sealed, err := SealPushToken(req.Token)
		if err != nil {
			if errors.Is(err, ErrPushTokenKeyMissing) {
				writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "rsa_master_key_required_for_push_mode"})
				return
			}
			log.Printf("AdminCreateRelay SealPushToken: %v", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "token_encryption_failed"})
			return
		}
		node.TokenHash = sealed
	}

	// Re-registering a relay issues a NEW token: remember the previous JTI so it can be cut off.
	if req.Mode == "pull" {
		previous, _ = adminStore.GetRelayTokenInfo(req.RelayID)
	}

	if err := adminStore.UpsertRelayNode(node); err != nil {
		log.Printf("AdminCreateRelay UpsertRelayNode: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db_error"})
		return
	}

	if req.Mode == "pull" && newJTI != "" {
		// Persist the JTI/expiry (never the token): required to revoke this relay later (#153).
		if err := adminStore.SetRelayTokenInfo(req.RelayID, newJTI, newJTIExp); err != nil {
			log.Printf("AdminCreateRelay SetRelayTokenInfo: %v", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db_error"})
			return
		}
		if previous.JTI != "" && previous.JTI != newJTI {
			if err := adminStore.BlacklistJTI(r.Context(), previous.JTI, req.RelayID, "token replaced by re-registration", previous.Exp); err != nil {
				log.Printf("AdminCreateRelay: blacklist previous token: %v", err)
			}
			ws.CloseRelay(req.RelayID, ws.WSRelayCloseRevoked, "token replaced")
		}
	}

	log.Printf("Relay registered: relay_id=%q mode=%s id=%s", req.RelayID, req.Mode, id)

	// Push mode: start the dial-out immediately, without restart.
	if req.Mode == "push" {
		pushHooksMu.RLock()
		start := pushStartFn
		pushHooksMu.RUnlock()
		if start != nil {
			if err := start(req.RelayID, req.URL, req.Token); err != nil {
				log.Printf("AdminCreateRelay: dialer start failed: relay_id=%q: %v", req.RelayID, err)
			}
		}
	}

	resp := RelayCreateResponse{
		ID:          id,
		RelayID:     req.RelayID,
		Mode:        req.Mode,
		Status:      "pending",
		Description: req.Description,
		JWTToken:    jwtToken, // empty for push mode
		URL:         req.URL,  // empty for pull mode
		CreatedAt:   now.Format(time.RFC3339),
	}
	writeJSON(w, http.StatusCreated, resp)
}

// ========================================================================
// GET /api/admin/relays
// ========================================================================

// AdminListRelays returns all registered relay nodes (no token plain text).
func AdminListRelays(w http.ResponseWriter, r *http.Request) {
	if !requireAdminAuth(w, r) {
		return
	}

	if adminStore == nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "store_not_initialized"})
		return
	}

	nodes, err := adminStore.ListRelayNodes()
	if err != nil {
		log.Printf("AdminListRelays: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db_error"})
		return
	}

	summaries := make([]RelaySummary, 0, len(nodes))
	for _, n := range nodes {
		summaries = append(summaries, relayNodeToSummary(n))
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{"relays": summaries})
}

// ========================================================================
// GET /api/admin/relays/status
// ========================================================================

// AdminRelaysStatus returns real-time connectivity status for all relay nodes.
// Currently the status is read from DB (updated by ws/relay_handler when relays connect).
func AdminRelaysStatus(w http.ResponseWriter, r *http.Request) {
	if !requireAdminAuth(w, r) {
		return
	}

	if adminStore == nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "store_not_initialized"})
		return
	}

	nodes, err := adminStore.ListRelayNodes()
	if err != nil {
		log.Printf("AdminRelaysStatus: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db_error"})
		return
	}

	summaries := make([]RelaySummary, 0, len(nodes))
	for _, n := range nodes {
		summaries = append(summaries, relayNodeToSummary(n))
	}

	writeJSON(w, http.StatusOK, RelayStatusResponse{
		Relays:    summaries,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	})
}

// ========================================================================
// DELETE /api/admin/relays/{id}
// ========================================================================

// AdminDeleteRelay removes a relay node by its internal UUID.
// Also cascades deletion of relay_routing entries for this relay.
func AdminDeleteRelay(w http.ResponseWriter, r *http.Request) {
	if !requireAdminAuth(w, r) {
		return
	}

	id := r.PathValue("id")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing_id"})
		return
	}

	if adminStore == nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "store_not_initialized"})
		return
	}

	// Check existence first to return 404 on unknown id
	node, err := adminStore.GetRelayNodeByID(id)
	if err != nil {
		log.Printf("AdminDeleteRelay GetRelayNodeByID: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db_error"})
		return
	}
	if node == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "relay_not_found"})
		return
	}

	// A relay whose token JTI is unknown (legacy, issued before #153, or a push relay) cannot be
	// blacklisted: deleting it would drop the revoked flag and let its old token reconnect until
	// it expires. Refuse unless it was revoked first. No bypass.
	info, ierr := adminStore.GetRelayTokenInfo(node.RelayID)
	if ierr != nil {
		log.Printf("AdminDeleteRelay GetRelayTokenInfo: %v", ierr)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db_error"})
		return
	}
	if info.JTI == "" && !info.Revoked {
		log.Printf("[SECURITY WARNING] relay delete refused: relay_id=%q has no tracked token and is not revoked", node.RelayID)
		writeJSON(w, http.StatusConflict, map[string]string{
			"error":   "relay_not_revoked",
			"message": "revoke the relay first (POST /api/admin/relays/{id}/revoke): its token cannot be blacklisted on delete",
		})
		return
	}

	// Pull relay: blacklist its token before the row (and its JTI) disappears (#153).
	if node.Mode == "pull" {
		if _, _, rerr := adminStore.RevokeRelayNode(r.Context(), node.RelayID, "relay deleted"); rerr != nil {
			log.Printf("AdminDeleteRelay RevokeRelayNode: %v", rerr)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db_error"})
			return
		}
	}

	// Best-effort: delete routing entries before the node (FK cascade handles it,
	// but explicit delete is safer if FK cascade is not enabled at connection level).
	_ = adminStore.DeleteRelayRoutingByRelay(node.RelayID)

	if err := adminStore.DeleteRelayNode(id); err != nil {
		log.Printf("AdminDeleteRelay DeleteRelayNode: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db_error"})
		return
	}

	if node.Mode == "push" {
		pushHooksMu.RLock()
		stop := pushStopFn
		pushHooksMu.RUnlock()
		if stop != nil {
			stop(node.RelayID)
		}
	}
	// A deleted relay must not keep a live link: cut it (permanent code, #148).
	disconnected := ws.CloseRelay(node.RelayID, ws.WSRelayCloseRevoked, "relay deleted")

	log.Printf("Relay deleted: id=%s relay_id=%q link_closed=%v", id, node.RelayID, disconnected)
	w.WriteHeader(http.StatusNoContent)
}

// ========================================================================
// Internal helpers
// ========================================================================

func relayNodeToSummary(n storage.RelayNode) RelaySummary {
	s := RelaySummary{
		ID:          n.ID,
		RelayID:     n.RelayID,
		Mode:        n.Mode,
		IsProxy:     n.IsProxy,
		Status:      n.Status,
		Description: n.Description,
		URL:         n.URL,
		CreatedAt:   time.Unix(n.CreatedAt, 0).UTC().Format(time.RFC3339),
	}
	if n.LastSeen != nil {
		t := time.Unix(*n.LastSeen, 0).UTC().Format(time.RFC3339)
		s.LastSeen = &t
	}
	return s
}

// ========================================================================
// POST /api/admin/relays/{id}/revoke  (#153)
// ========================================================================

// RelayRevokeResponse is returned by the relay revocation endpoints. It carries no secret.
type RelayRevokeResponse struct {
	Revoked      bool   `json:"revoked"`
	ID           string `json:"id"`
	RelayID      string `json:"relay_id"`
	Blacklisted  bool   `json:"blacklisted"`  // the token JTI is now blacklisted
	LegacyToken  bool   `json:"legacy_token"` // the token predates JTI tracking: refused through the revoked flag only
	Disconnected bool   `json:"disconnected"` // a live link was closed (4010)
	UpdatedAt    string `json:"updated_at"`
}

// AdminRevokeRelay revokes a relay: its token JTI is blacklisted (when known), the relay is
// flagged revoked (refused at /ws/relay even for legacy tokens), and its live link is closed
// with the permanent code 4010. Push relays: the dialer is stopped and the link closed.
func AdminRevokeRelay(w http.ResponseWriter, r *http.Request) {
	if !requireAdminAuth(w, r) {
		return
	}
	if adminStore == nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "store_not_initialized"})
		return
	}
	node, err := adminStore.GetRelayNodeByID(r.PathValue("id"))
	if err != nil {
		log.Printf("AdminRevokeRelay: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db_error"})
		return
	}
	if node == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "relay_not_found"})
		return
	}
	resp, err := revokeRelayNode(r, node)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db_error"})
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// revokeRelayNode is shared by the relay and the tokens revoke endpoints.
func revokeRelayNode(r *http.Request, node *storage.RelayNode) (RelayRevokeResponse, error) {
	resp := RelayRevokeResponse{Revoked: true, ID: node.ID, RelayID: node.RelayID, UpdatedAt: time.Now().UTC().Format(time.RFC3339)}
	info, _, err := adminStore.RevokeRelayNode(r.Context(), node.RelayID, "relay token revoked")
	if err != nil {
		log.Printf("revokeRelayNode: %v", err)
		return RelayRevokeResponse{}, err
	}
	if node.Mode == "push" {
		pushHooksMu.RLock()
		stop := pushStopFn
		pushHooksMu.RUnlock()
		if stop != nil {
			stop(node.RelayID)
		}
	} else {
		resp.Blacklisted = info.JTI != ""
		resp.LegacyToken = info.JTI == ""
	}
	resp.Disconnected = ws.CloseRelay(node.RelayID, ws.WSRelayCloseRevoked, "token revoked")
	log.Printf("Relay revoked: relay_id=%q mode=%s blacklisted=%v legacy=%v link_closed=%v",
		node.RelayID, node.Mode, resp.Blacklisted, resp.LegacyToken, resp.Disconnected)
	return resp, nil
}

// RelayRevokedCheck is the ws.SetRelayRevokedFunc implementation backed by relay_nodes.
func RelayRevokedCheck(relayID string) (bool, error) {
	if adminStore == nil {
		return false, errors.New("store_not_initialized")
	}
	info, err := adminStore.GetRelayTokenInfo(relayID)
	if err != nil {
		return false, err
	}
	return info.Revoked, nil
}
