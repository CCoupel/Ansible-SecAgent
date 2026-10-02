// Phase 12 — admin_relays.go
// Admin REST endpoints for managing relay nodes in proxy/gateway mode.
//
//   POST   /api/admin/relays           — register a relay (push or pull mode)
//   GET    /api/admin/relays           — list all relay nodes
//   GET    /api/admin/relays/status    — live connectivity status
//   DELETE /api/admin/relays/{id}      — remove a relay node
package handlers

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"secagent-server/cmd/secagent-server/internal/auth"
	"secagent-server/cmd/secagent-server/internal/storage"
)

// ========================================================================
// Request / Response types
// ========================================================================

// RelayCreateRequest is the body for POST /api/admin/relays.
type RelayCreateRequest struct {
	RelayID     string `json:"relay_id"`             // required, unique name e.g. "dmz1"
	Mode        string `json:"mode,omitempty"`       // "pull" (default) or "push"
	URL         string `json:"url,omitempty"`        // push mode: relay HTTP base URL
	Token       string `json:"token,omitempty"`      // push mode: bearer token to auth to the relay
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

	var req RelayCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json"})
		return
	}
	defer r.Body.Close()

	req.RelayID = strings.TrimSpace(req.RelayID)
	if req.RelayID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing_relay_id"})
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

	switch req.Mode {
	case "pull":
		// Generate a long-lived JWT relay token (30 days)
		jwtSvc := auth.New(GetServerJWTSecrets, 720*time.Hour)
		rawJWT, _, err := jwtSvc.SignRelay(req.RelayID)
		if err != nil {
			log.Printf("AdminCreateRelay SignRelay: %v", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "jwt_generation_failed"})
			return
		}
		jwtToken = rawJWT
		// Store SHA-256 of the JWT for future reference (not strictly required for pull)
		h := sha256.Sum256([]byte(rawJWT))
		node.TokenHash = fmt.Sprintf("%x", h)

	case "push":
		node.URL = req.URL
		// Store plain token for push mode — reserved for future use (#140).
		// Push-mode relay entries are stored but REST polling is currently inert
		// (PushManager was removed in v3.0 #123).
		// Pull mode stores SHA-256 only (JWT not needed after registration).
		node.TokenHash = req.Token
	}

	if err := adminStore.UpsertRelayNode(node); err != nil {
		log.Printf("AdminCreateRelay UpsertRelayNode: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db_error"})
		return
	}

	log.Printf("Relay registered: relay_id=%s mode=%s id=%s", req.RelayID, req.Mode, id)

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

	// Best-effort: delete routing entries before the node (FK cascade handles it,
	// but explicit delete is safer if FK cascade is not enabled at connection level).
	_ = adminStore.DeleteRelayRoutingByRelay(node.RelayID)

	if err := adminStore.DeleteRelayNode(id); err != nil {
		log.Printf("AdminDeleteRelay DeleteRelayNode: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db_error"})
		return
	}

	log.Printf("Relay deleted: id=%s relay_id=%s", id, node.RelayID)
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
