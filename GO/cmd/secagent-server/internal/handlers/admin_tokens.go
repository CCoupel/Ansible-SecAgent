package handlers

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"

	"secagent-server/cmd/secagent-server/internal/auth"
	"secagent-server/cmd/secagent-server/internal/storage"
)

// ========================================================================
// Request / Response types — tokens
// ========================================================================

// TokenCreateRequest is the body for POST /api/admin/tokens.
// The "role" field determines whether an enrollment, plugin, relay-child or relay-parent token is created.
type TokenCreateRequest struct {
	Role                   string `json:"role"`                               // "enrollment", "plugin" or "relay-parent"
	HostnamePattern        string `json:"hostname_pattern,omitempty"`         // enrollment only
	Reusable               int    `json:"reusable,omitempty"`                 // enrollment only: 0=one-shot, 1=permanent
	Description            string `json:"description,omitempty"`              // plugin only
	AllowedIPs             string `json:"allowed_ips,omitempty"`              // plugin only, comma-separated CIDRs
	AllowedHostnamePattern string `json:"allowed_hostname_pattern,omitempty"` // plugin only
	ExpiresAt              string `json:"expires_at,omitempty"`               // RFC3339 or empty = no expiry (REQUIRED for relay-parent)
	CreatedBy              string `json:"created_by,omitempty"`
	Sub                    string `json:"sub,omitempty"` // relay-child / relay-parent: relay_id of the presenter
	Aud                    string `json:"aud,omitempty"` // relay-child / relay-parent: relay_id of the verifier
}

// TokenCreateResponse is returned from POST /api/admin/tokens.
// The token plain text is shown only once.
type TokenCreateResponse struct {
	Token     string `json:"token"` // plain text — shown ONCE, never stored
	ID        string `json:"id"`
	Role      string `json:"role"`
	ExpiresAt string `json:"expires_at,omitempty"`
	// enrollment fields
	HostnamePattern string `json:"hostname_pattern,omitempty"`
	Reusable        bool   `json:"reusable,omitempty"`
	// plugin fields
	Description            string `json:"description,omitempty"`
	AllowedIPs             string `json:"allowed_ips,omitempty"`
	AllowedHostnamePattern string `json:"allowed_hostname_pattern,omitempty"`
	// link token fields (relay-child / relay-parent)
	Sub string `json:"sub,omitempty"`
	Aud string `json:"aud,omitempty"`
	JTI string `json:"jti,omitempty"`
	KID string `json:"kid,omitempty"`
	// audit
	UseCount  int    `json:"use_count"`
	CreatedAt string `json:"created_at"`
}

var relayIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,62}$`)

// EnrollmentTokenSummary is the list view for enrollment tokens (no plain text).
type EnrollmentTokenSummary struct {
	ID              string `json:"id"`
	Role            string `json:"role"`
	TokenHash       string `json:"token_hash"`
	HostnamePattern string `json:"hostname_pattern"`
	Reusable        bool   `json:"reusable"`
	UseCount        int    `json:"use_count"`
	LastUsedAt      string `json:"last_used_at,omitempty"`
	ExpiresAt       string `json:"expires_at,omitempty"`
	CreatedAt       string `json:"created_at"`
	CreatedBy       string `json:"created_by,omitempty"`
}

// PluginTokenSummary is the list view for plugin tokens (no plain text).
type PluginTokenSummary struct {
	ID                     string `json:"id"`
	Role                   string `json:"role"`
	TokenHash              string `json:"token_hash"`
	Description            string `json:"description,omitempty"`
	AllowedIPs             string `json:"allowed_ips,omitempty"`
	AllowedHostnamePattern string `json:"allowed_hostname_pattern,omitempty"`
	ExpiresAt              string `json:"expires_at,omitempty"`
	LastUsedAt             string `json:"last_used_at,omitempty"`
	LastUsedIP             string `json:"last_used_ip,omitempty"`
	// LastUsedApproximate is true whenever last_used_at / last_used_ip are reported: they are kept
	// in memory and persisted only with the next write of the state, so they may lag by minutes and
	// a token used just before a crash can read "never used" (audits must not rely on them).
	LastUsedApproximate bool   `json:"last_used_approximate,omitempty"`
	Revoked             bool   `json:"revoked"`
	CreatedAt           string `json:"created_at"`
}

// PurgeResponse is returned from POST /api/admin/tokens/purge.
type PurgeResponse struct {
	DeletedCount int64  `json:"deleted_count"`
	PurgedAt     string `json:"purged_at"`
}

// ========================================================================
// POST /api/admin/tokens
// ========================================================================

// AdminCreateToken creates a new enrollment or plugin token.
// The token plain text is returned once in the response and never stored.
func AdminCreateToken(w http.ResponseWriter, r *http.Request) {
	if !requireAdminAuth(w, r) {
		return
	}

	defer func() { _ = r.Body.Close() }()

	var req TokenCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json"})
		return
	}

	req.Role = strings.TrimSpace(req.Role)
	if req.Role != "enrollment" && req.Role != "plugin" && req.Role != auth.RoleRelayChild && req.Role != auth.RoleRelayParent {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_role"})
		return
	}

	if adminStore == nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "store_not_initialized"})
		return
	}

	ctx := r.Context()

	if req.Role == auth.RoleRelayChild || req.Role == auth.RoleRelayParent {
		createLinkToken(ctx, w, req)
		return
	}

	// Generate token: 32 random bytes → hex prefix
	rawBytes := make([]byte, 32)
	if _, err := rand.Read(rawBytes); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "token_generation_failed"})
		return
	}
	prefix := map[string]string{"enrollment": "secagent_enr_", "plugin": "secagent_plg_"}[req.Role]
	tokenPlain := prefix + hex.EncodeToString(rawBytes)

	// SHA-256 hash for DB storage
	h := sha256.Sum256([]byte(tokenPlain))
	tokenHash := fmt.Sprintf("%x", h)

	id := uuid.New().String()
	now := time.Now().UTC()

	// Parse optional expiry
	var expiresAt *time.Time
	if req.ExpiresAt != "" {
		t, err := time.Parse(time.RFC3339, req.ExpiresAt)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_expires_at"})
			return
		}
		expiresAt = &t
	}

	createdBy := req.CreatedBy
	if createdBy == "" {
		createdBy = "admin-cli"
	}

	switch req.Role {
	case "enrollment":
		if strings.TrimSpace(req.HostnamePattern) == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing_hostname_pattern"})
			return
		}
		if _, err := regexp.Compile(req.HostnamePattern); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_hostname_pattern"})
			return
		}
		tok := storage.EnrollmentToken{
			ID:              id,
			TokenHash:       tokenHash,
			HostnamePattern: req.HostnamePattern,
			Reusable:        req.Reusable != 0,
			CreatedAt:       now,
			ExpiresAt:       expiresAt,
			CreatedBy:       createdBy,
		}
		if err := adminStore.CreateEnrollmentToken(ctx, tok); err != nil {
			log.Printf("AdminCreateToken enrollment: %v", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db_error"})
			return
		}
		log.Printf("Enrollment token created by admin: id=%q pattern=%q reusable=%v", id, req.HostnamePattern, tok.Reusable)

	case "plugin":
		if req.AllowedHostnamePattern != "" {
			if _, err := regexp.Compile(req.AllowedHostnamePattern); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_hostname_pattern"})
				return
			}
		}
		tok := storage.PluginToken{
			ID:                     id,
			TokenHash:              tokenHash,
			Description:            req.Description,
			Role:                   "plugin",
			AllowedIPs:             req.AllowedIPs,
			AllowedHostnamePattern: req.AllowedHostnamePattern,
			CreatedAt:              now,
			ExpiresAt:              expiresAt,
		}
		if err := adminStore.CreatePluginToken(ctx, tok); err != nil {
			log.Printf("AdminCreateToken plugin: %v", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db_error"})
			return
		}
		log.Printf("Plugin token created by admin: id=%q description=%q", id, req.Description)
	}

	expiresStr := ""
	if expiresAt != nil {
		expiresStr = expiresAt.UTC().Format(time.RFC3339)
	}

	resp := TokenCreateResponse{
		Token:                  tokenPlain, // shown once
		ID:                     id,
		Role:                   req.Role,
		ExpiresAt:              expiresStr,
		HostnamePattern:        req.HostnamePattern,
		Reusable:               req.Reusable != 0,
		Description:            req.Description,
		AllowedIPs:             req.AllowedIPs,
		AllowedHostnamePattern: req.AllowedHostnamePattern,
		UseCount:               0,
		CreatedAt:              now.Format(time.RFC3339),
	}

	writeJSON(w, http.StatusCreated, resp)
}

// ========================================================================
// GET /api/admin/tokens?role=enrollment|plugin|relay-parent|all
// ========================================================================

// AdminListTokens returns all tokens, optionally filtered by role.
// Never returns token plain text — only hash and metadata.
func AdminListTokens(w http.ResponseWriter, r *http.Request) {
	if !requireAdminAuth(w, r) {
		return
	}

	if adminStore == nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "store_not_initialized"})
		return
	}

	role := strings.ToLower(r.URL.Query().Get("role"))
	if role == "" {
		role = "all"
	}
	if role != "enrollment" && role != "plugin" && role != auth.RoleRelayChild && role != auth.RoleRelayParent && role != "all" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_role"})
		return
	}

	ctx := context.Background()
	var result []interface{}

	if role == "enrollment" || role == "all" {
		tokens, err := adminStore.ListEnrollmentTokens(ctx)
		if err != nil {
			log.Printf("AdminListTokens enrollment: %v", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db_error"})
			return
		}
		for _, t := range tokens {
			result = append(result, enrollmentTokenToSummary(t))
		}
	}

	if role == "plugin" || role == "all" {
		tokens, err := adminStore.ListPluginTokens(ctx)
		if err != nil {
			log.Printf("AdminListTokens plugin: %v", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db_error"})
			return
		}
		for _, t := range tokens {
			result = append(result, pluginTokenToSummary(t))
		}
	}

	if role == auth.RoleRelayChild || role == auth.RoleRelayParent || role == "all" {
		for _, t := range adminStore.ListLinkTokens() { // registry of the link tokens: metadata only
			if role == "all" || t.Role == role {
				result = append(result, linkTokenSummary(t))
			}
		}
	}

	if result == nil {
		result = []interface{}{}
	}

	writeJSON(w, http.StatusOK, result)
}

// ========================================================================
// POST /api/admin/tokens/{id}/revoke
// ========================================================================

// AdminRevokeToken soft-deletes a plugin token (sets revoked=1).
// Enrollment tokens do not have a revoke field — use DELETE for them.
func AdminRevokeToken(w http.ResponseWriter, r *http.Request) {
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

	ctx := r.Context()

	// Try plugin token first
	found, err := adminStore.RevokePluginToken(ctx, id)
	if err != nil {
		log.Printf("AdminRevokeToken plugin: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db_error"})
		return
	}
	if found {
		log.Printf("Token revoked: id=%q", id)
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"revoked":    true,
			"id":         id,
			"updated_at": time.Now().UTC().Format(time.RFC3339),
		})
		return
	}

	// Link token (relay-child / relay-parent): registry + blacklist + seq in one mutation, links cut (4010).
	if revokeLinkToken(ctx, w, id) {
		return
	}

	// Relay node (pull token or push link) addressed by its id: SECURITY.md §7 « tokens revoke ».
	if node, nerr := adminStore.GetRelayNodeByID(id); nerr != nil {
		log.Printf("AdminRevokeToken relay: %v", nerr)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db_error"})
		return
	} else if node != nil {
		resp, rerr := revokeRelayNode(r, node)
		if rerr != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db_error"})
			return
		}
		writeJSON(w, http.StatusOK, resp)
		return
	}

	// Enrollment tokens don't support soft-revoke — return 404
	tok, err := adminStore.GetEnrollmentTokenByID(ctx, id)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db_error"})
		return
	}
	if tok != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "enrollment_tokens_use_delete_not_revoke",
		})
		return
	}

	writeJSON(w, http.StatusNotFound, map[string]string{"error": "token_not_found"})
}

// ========================================================================
// DELETE /api/admin/tokens/{id}
// ========================================================================

// AdminDeleteToken permanently removes a token (enrollment or plugin).
func AdminDeleteToken(w http.ResponseWriter, r *http.Request) {
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

	ctx := r.Context()

	// Try enrollment token first
	deleted, err := adminStore.DeleteEnrollmentToken(ctx, id)
	if err != nil {
		log.Printf("AdminDeleteToken enrollment: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db_error"})
		return
	}
	if deleted {
		log.Printf("Enrollment token deleted: id=%q", id)
		writeJSON(w, http.StatusOK, map[string]interface{}{"deleted": true, "id": id})
		return
	}

	// Try plugin token
	deleted, err = adminStore.DeletePluginToken(ctx, id)
	if err != nil {
		log.Printf("AdminDeleteToken plugin: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db_error"})
		return
	}
	if deleted {
		log.Printf("Plugin token deleted: id=%q", id)
		writeJSON(w, http.StatusOK, map[string]interface{}{"deleted": true, "id": id})
		return
	}

	writeJSON(w, http.StatusNotFound, map[string]string{"error": "token_not_found"})
}

// ========================================================================
// POST /api/admin/tokens/purge?expired=1&used=1
// ========================================================================

// AdminPurgeTokens bulk-removes expired and/or consumed one-shot tokens.
func AdminPurgeTokens(w http.ResponseWriter, r *http.Request) {
	if !requireAdminAuth(w, r) {
		return
	}

	if adminStore == nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "store_not_initialized"})
		return
	}

	purgeExpired := r.URL.Query().Get("expired") == "1"
	purgeUsed := r.URL.Query().Get("used") == "1"

	if !purgeExpired && !purgeUsed {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "specify_at_least_one_param_expired_or_used",
		})
		return
	}

	ctx := r.Context()
	var totalDeleted int64

	if purgeExpired {
		n, err := adminStore.PurgeExpiredEnrollmentTokens(ctx)
		if err != nil {
			log.Printf("AdminPurgeTokens expired enrollment: %v", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db_error"})
			return
		}
		totalDeleted += n
		// Plugin tokens don't have a separate purge method yet; treat as no-op
	}

	if purgeUsed {
		n, err := adminStore.PurgeUsedOneShotEnrollmentTokens(ctx)
		if err != nil {
			log.Printf("AdminPurgeTokens used enrollment: %v", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db_error"})
			return
		}
		totalDeleted += n
	}

	log.Printf("Tokens purged: count=%d expired=%v used=%v", totalDeleted, purgeExpired, purgeUsed)
	writeJSON(w, http.StatusOK, PurgeResponse{
		DeletedCount: totalDeleted,
		PurgedAt:     time.Now().UTC().Format(time.RFC3339),
	})
}

// ========================================================================
// Internal helpers
// ========================================================================

func enrollmentTokenToSummary(t storage.EnrollmentToken) EnrollmentTokenSummary {
	s := EnrollmentTokenSummary{
		ID:              t.ID,
		Role:            "enrollment",
		TokenHash:       t.TokenHash,
		HostnamePattern: t.HostnamePattern,
		Reusable:        t.Reusable,
		UseCount:        t.UseCount,
		CreatedAt:       t.CreatedAt.UTC().Format(time.RFC3339),
		CreatedBy:       t.CreatedBy,
	}
	if t.LastUsedAt != nil {
		s.LastUsedAt = t.LastUsedAt.UTC().Format(time.RFC3339)
	}
	if t.ExpiresAt != nil {
		s.ExpiresAt = t.ExpiresAt.UTC().Format(time.RFC3339)
	}
	return s
}

func pluginTokenToSummary(t storage.PluginToken) PluginTokenSummary {
	s := PluginTokenSummary{
		ID:                     t.ID,
		Role:                   "plugin",
		TokenHash:              t.TokenHash,
		Description:            t.Description,
		AllowedIPs:             t.AllowedIPs,
		AllowedHostnamePattern: t.AllowedHostnamePattern,
		Revoked:                t.Revoked,
		LastUsedIP:             t.LastUsedIP,
		CreatedAt:              t.CreatedAt.UTC().Format(time.RFC3339),
	}
	if t.ExpiresAt != nil {
		s.ExpiresAt = t.ExpiresAt.UTC().Format(time.RFC3339)
	}
	if t.LastUsedAt != nil {
		s.LastUsedAt = t.LastUsedAt.UTC().Format(time.RFC3339)
		s.LastUsedApproximate = true
	}
	return s
}
