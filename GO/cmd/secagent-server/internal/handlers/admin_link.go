package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"secagent-server/cmd/secagent-server/internal/auth"
	"secagent-server/cmd/secagent-server/internal/link"
	"secagent-server/cmd/secagent-server/internal/storage"
)

var (
	linkMgrMu sync.RWMutex
	linkMgr   *link.Manager
)

// SetLinkManager injects the link authority (mint, revoke, rotate) used by the admin handlers.
func SetLinkManager(m *link.Manager) {
	linkMgrMu.Lock()
	linkMgr = m
	linkMgrMu.Unlock()
}

func linkManager() *link.Manager {
	linkMgrMu.RLock()
	defer linkMgrMu.RUnlock()
	return linkMgr
}

// writeLinkError maps the errors of the link authority to the documented HTTP answers.
func writeLinkError(w http.ResponseWriter, op string, err error) {
	switch {
	case errors.Is(err, link.ErrNotRoot):
		writeJSON(w, http.StatusConflict, map[string]string{"error": "not_root"})
	case errors.Is(err, link.ErrMasterKey):
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "master_key_required"})
	case errors.Is(err, link.ErrPreviousOpen):
		writeJSON(w, http.StatusConflict, map[string]string{"error": "previous_key_not_retired"})
	case errors.Is(err, link.ErrNoPrevious):
		writeJSON(w, http.StatusConflict, map[string]string{"error": "no_previous_key"})
	case errors.Is(err, link.ErrInvalidRequest):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
	default:
		log.Printf("%s: %v", op, err) // the error never carries key material
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db_error"})
	}
}

// createLinkToken mints a relay-child / relay-parent link token on the root (#141/#146).
func createLinkToken(ctx context.Context, w http.ResponseWriter, req TokenCreateRequest) {
	m := linkManager()
	if m == nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "link_not_configured"})
		return
	}
	sub, aud := strings.TrimSpace(req.Sub), strings.TrimSpace(req.Aud)
	switch {
	case sub == "":
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing_sub"})
		return
	case aud == "":
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing_aud"})
		return
	case !relayIDPattern.MatchString(sub):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_sub"})
		return
	case !relayIDPattern.MatchString(aud):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_aud"})
		return
	case sub == aud:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "sub_equals_aud"})
		return
	}
	ttl := link.DefaultTTL
	if strings.TrimSpace(req.ExpiresAt) != "" {
		exp, err := time.Parse(time.RFC3339, req.ExpiresAt)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_expires_at"})
			return
		}
		ttl = time.Until(exp)
		if ttl <= 0 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "expires_in_the_past"})
			return
		}
		if ttl > link.MaxTTL {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "expires_exceeds_maximum_365d"})
			return
		}
	}
	by := req.CreatedBy
	if by == "" {
		by = "admin-cli"
	}
	out, err := m.Mint(ctx, link.MintRequest{Role: req.Role, Sub: sub, Aud: aud, TTL: ttl, Description: req.Description, CreatedBy: by})
	if err != nil {
		writeLinkError(w, "AdminCreateToken link", err)
		return
	}
	rec := out.Rec
	log.Printf("Link token minted: id=%q role=%q sub=%q aud=%q kid=%q expires=%s", rec.ID, rec.Role, rec.Sub, rec.Aud, rec.KID, rec.ExpiresAt.Format(time.RFC3339))
	writeJSON(w, http.StatusCreated, TokenCreateResponse{
		Token: out.Token, // shown ONCE; neither stored nor logged
		ID:    rec.ID, Role: rec.Role, Sub: rec.Sub, Aud: rec.Aud, JTI: rec.JTI, KID: rec.KID,
		ExpiresAt: rec.ExpiresAt.Format(time.RFC3339), Description: rec.Description, CreatedAt: rec.CreatedAt.Format(time.RFC3339),
	})
}

// LinkTokenSummary is the list view of a link token: metadata only.
type LinkTokenSummary struct {
	ID          string `json:"id"`
	Role        string `json:"role"`
	Sub         string `json:"sub"`
	Aud         string `json:"aud"`
	JTI         string `json:"jti"`
	KID         string `json:"kid"`
	Description string `json:"description,omitempty"`
	CreatedBy   string `json:"created_by,omitempty"`
	CreatedAt   string `json:"created_at"`
	ExpiresAt   string `json:"expires_at"`
	Revoked     bool   `json:"revoked"`
	RevokedAt   string `json:"revoked_at,omitempty"`
}

func linkTokenSummary(t storage.LinkToken) LinkTokenSummary {
	s := LinkTokenSummary{ID: t.ID, Role: t.Role, Sub: t.Sub, Aud: t.Aud, JTI: t.JTI, KID: t.KID, Description: t.Description,
		CreatedBy: t.CreatedBy, CreatedAt: t.CreatedAt.Format(time.RFC3339), ExpiresAt: t.ExpiresAt.Format(time.RFC3339), Revoked: t.RevokedAt != nil}
	if t.RevokedAt != nil {
		s.RevokedAt = t.RevokedAt.Format(time.RFC3339)
	}
	return s
}

// revokeLinkToken revokes a link token if id names one. handled=false: not a link token.
func revokeLinkToken(ctx context.Context, w http.ResponseWriter, id string) (handled bool) {
	if _, ok := adminStore.GetLinkToken(id); !ok {
		return false
	}
	m := linkManager()
	if m == nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "link_not_configured"})
		return true
	}
	rec, seq, closed, found, err := m.Revoke(ctx, id)
	if err != nil {
		writeLinkError(w, "AdminRevokeToken link", err)
		return true
	}
	if !found {
		return false
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"revoked": true, "id": id, "jti": rec.JTI, "seq": seq, "links_closed": closed,
		"updated_at": time.Now().UTC().Format(time.RFC3339),
	})
	return true
}

// ── /api/admin/link/* — signing key of the links (root only) ─────────────────

func linkAdmin(w http.ResponseWriter, r *http.Request) *link.Manager {
	if !requireAdminAuth(w, r) {
		return nil
	}
	m := linkManager()
	if m == nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "link_not_configured"})
	}
	return m
}

// AdminLinkPubkey: GET /api/admin/link/pubkey — the PUBLIC key to pin on the children.
func AdminLinkPubkey(w http.ResponseWriter, r *http.Request) {
	m := linkAdmin(w, r)
	if m == nil {
		return
	}
	info, err := m.PublicInfo()
	if err != nil {
		writeLinkError(w, "AdminLinkPubkey", err)
		return
	}
	writeJSON(w, http.StatusOK, info)
}

// AdminLinkRotate: POST /api/admin/link/keys/rotate.
func AdminLinkRotate(w http.ResponseWriter, r *http.Request) {
	m := linkAdmin(w, r)
	if m == nil {
		return
	}
	cur, prev, seq, err := m.Rotate(r.Context())
	if err != nil {
		writeLinkError(w, "AdminLinkRotate", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"current_kid": cur, "previous_kid": prev, "seq": seq})
}

// AdminLinkRetire: POST /api/admin/link/keys/retire-previous {"force":bool}.
func AdminLinkRetire(w http.ResponseWriter, r *http.Request) {
	m := linkAdmin(w, r)
	if m == nil {
		return
	}
	var body struct {
		Force bool `json:"force"`
	}
	if r.Body != nil && r.ContentLength != 0 {
		defer func() { _ = r.Body.Close() }()
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json"})
			return
		}
	}
	seq, unconfirmed, err := m.Retire(r.Context(), body.Force)
	if errors.Is(err, link.ErrUnconfirmed) {
		writeJSON(w, http.StatusConflict, map[string]interface{}{"error": "rotation_unconfirmed", "unconfirmed": unconfirmed})
		return
	}
	if err != nil {
		writeLinkError(w, "AdminLinkRetire", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"retired": true, "seq": seq, "unconfirmed": unconfirmed})
}

// AdminLinkStatus: GET /api/admin/link/status.
func AdminLinkStatus(w http.ResponseWriter, r *http.Request) {
	m := linkAdmin(w, r)
	if m == nil {
		return
	}
	st, err := m.Status()
	if err != nil {
		writeLinkError(w, "AdminLinkStatus", err)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

var _ = auth.RoleRelayChild
