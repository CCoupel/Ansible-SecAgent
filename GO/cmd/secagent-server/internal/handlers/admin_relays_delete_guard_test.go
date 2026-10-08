package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"secagent-server/cmd/secagent-server/internal/storage"
	"secagent-server/cmd/secagent-server/internal/ws"
)

// ── DELETE of a relay whose token cannot be blacklisted (#153, security-reviewer MOYEN) ──

func deleteRelayByID(t *testing.T, id string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	req := adminReq("DELETE", "/api/admin/relays/"+id, nil)
	req.SetPathValue("id", id)
	AdminDeleteRelay(w, req)
	return w
}

func seedLegacyRelay(t *testing.T, s *storage.Store, relayID, mode string) {
	t.Helper()
	n := storage.RelayNode{ID: "uuid-" + relayID, RelayID: relayID, Mode: mode, Status: "connected", CreatedAt: time.Now().Unix()}
	if mode == "push" {
		n.TokenSecret = "enc:sealed-for-" + relayID // the state only holds sealed push tokens
	}
	if err := s.UpsertRelayNode(n); err != nil {
		t.Fatal(err)
	}
}

func TestDeleteGuard_LegacyRelayNotRevokedIsRefusedWith409(t *testing.T) {
	s := useFreshStores(t)
	srv := wireChildLinks(t)
	seedLegacyRelay(t, s, "legacy", "pull")
	// a relay whose JTI the node never learned (legacy row): token minted, JTI deliberately NOT recorded
	code, tk, raw := mintLink(t, map[string]interface{}{"role": "relay-child", "sub": "legacy", "aud": testRootID})
	if code != http.StatusCreated {
		t.Fatalf("mint: %d %s", code, raw)
	}
	legacyToken := tk.Token
	c, _, err := connectChild(t, srv, legacyToken, "legacy")
	if err != nil {
		t.Fatal(err)
	}

	w := deleteRelayByID(t, "uuid-legacy")
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "revoke the relay first") {
		t.Fatalf("delete: %d %s, want 409 with an explicit message", w.Code, w.Body.String())
	}
	// nothing happened: row kept, link kept, no bypass
	if n, _ := s.GetRelayNode("legacy"); n == nil {
		t.Error("the relay row must still exist")
	}
	if !ws.IsRelayConnected("legacy") {
		t.Error("the link must not be closed by a refused delete")
	}
	_ = c

	// after the revoke, the delete goes through and the old token stays refused
	if code, _, body := revokeRelayByPath(t, "uuid-legacy"); code != http.StatusOK {
		t.Fatalf("revoke: %d %s", code, body)
	}
	if w := deleteRelayByID(t, "uuid-legacy"); w.Code != http.StatusNoContent {
		t.Fatalf("delete after revoke: %d %s", w.Code, w.Body.String())
	}
	if n, _ := s.GetRelayNode("legacy"); n != nil {
		t.Error("the relay row must be gone")
	}
}

// The reason for the guard: without it, deleting a legacy relay drops the revoked flag and the
// old token could reconnect (auto-registration recreates the row). With the guard, the only way
// to delete is to revoke first, and the flag is consulted before the row disappears.
func TestDeleteGuard_RelayWithTrackedJTIIsUnchanged(t *testing.T) {
	s := useFreshStores(t)
	srv := wireChildLinks(t)
	r := registerPull(t, "dmz1")
	jti := mustJTI(t, s, "dmz1")
	c, _, err := connectChild(t, srv, r.JWTToken, "dmz1")
	if err != nil {
		t.Fatal(err)
	}
	if w := deleteRelayByID(t, r.ID); w.Code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", w.Code, w.Body.String())
	}
	if got := expectCloseCode(t, c); got != ws.WSRelayCloseRevoked {
		t.Errorf("close code = %d", got)
	}
	if bl, _ := s.IsJTIBlacklisted(context.Background(), jti); !bl {
		t.Error("JTI must be blacklisted on delete")
	}
}

func TestDeleteGuard_PushRelayRequiresRevokeFirst(t *testing.T) {
	s := useFreshStores(t)
	setPushHooks(t)
	seedLegacyRelay(t, s, "dmz9", "push")
	if w := deleteRelayByID(t, "uuid-dmz9"); w.Code != http.StatusConflict {
		t.Fatalf("push relay delete without revoke: %d %s, want 409", w.Code, w.Body.String())
	}
	if code, _, body := revokeRelayByPath(t, "uuid-dmz9"); code != http.StatusOK {
		t.Fatalf("revoke: %d %s", code, body)
	}
	if w := deleteRelayByID(t, "uuid-dmz9"); w.Code != http.StatusNoContent {
		t.Fatalf("push relay delete after revoke: %d %s", w.Code, w.Body.String())
	}
}

func TestDeleteGuard_UnknownRelayStill404(t *testing.T) {
	useFreshStores(t)
	if w := deleteRelayByID(t, "nope"); w.Code != http.StatusNotFound {
		t.Errorf("status %d, want 404", w.Code)
	}
}
