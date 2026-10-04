package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/websocket"

	"secagent-server/cmd/secagent-server/internal/auth"
	"secagent-server/cmd/secagent-server/internal/storage"
	"secagent-server/cmd/secagent-server/internal/ws"
)

// ── helpers ──────────────────────────────────────────────────────────────────

// wireChildLinks makes /ws/relay verify like production for CHILD links (JWT, JTI blacklist,
// revoked flag) against the test store.
func wireChildLinks(t *testing.T) *httptest.Server {
	t.Helper()
	prev := ws.JWTSecretsFunc
	ws.SetJWTSecretsFunc(GetServerJWTSecrets)
	ws.SetRelayLocalIDFunc(func() string { return "central" })
	ws.SetRelayJTIBlacklistFunc(func(jti string) (bool, error) { return adminStore.IsJTIBlacklisted(context.Background(), jti) })
	ws.SetRelayRevokedFunc(RelayRevokedCheck)
	srv := httptest.NewServer(http.HandlerFunc(ws.RelayHandler))
	t.Cleanup(func() {
		srv.Close()
		ws.SetJWTSecretsFunc(prev)
		ws.SetRelayLocalIDFunc(nil)
		ws.SetRelayJTIBlacklistFunc(nil)
		ws.SetRelayRevokedFunc(nil)
	})
	return srv
}

func registerPull(t *testing.T, relayID string) RelayCreateResponse {
	t.Helper()
	rr := doAdminRelayRequest(t, AdminCreateRelay, "POST", "/api/admin/relays", map[string]interface{}{"relay_id": relayID, "mode": "pull"})
	if rr.Code != http.StatusCreated {
		t.Fatalf("register %s: %d %s", relayID, rr.Code, rr.Body.String())
	}
	var resp RelayCreateResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	return resp
}

func connectChild(t *testing.T, srv *httptest.Server, token, relayID string) (*websocket.Conn, int, error) {
	t.Helper()
	c, status, err := dialParent(srv, token) // same upgrade, bearer header
	if err == nil {
		t.Cleanup(func() { _ = c.Close() })
		deadline := time.Now().Add(3 * time.Second)
		for !ws.IsRelayConnected(relayID) && time.Now().Before(deadline) {
			time.Sleep(5 * time.Millisecond)
		}
	}
	return c, status, err
}

func expectCloseCode(t *testing.T, c *websocket.Conn) int {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	for {
		var m map[string]any
		if err := c.ReadJSON(&m); err != nil {
			if ce, ok := err.(*websocket.CloseError); ok {
				return ce.Code
			}
			t.Fatalf("expected a close frame, got %v", err)
		}
	}
}

func revokeRelayByPath(t *testing.T, id string) (int, RelayRevokeResponse, string) {
	t.Helper()
	w := httptest.NewRecorder()
	req := adminReq("POST", "/api/admin/relays/"+id+"/revoke", nil)
	req.SetPathValue("id", id)
	AdminRevokeRelay(w, req)
	var resp RelayRevokeResponse
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	return w.Code, resp, w.Body.String()
}

// ── JTI persisted at registration ────────────────────────────────────────────

func TestRelayRevoke_RegistrationPersistsJTIAndExpiryNotTheToken(t *testing.T) {
	s := useFreshStores(t)
	resp := registerPull(t, "dmz1")
	tok, err := jwt.Parse(resp.JWTToken, func(*jwt.Token) (any, error) { return []byte(server.JWTSecret), nil })
	if err != nil {
		t.Fatal(err)
	}
	claims := tok.Claims.(jwt.MapClaims)
	info, err := s.GetRelayTokenInfo("dmz1")
	if err != nil || info.JTI == "" || info.JTI != claims["jti"] || info.Revoked {
		t.Fatalf("info = %+v %v, want the JTI of the issued token", info, err)
	}
	if want := int64(claims["exp"].(float64)); info.Exp < want-5 || info.Exp > want+5 {
		t.Errorf("persisted exp = %d, token exp = %d", info.Exp, want)
	}
	node, _ := s.GetRelayNode("dmz1")
	if strings.Contains(node.TokenHash, resp.JWTToken) {
		t.Error("the token itself must not be stored")
	}
}

// ── revocation: blacklist + live link cut + no reconnect ─────────────────────

func TestRelayRevoke_BlacklistsClosesLinkAndRefusesReconnection(t *testing.T) {
	s := useFreshStores(t)
	srv := wireChildLinks(t)
	dmz1 := registerPull(t, "dmz1")
	dmz2 := registerPull(t, "dmz2")

	c1, _, err := connectChild(t, srv, dmz1.JWTToken, "dmz1")
	if err != nil {
		t.Fatalf("dmz1 must connect: %v", err)
	}
	c2, _, err := connectChild(t, srv, dmz2.JWTToken, "dmz2")
	if err != nil {
		t.Fatalf("dmz2 must connect: %v", err)
	}
	_ = c2

	code, resp, body := revokeRelayByPath(t, dmz1.ID)
	if code != http.StatusOK || !resp.Revoked || !resp.Blacklisted || resp.LegacyToken || !resp.Disconnected {
		t.Fatalf("revoke: %d %s", code, body)
	}
	if strings.Contains(body, dmz1.JWTToken) {
		t.Error("the response must carry no token")
	}
	if got := expectCloseCode(t, c1); got != ws.WSRelayCloseRevoked {
		t.Errorf("close code = %d, want 4010", got)
	}
	// manual reconnection with the same token: refused at the upgrade
	if _, status, err := connectChild(t, srv, dmz1.JWTToken, "dmz1"); err == nil || status != http.StatusUnauthorized {
		t.Errorf("reconnect: status %d err %v, want 401", status, err)
	}
	// the other relay is unaffected
	if !ws.IsRelayConnected("dmz2") {
		t.Error("dmz2 must stay connected")
	}
	if bl, _ := s.IsJTIBlacklisted(context.Background(), mustJTI(t, s, "dmz1")); !bl {
		t.Error("JTI not blacklisted")
	}
	// unknown relay → 404
	if code, _, _ := revokeRelayByPath(t, "no-such-id"); code != http.StatusNotFound {
		t.Errorf("unknown id: %d, want 404", code)
	}
}

func mustJTI(t *testing.T, s *storage.Store, relayID string) string {
	t.Helper()
	info, err := s.GetRelayTokenInfo(relayID)
	if err != nil || info.JTI == "" {
		t.Fatalf("no JTI for %s: %+v %v", relayID, info, err)
	}
	return info.JTI
}

func TestRelayRevoke_ViaTokensRevokeWithRelayID(t *testing.T) {
	useFreshStores(t)
	srv := wireChildLinks(t)
	r := registerPull(t, "dmz1")
	c, _, err := connectChild(t, srv, r.JWTToken, "dmz1")
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	req := adminReq("POST", "/api/admin/tokens/"+r.ID+"/revoke", nil)
	req.SetPathValue("id", r.ID)
	AdminRevokeToken(w, req)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"disconnected":true`) {
		t.Fatalf("tokens revoke <relay id>: %d %s", w.Code, w.Body.String())
	}
	if got := expectCloseCode(t, c); got != ws.WSRelayCloseRevoked {
		t.Errorf("close code = %d", got)
	}
}

// A relay registered before #153 has no JTI: it is still revoked (flag), disconnected and
// refused on reconnection; the response says the token was legacy.
func TestRelayRevoke_LegacyRelayWithoutJTI(t *testing.T) {
	s := useFreshStores(t)
	srv := wireChildLinks(t)
	if err := s.UpsertRelayNode(storage.RelayNode{ID: "uuid-legacy", RelayID: "legacy", Mode: "pull", Status: "connected", CreatedAt: time.Now().Unix()}); err != nil {
		t.Fatal(err)
	}
	// a legacy token: valid signature, role relay, a JTI that was never recorded
	legacy, _, err := auth.New(GetServerJWTSecrets, 720*time.Hour).SignRelay("legacy")
	if err != nil {
		t.Fatal(err)
	}
	c, _, err := connectChild(t, srv, legacy, "legacy")
	if err != nil {
		t.Fatalf("the legacy relay connects before revocation: %v", err)
	}
	code, resp, body := revokeRelayByPath(t, "uuid-legacy")
	if code != http.StatusOK || !resp.Revoked || resp.Blacklisted || !resp.LegacyToken || !resp.Disconnected {
		t.Fatalf("revoke legacy: %d %s", code, body)
	}
	if got := expectCloseCode(t, c); got != ws.WSRelayCloseRevoked {
		t.Errorf("close code = %d", got)
	}
	if _, status, err := connectChild(t, srv, legacy, "legacy"); err == nil || status != http.StatusUnauthorized {
		t.Errorf("legacy reconnect: status %d err %v, want 401 (revoked flag)", status, err)
	}
}

// ── delete ───────────────────────────────────────────────────────────────────

func TestRelayRevoke_DeleteClosesLinkAndBlacklists(t *testing.T) {
	s := useFreshStores(t)
	srv := wireChildLinks(t)
	r := registerPull(t, "dmz1")
	jti := mustJTI(t, s, "dmz1")
	c, _, err := connectChild(t, srv, r.JWTToken, "dmz1")
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	req := adminReq("DELETE", "/api/admin/relays/"+r.ID, nil)
	req.SetPathValue("id", r.ID)
	AdminDeleteRelay(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", w.Code, w.Body.String())
	}
	if got := expectCloseCode(t, c); got != ws.WSRelayCloseRevoked {
		t.Errorf("close code = %d, want 4010", got)
	}
	if bl, _ := s.IsJTIBlacklisted(context.Background(), jti); !bl {
		t.Error("a deleted relay's token must be blacklisted")
	}
	if _, status, err := connectChild(t, srv, r.JWTToken, "dmz1"); err == nil || status != http.StatusUnauthorized {
		t.Errorf("reconnect after delete: status %d err %v, want 401", status, err)
	}
}

func TestRelayRevoke_PushRelayStopsDialerAndClosesLink(t *testing.T) {
	useFreshStores(t)
	calls := setPushHooks(t)
	rr := createPush(t, "dmz9", "wss://dmz9:7772", "child-jwt")
	var resp RelayCreateResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	code, rev, body := revokeRelayByPath(t, resp.ID)
	if code != http.StatusOK || !rev.Revoked || rev.Blacklisted {
		t.Fatalf("revoke push: %d %s", code, body)
	}
	calls.mu.Lock()
	defer calls.mu.Unlock()
	if len(calls.stopped) != 1 || calls.stopped[0] != "dmz9" {
		t.Errorf("dialer not stopped: %v", calls.stopped)
	}
}

// ── re-registration rotates the token ────────────────────────────────────────

func TestRelayRevoke_ReRegistrationCutsTheOldToken(t *testing.T) {
	s := useFreshStores(t)
	srv := wireChildLinks(t)
	old := registerPull(t, "dmz1")
	oldJTI := mustJTI(t, s, "dmz1")
	c, _, err := connectChild(t, srv, old.JWTToken, "dmz1")
	if err != nil {
		t.Fatal(err)
	}
	fresh := registerPull(t, "dmz1") // same relay_id, new token
	if mustJTI(t, s, "dmz1") == oldJTI {
		t.Fatal("a new JTI must be recorded")
	}
	if got := expectCloseCode(t, c); got != ws.WSRelayCloseRevoked {
		t.Errorf("the link authenticated with the replaced token must be cut (4010), got %d", got)
	}
	if _, status, err := connectChild(t, srv, old.JWTToken, "dmz1"); err == nil || status != http.StatusUnauthorized {
		t.Errorf("old token: status %d err %v, want 401", status, err)
	}
	if _, _, err := connectChild(t, srv, fresh.JWTToken, "dmz1"); err != nil {
		t.Errorf("the new token must work: %v", err)
	}
}

// ── security ─────────────────────────────────────────────────────────────────

func TestRelayRevoke_AdminOnly(t *testing.T) {
	useFreshStores(t)
	r := registerPull(t, "dmz1")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/admin/relays/"+r.ID+"/revoke", nil)
	req.SetPathValue("id", r.ID)
	AdminRevokeRelay(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status %d, want 401", w.Code)
	}
}

func TestRelayRevoke_NoTokenInLogsOrResponses(t *testing.T) {
	useFreshStores(t)
	sink := captureLog(t)
	srv := wireChildLinks(t)
	r := registerPull(t, "dmz1")
	_, _, _ = connectChild(t, srv, r.JWTToken, "dmz1")
	_, _, body := revokeRelayByPath(t, r.ID)
	list := httptest.NewRecorder()
	AdminListRelays(list, adminReq("GET", "/api/admin/relays", nil))
	logs := sink.String()
	if logs == "" {
		t.Fatal("no logs captured: vacuous test")
	}
	parts := strings.Split(r.JWTToken, ".")
	for _, secret := range []string{r.JWTToken, parts[0], parts[1], parts[2]} {
		for name, hay := range map[string]string{"logs": logs, "revoke response": body, "list": list.Body.String()} {
			if strings.Contains(hay, secret) {
				t.Fatalf("token material leaked in %s", name)
			}
		}
	}
}
