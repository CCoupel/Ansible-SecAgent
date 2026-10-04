package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/websocket"

	"secagent-server/cmd/secagent-server/internal/ws"
)

// ── helpers ──────────────────────────────────────────────────────────────────

func mintParentToken(t *testing.T, body map[string]interface{}) (int, TokenCreateResponse, string) {
	t.Helper()
	body["role"] = "relay-parent"
	w := httptest.NewRecorder()
	AdminCreateToken(w, adminReq("POST", "/api/admin/tokens", body))
	var resp TokenCreateResponse
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	return w.Code, resp, w.Body.String()
}

func in(d time.Duration) string { return time.Now().UTC().Add(d).Format(time.RFC3339) }

// captureLog redirects the standard logger and returns the sink.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })
	return &buf
}

// ── creation ─────────────────────────────────────────────────────────────────

func TestRelayParentToken_CreateShowsJWTOnceAndPersistsMetadataOnly(t *testing.T) {
	s := useFreshStores(t)
	code, resp, _ := mintParentToken(t, map[string]interface{}{"sub": "central", "expires_at": in(90 * 24 * time.Hour), "description": "uplink"})
	if code != http.StatusCreated {
		t.Fatalf("status %d", code)
	}
	if resp.Token == "" || resp.Role != "relay-parent" || resp.Sub != "central" || resp.ID == "" || resp.JTI == "" {
		t.Fatalf("response = %+v", resp)
	}
	// the JWT is signed with this node's secret and carries role, sub, jti and exp
	tok, err := jwt.Parse(resp.Token, func(*jwt.Token) (any, error) { return []byte(server.JWTSecret), nil })
	if err != nil || !tok.Valid {
		t.Fatalf("jwt invalid: %v", err)
	}
	claims := tok.Claims.(jwt.MapClaims)
	exp, _ := claims["exp"].(float64)
	if claims["role"] != "relay-parent" || claims["sub"] != "central" || claims["jti"] != resp.JTI ||
		time.Until(time.Unix(int64(exp), 0)) < 89*24*time.Hour {
		t.Errorf("claims = %v", claims)
	}
	// metadata persisted, the token itself nowhere
	list, err := s.ListRelayParentTokens(context.Background())
	if err != nil || len(list) != 1 || list[0].JTI != resp.JTI || list[0].ParentID != "central" {
		t.Fatalf("persisted = %+v %v", list, err)
	}
	// list: id/sub/exp/revoked, never the token
	w := httptest.NewRecorder()
	AdminListTokens(w, adminReq("GET", "/api/admin/tokens?role=relay-parent", nil))
	if w.Code != http.StatusOK || strings.Contains(w.Body.String(), resp.Token) || strings.Contains(w.Body.String(), `"token"`) {
		t.Errorf("list leaks the token or fails: %d %s", w.Code, w.Body.String())
	}
	var summaries []RelayParentTokenSummary
	if err := json.Unmarshal(w.Body.Bytes(), &summaries); err != nil || len(summaries) != 1 ||
		summaries[0].ID != resp.ID || summaries[0].Sub != "central" || summaries[0].Revoked || summaries[0].ExpiresAt == "" {
		t.Errorf("summaries = %+v %v", summaries, err)
	}
	// "all" includes it too
	w = httptest.NewRecorder()
	AdminListTokens(w, adminReq("GET", "/api/admin/tokens", nil))
	if !strings.Contains(w.Body.String(), resp.ID) || strings.Contains(w.Body.String(), resp.Token) {
		t.Errorf("all-roles list = %s", w.Body.String())
	}
}

func TestRelayParentToken_CreateValidation(t *testing.T) {
	useFreshStores(t)
	ws.SetRelayLocalIDFunc(func() string { return "dmz1" })
	ws.SetRelayAncestorsFunc(func() []string { return []string{"root"} })
	t.Cleanup(func() { ws.SetRelayLocalIDFunc(nil); ws.SetRelayAncestorsFunc(nil) })

	tests := []struct {
		name string
		body map[string]interface{}
		want string
	}{
		{"no expiry", map[string]interface{}{"sub": "central"}, "expires_required_for_relay_parent"},
		{"expiry in the past", map[string]interface{}{"sub": "central", "expires_at": in(-time.Hour)}, "expires_in_the_past"},
		{"beyond the 365d cap", map[string]interface{}{"sub": "central", "expires_at": in(366 * 24 * time.Hour)}, "expires_exceeds_maximum_365d"},
		{"malformed expiry", map[string]interface{}{"sub": "central", "expires_at": "tomorrow"}, "invalid_expires_at"},
		{"missing sub", map[string]interface{}{"expires_at": in(time.Hour)}, "invalid_sub"},
		{"bad sub", map[string]interface{}{"sub": "a b/c", "expires_at": in(time.Hour)}, "invalid_sub"},
		{"sub is this node", map[string]interface{}{"sub": "dmz1", "expires_at": in(time.Hour)}, "sub_would_create_loop"},
		{"sub is an ancestor of this node", map[string]interface{}{"sub": "root", "expires_at": in(time.Hour)}, "sub_would_create_loop"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, resp, raw := mintParentToken(t, tt.body)
			if code != http.StatusBadRequest || !strings.Contains(raw, tt.want) {
				t.Errorf("status %d body %s, want 400 %s", code, raw, tt.want)
			}
			if resp.Token != "" {
				t.Error("no token may be issued on refusal")
			}
		})
	}
	// the cap itself is accepted
	if code, _, raw := mintParentToken(t, map[string]interface{}{"sub": "central", "expires_at": in(364 * 24 * time.Hour)}); code != http.StatusCreated {
		t.Errorf("364d must be accepted: %d %s", code, raw)
	}
}

func TestRelayParentToken_AdminOnly(t *testing.T) {
	useFreshStores(t)
	body, _ := json.Marshal(map[string]interface{}{"role": "relay-parent", "sub": "central", "expires_at": in(time.Hour)})
	for name, hdr := range map[string]string{"no auth": "", "plugin-style token": "Bearer secagent_plg_x", "wrong admin": "Bearer nope"} {
		req := httptest.NewRequest("POST", "/api/admin/tokens", bytes.NewReader(body))
		if hdr != "" {
			req.Header.Set("Authorization", hdr)
		}
		w := httptest.NewRecorder()
		AdminCreateToken(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("%s: status %d, want 401", name, w.Code)
		}
	}
}

// ── revocation + end to end with the /ws/relay handler ───────────────────────

// wireRelayWS makes /ws/relay verify with this server's secret and blacklist, and accept a parent link.
func wireRelayWS(t *testing.T, serve func(*websocket.Conn) error) *httptest.Server {
	t.Helper()
	prevJWT := ws.JWTSecretsFunc
	ws.SetJWTSecretsFunc(GetServerJWTSecrets)
	ws.SetRelayLocalIDFunc(func() string { return "dmz1" })
	ws.SetRelayJTIBlacklistFunc(func(jti string) (bool, error) {
		return adminStore.IsJTIBlacklisted(context.Background(), jti)
	})
	ws.SetRelayParentLinkFunc(func(_ context.Context, conn *websocket.Conn, _ []string, ack func() error) error {
		if err := ack(); err != nil {
			return err
		}
		return serve(conn)
	})
	srv := httptest.NewServer(http.HandlerFunc(ws.RelayHandler))
	t.Cleanup(func() {
		srv.Close()
		ws.SetJWTSecretsFunc(prevJWT)
		ws.SetRelayLocalIDFunc(nil)
		ws.SetRelayJTIBlacklistFunc(nil)
		ws.SetRelayParentLinkFunc(nil)
	})
	return srv
}

func dialParent(srv *httptest.Server, token string) (*websocket.Conn, int, error) {
	h := http.Header{}
	h.Set("Authorization", "Bearer "+token)
	c, resp, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http")+"/ws/relay", h)
	status := 0
	if resp != nil {
		status = resp.StatusCode
	}
	return c, status, err
}

func TestRelayParentToken_EndToEndLinkAndRevocation(t *testing.T) {
	useFreshStores(t)
	linked := make(chan struct{}, 4)
	srv := wireRelayWS(t, func(conn *websocket.Conn) error {
		linked <- struct{}{}
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return err
			}
		}
	})
	_, resp, _ := mintParentToken(t, map[string]interface{}{"sub": "central", "expires_at": in(24 * time.Hour)})

	// 1. a parent configured with the token establishes the link
	c, _, err := dialParent(srv, resp.Token)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = c.Close() }()
	if err := c.WriteJSON(map[string]any{"type": "relay_hello", "relay_id": "central", "version": "3.0"}); err != nil {
		t.Fatal(err)
	}
	var ack map[string]any
	if err := c.ReadJSON(&ack); err != nil || ack["type"] != "relay_ack" || ack["relay_id"] != "dmz1" {
		t.Fatalf("ack = %v %v", ack, err)
	}
	select {
	case <-linked:
	case <-time.After(3 * time.Second):
		t.Fatal("link not served")
	}

	// 2. revoke → the live link is cut with 4010 ...
	w := httptest.NewRecorder()
	req := adminReq("POST", "/api/admin/tokens/"+resp.ID+"/revoke", nil)
	req.SetPathValue("id", resp.ID)
	AdminRevokeToken(w, req)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"disconnected":true`) {
		t.Fatalf("revoke: %d %s", w.Code, w.Body.String())
	}
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	var m map[string]any
	err = c.ReadJSON(&m)
	if ce, ok := err.(*websocket.CloseError); !ok || ce.Code != ws.WSRelayCloseRevoked {
		t.Errorf("after revoke: err = %v, want close 4010", err)
	}
	// ... and the same token can no longer reconnect
	if _, status, err := dialParent(srv, resp.Token); err == nil || status != http.StatusUnauthorized {
		t.Errorf("reconnect with a revoked token: status %d err %v, want 401", status, err)
	}
	// list shows it revoked
	lw := httptest.NewRecorder()
	AdminListTokens(lw, adminReq("GET", "/api/admin/tokens?role=relay-parent", nil))
	if !strings.Contains(lw.Body.String(), `"revoked":true`) {
		t.Errorf("list = %s", lw.Body.String())
	}
}

func TestRelayParentToken_OtherKeyOrRoleRefused(t *testing.T) {
	useFreshStores(t)
	srv := wireRelayWS(t, func(*websocket.Conn) error { return nil })
	sign := func(role, secret string) string {
		raw, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"sub": "central", "role": role, "jti": "x-" + role + secret,
			"iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(),
		}).SignedString([]byte(secret))
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	for name, tok := range map[string]string{
		"relay-parent signed with another key": sign("relay-parent", "someone-elses-secret"),
		"agent role":                           sign("agent", server.JWTSecret),
		"admin role":                           sign("admin", server.JWTSecret),
	} {
		if _, status, err := dialParent(srv, tok); err == nil || status != http.StatusUnauthorized {
			t.Errorf("%s: status %d err %v, want 401", name, status, err)
		}
	}
}

func TestRelayParentToken_JWTNeverLogged(t *testing.T) {
	useFreshStores(t)
	sink := captureLog(t)
	code, resp, _ := mintParentToken(t, map[string]interface{}{"sub": "central", "expires_at": in(time.Hour), "description": "secret-desc-ok"})
	if code != http.StatusCreated {
		t.Fatalf("status %d", code)
	}
	lw := httptest.NewRecorder()
	AdminListTokens(lw, adminReq("GET", "/api/admin/tokens", nil))
	rw := httptest.NewRecorder()
	rr := adminReq("POST", "/api/admin/tokens/"+resp.ID+"/revoke", nil)
	rr.SetPathValue("id", resp.ID)
	AdminRevokeToken(rw, rr)
	// refused creations log too
	mintParentToken(t, map[string]interface{}{"sub": "central"})

	logs := sink.String()
	if logs == "" {
		t.Fatal("no logs captured: the test would be vacuous")
	}
	parts := strings.Split(resp.Token, ".")
	for _, secret := range []string{resp.Token, parts[0], parts[1], parts[2], "Bearer " + resp.Token} {
		if strings.Contains(logs, secret) {
			t.Fatalf("the relay-parent JWT (or a part of it) leaked in the logs: %q", secret)
		}
	}
	if strings.Contains(logs, server.JWTSecret+"\n") {
		t.Error("signing secret leaked")
	}
}
