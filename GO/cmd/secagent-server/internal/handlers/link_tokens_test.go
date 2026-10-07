package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/websocket"

	"secagent-server/cmd/secagent-server/internal/auth"
	"secagent-server/cmd/secagent-server/internal/link"
	"secagent-server/cmd/secagent-server/internal/ws"
)

// ── helpers ──────────────────────────────────────────────────────────────────

const testRootID = "central"

// useLinkRoot installs a link authority acting as the ROOT relay "central" (master key set) and
// makes /ws/relay verify against it. Returns the manager.
func useLinkRoot(t *testing.T) *link.Manager {
	t.Helper()
	t.Setenv("RSA_MASTER_KEY", "handlers-link-test-master-key")
	s := adminStore
	m := &link.Manager{
		Store:      s,
		MasterKey:  func() (string, bool) { return "handlers-link-test-master-key", true },
		LocalID:    func() string { return testRootID },
		IsRoot:     func() bool { return true },
		Broadcast:  ws.BroadcastLinkFrame,
		CloseByJTI: ws.CloseLinksByJTI,
	}
	SetLinkManager(m)
	ws.SetLinkTrustFunc(m.Trust)
	ws.SetRelayLocalIDFunc(func() string { return testRootID })
	t.Cleanup(func() { SetLinkManager(nil); ws.SetLinkTrustFunc(nil); ws.SetRelayLocalIDFunc(nil) })
	return m
}

func mintLink(t *testing.T, body map[string]interface{}) (int, TokenCreateResponse, string) {
	t.Helper()
	w := httptest.NewRecorder()
	AdminCreateToken(w, adminReq("POST", "/api/admin/tokens", body))
	var resp TokenCreateResponse
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	return w.Code, resp, w.Body.String()
}

func in(d time.Duration) string { return time.Now().UTC().Add(d).Format(time.RFC3339) }

// lockedBuffer is a log sink safe for concurrent writers (background handler goroutines log too).
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// captureLog redirects the standard logger and returns the sink.
func captureLog(t *testing.T) *lockedBuffer {
	t.Helper()
	buf := &lockedBuffer{}
	prev := log.Writer()
	log.SetOutput(buf)
	t.Cleanup(func() { log.SetOutput(prev) })
	return buf
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

// ── creation ─────────────────────────────────────────────────────────────────

func TestLinkToken_CreateShowsJWTOnceAndPersistsMetadataOnly(t *testing.T) {
	s := useFreshStores(t)
	useLinkRoot(t)
	for _, role := range []string{"relay-child", "relay-parent"} {
		code, resp, raw := mintLink(t, map[string]interface{}{"role": role, "sub": "relay-x", "aud": "relay-y", "expires_at": in(90 * 24 * time.Hour), "description": "uplink"})
		if code != http.StatusCreated {
			t.Fatalf("%s: status %d %s", role, code, raw)
		}
		if resp.Token == "" || resp.Role != role || resp.Sub != "relay-x" || resp.Aud != "relay-y" || resp.ID == "" || resp.JTI == "" || resp.KID == "" {
			t.Fatalf("response = %+v", resp)
		}
		tok, _, err := jwt.NewParser().ParseUnverified(resp.Token, jwt.MapClaims{})
		if err != nil {
			t.Fatal(err)
		}
		c := tok.Claims.(jwt.MapClaims)
		if tok.Header["alg"] != "EdDSA" || tok.Header["kid"] != resp.KID || c["iss"] != testRootID || c["sub"] != "relay-x" || c["aud"] != "relay-y" || c["role"] != role || c["jti"] != resp.JTI {
			t.Errorf("%s: header %v claims %v", role, tok.Header, c)
		}
		rec, ok := s.GetLinkToken(resp.ID)
		if !ok || rec.JTI != resp.JTI || rec.Aud != "relay-y" {
			t.Fatalf("registry = %+v %v", rec, ok)
		}
	}
	// the list carries metadata only, never the token
	w := httptest.NewRecorder()
	AdminListTokens(w, adminReq("GET", "/api/admin/tokens?role=relay-child", nil))
	var list []LinkTokenSummary
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &list) != nil || len(list) != 1 || list[0].Role != "relay-child" || list[0].Revoked {
		t.Fatalf("list = %d %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "eyJ") || strings.Contains(w.Body.String(), "token_hash") {
		t.Error("the list leaks a token or a hash")
	}
	// default lifetime when expires_at is omitted: 720 h
	_, resp, _ := mintLink(t, map[string]interface{}{"role": "relay-child", "sub": "a", "aud": "b"})
	rec, _ := s.GetLinkToken(resp.ID)
	if d := time.Until(rec.ExpiresAt); d < 719*time.Hour || d > 721*time.Hour {
		t.Errorf("default ttl = %v, want 720h", d)
	}
}

func TestLinkToken_CreateValidation(t *testing.T) {
	useFreshStores(t)
	useLinkRoot(t)
	tests := []struct {
		name string
		body map[string]interface{}
		want string
	}{
		{"legacy role", map[string]interface{}{"role": "relay", "sub": "a", "aud": "b"}, "invalid_role"},
		{"missing sub", map[string]interface{}{"role": "relay-child", "aud": "b"}, "missing_sub"},
		{"missing aud", map[string]interface{}{"role": "relay-child", "sub": "a"}, "missing_aud"},
		{"bad sub", map[string]interface{}{"role": "relay-child", "sub": "a b/c", "aud": "b"}, "invalid_sub"},
		{"bad aud", map[string]interface{}{"role": "relay-parent", "sub": "a", "aud": "../b"}, "invalid_aud"},
		{"sub equals aud", map[string]interface{}{"role": "relay-child", "sub": "a", "aud": "a"}, "sub_equals_aud"},
		{"expiry in the past", map[string]interface{}{"role": "relay-child", "sub": "a", "aud": "b", "expires_at": in(-time.Hour)}, "expires_in_the_past"},
		{"beyond the 365d cap", map[string]interface{}{"role": "relay-child", "sub": "a", "aud": "b", "expires_at": in(366 * 24 * time.Hour)}, "expires_exceeds_maximum_365d"},
		{"malformed expiry", map[string]interface{}{"role": "relay-child", "sub": "a", "aud": "b", "expires_at": "tomorrow"}, "invalid_expires_at"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, resp, raw := mintLink(t, tt.body)
			if code != http.StatusBadRequest || !strings.Contains(raw, tt.want) {
				t.Errorf("status %d body %s, want 400 %s", code, raw, tt.want)
			}
			if resp.Token != "" {
				t.Error("no token may be issued on refusal")
			}
		})
	}
}

func TestLinkToken_NotRootIs409_NoMasterKeyIs503(t *testing.T) {
	s := useFreshStores(t)
	m := useLinkRoot(t)
	// a node with a parent never mints and never creates a key
	m.IsRoot = func() bool { return false }
	code, resp, raw := mintLink(t, map[string]interface{}{"role": "relay-child", "sub": "a", "aud": "b"})
	if code != http.StatusConflict || !strings.Contains(raw, "not_root") || resp.Token != "" {
		t.Errorf("non-root: %d %s, want 409 not_root", code, raw)
	}
	if cur, _ := s.LinkSigningKeys(); cur != "" {
		t.Error("a non-root node must not hold a link signing key")
	}
	// the root without RSA_MASTER_KEY: 503 and nothing stored
	m.IsRoot = func() bool { return true }
	m.MasterKey = func() (string, bool) { return "", false }
	code, resp, raw = mintLink(t, map[string]interface{}{"role": "relay-child", "sub": "a", "aud": "b"})
	if code != http.StatusServiceUnavailable || !strings.Contains(raw, "master_key_required") || resp.Token != "" {
		t.Errorf("no master key: %d %s, want 503 master_key_required", code, raw)
	}
	if cur, _ := s.LinkSigningKeys(); cur != "" {
		t.Error("no key may be generated without a master key")
	}
}

func TestLinkToken_AdminOnly(t *testing.T) {
	useFreshStores(t)
	useLinkRoot(t)
	body, _ := json.Marshal(map[string]interface{}{"role": "relay-child", "sub": "a", "aud": "b"})
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

// wireRelayWS makes /ws/relay verify like production (link trust, blacklist) and accept a parent link.
func wireRelayWS(t *testing.T, serve func(*websocket.Conn) error) *httptest.Server {
	t.Helper()
	useLinkRoot(t)
	// this node is the CHILD "dmz1": it verifies with the root key (iss "central") and aud = "dmz1"
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
		ws.SetRelayJTIBlacklistFunc(nil)
		ws.SetRelayParentLinkFunc(nil)
	})
	return srv
}

func TestLinkToken_EndToEndPushLinkAndRevocation(t *testing.T) {
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
	// the root mints the relay-parent token the parent "central" presents to its child "dmz1"
	code, resp, raw := mintLink(t, map[string]interface{}{"role": "relay-parent", "sub": "central", "aud": "dmz1", "expires_at": in(24 * time.Hour)})
	if code != http.StatusCreated {
		t.Fatalf("mint: %d %s", code, raw)
	}

	// 1. the parent establishes the link
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

	// 2. revoke on the root: registry + blacklist + seq, and the live link is cut with 4010
	w := httptest.NewRecorder()
	req := adminReq("POST", "/api/admin/tokens/"+resp.ID+"/revoke", nil)
	req.SetPathValue("id", resp.ID)
	AdminRevokeToken(w, req)
	var rv struct {
		Revoked     bool   `json:"revoked"`
		JTI         string `json:"jti"`
		Seq         uint64 `json:"seq"`
		LinksClosed int    `json:"links_closed"`
	}
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &rv) != nil || !rv.Revoked || rv.JTI != resp.JTI || rv.Seq != 1 || rv.LinksClosed != 1 {
		t.Fatalf("revoke: %d %s", w.Code, w.Body.String())
	}
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	var m map[string]any
	err = c.ReadJSON(&m)
	if ce, ok := err.(*websocket.CloseError); !ok || ce.Code != ws.WSRelayCloseRevoked {
		t.Errorf("after revoke: err = %v, want close 4010", err)
	}
	if bl, _ := adminStore.IsJTIBlacklisted(context.Background(), resp.JTI); !bl {
		t.Error("the JTI must be blacklisted in the same mutation")
	}
	// the same token can no longer reconnect
	if _, status, err := dialParent(srv, resp.Token); err == nil || status != http.StatusUnauthorized {
		t.Errorf("reconnect with a revoked token: status %d err %v, want 401", status, err)
	}
	// list shows it revoked; a second revoke is idempotent (no second seq)
	lw := httptest.NewRecorder()
	AdminListTokens(lw, adminReq("GET", "/api/admin/tokens?role=relay-parent", nil))
	if !strings.Contains(lw.Body.String(), `"revoked":true`) {
		t.Errorf("list = %s", lw.Body.String())
	}
	w2 := httptest.NewRecorder()
	AdminRevokeToken(w2, req)
	if !strings.Contains(w2.Body.String(), `"seq":1`) {
		t.Errorf("second revoke must not increment seq: %s", w2.Body.String())
	}
}

func TestLinkToken_OtherKeyRoleOrAudienceRefused(t *testing.T) {
	useFreshStores(t)
	srv := wireRelayWS(t, func(*websocket.Conn) error { return nil })
	hs := func(role, secret string) string {
		raw, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"sub": "central", "role": role, "jti": "x-" + role + secret,
			"iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(),
		}).SignedString([]byte(secret))
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	_, other, _ := mintLink(t, map[string]interface{}{"role": "relay-parent", "sub": "central", "aud": "somebody-else"})
	for name, tok := range map[string]string{
		"HS256 relay-parent (v3.0.3 format)": hs("relay-parent", server.JWTSecret),
		"HS256 legacy relay role":            hs("relay", server.JWTSecret),
		"agent role":                         hs("agent", server.JWTSecret),
		"link token for another verifier":    other.Token,
	} {
		if _, status, err := dialParent(srv, tok); err == nil || status != http.StatusUnauthorized {
			t.Errorf("%s: status %d err %v, want 401", name, status, err)
		}
	}
}

func TestLinkToken_JWTNeverLogged(t *testing.T) {
	useFreshStores(t)
	useLinkRoot(t)
	sink := captureLog(t)
	code, resp, _ := mintLink(t, map[string]interface{}{"role": "relay-parent", "sub": "central", "aud": "dmz1", "expires_at": in(time.Hour), "description": "d"})
	if code != http.StatusCreated {
		t.Fatalf("status %d", code)
	}
	lw := httptest.NewRecorder()
	AdminListTokens(lw, adminReq("GET", "/api/admin/tokens", nil))
	rw := httptest.NewRecorder()
	rr := adminReq("POST", "/api/admin/tokens/"+resp.ID+"/revoke", nil)
	rr.SetPathValue("id", resp.ID)
	AdminRevokeToken(rw, rr)
	mintLink(t, map[string]interface{}{"role": "relay-parent", "sub": "central"}) // a refusal logs too

	logs := sink.String()
	if logs == "" {
		t.Fatal("no logs captured: the test would be vacuous")
	}
	parts := strings.Split(resp.Token, ".")
	for _, secret := range []string{resp.Token, parts[0], parts[1], parts[2], "Bearer " + resp.Token, "PRIVATE KEY"} {
		if strings.Contains(logs, secret) {
			t.Fatalf("the link token (or key material) leaked in the logs: %q", secret)
		}
	}
	cur, _ := adminStore.LinkSigningKeys()
	if cur != "" && strings.Contains(logs, cur) {
		t.Error("the sealed signing key leaked in the logs")
	}
}

// ── key operations (pubkey, rotation, retire) ────────────────────────────────

func TestLinkKeys_PubkeyRotateRetire(t *testing.T) {
	useFreshStores(t)
	useLinkRoot(t)
	call := func(h http.HandlerFunc, method, path string, body interface{}) (int, map[string]interface{}) {
		w := httptest.NewRecorder()
		h(w, adminReq(method, path, body))
		var out map[string]interface{}
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}
	code, pk := call(AdminLinkPubkey, "GET", "/api/admin/link/pubkey", nil)
	pem, _ := pk["current_pub_pem"].(string)
	if code != http.StatusOK || !strings.HasPrefix(pem, "-----BEGIN PUBLIC KEY-----") || pk["root_id"] != testRootID || strings.Contains(pem, "PRIVATE") {
		t.Fatalf("pubkey: %d %v", code, pk)
	}
	kid1 := pk["current_kid"]
	_, tok1, _ := mintLink(t, map[string]interface{}{"role": "relay-child", "sub": "a", "aud": "b"})

	code, rot := call(AdminLinkRotate, "POST", "/api/admin/link/keys/rotate", map[string]string{})
	if code != http.StatusOK || rot["previous_kid"] != kid1 || rot["current_kid"] == kid1 || rot["seq"] != float64(1) {
		t.Fatalf("rotate: %d %v", code, rot)
	}
	if code, e := call(AdminLinkRotate, "POST", "/api/admin/link/keys/rotate", map[string]string{}); code != http.StatusConflict || e["error"] != "previous_key_not_retired" {
		t.Errorf("second rotation: %d %v, want 409 previous_key_not_retired", code, e)
	}
	// the token minted before the rotation still verifies during the double acceptation
	tr, root, err := linkManager().Trust()
	if err != nil {
		t.Fatal(err)
	}
	want := auth.LinkWant{LocalID: "b", RootID: root, Role: auth.RoleRelayChild}
	if _, err := auth.VerifyLinkToken(tr, tok1.Token, want, time.Now()); err != nil {
		t.Fatalf("token signed by previous during the window: %v", err)
	}
	// a relay known below has not confirmed: retire refused without force
	ws.RecordLinkState("child-1", 0, "")
	m := linkManager()
	m.Known = func() []string { return []string{"child-1"} }
	if code, e := call(AdminLinkRetire, "POST", "/api/admin/link/keys/retire-previous", map[string]bool{}); code != http.StatusConflict || e["error"] != "rotation_unconfirmed" {
		t.Fatalf("retire unconfirmed: %d %v", code, e)
	}
	// confirmed: accepted
	m.States = func() map[string]link.ConfirmedState {
		return map[string]link.ConfirmedState{"child-1": {Seq: 1, KID: rot["current_kid"].(string)}}
	}
	if code, e := call(AdminLinkRetire, "POST", "/api/admin/link/keys/retire-previous", map[string]bool{}); code != http.StatusOK || e["seq"] != float64(2) {
		t.Fatalf("retire: %d %v", code, e)
	}
	tr, _, _ = m.Trust()
	if _, err := auth.VerifyLinkToken(tr, tok1.Token, want, time.Now()); err == nil {
		t.Error("a token signed by the retired key must be refused (mutation: previous always accepted)")
	}
	if code, e := call(AdminLinkRetire, "POST", "/api/admin/link/keys/retire-previous", map[string]bool{}); code != http.StatusConflict || e["error"] != "no_previous_key" {
		t.Errorf("retire twice: %d %v", code, e)
	}
}
