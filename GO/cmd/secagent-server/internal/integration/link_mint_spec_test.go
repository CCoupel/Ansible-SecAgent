package integration

// #141 / #146 (L1d, plan rev2 §1.3, §1.8, §3 tests 7, 8, 10) — minting of the link tokens on the ROOT:
//
//	POST /api/admin/tokens {"role":"relay-child"|"relay-parent","sub":X,"aud":P}  →  201 {"token","id",…}
//
// The REST_ADMIN contract (first commit of L1d) is not written yet: the field names above are those
// of the plan and of the existing mintParentToken (`sub`); dev-relay adjusts linkMint() if the
// contract names them differently — the ASSERTIONS are the specification and must not move.
//
// Every test starts with requireLinkMint: while the server does not know the role yet (v3.0.3
// behaviour) the test is SKIPPED as "PENDING L1d", never passed artificially.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/websocket"

	"secagent-server/cmd/secagent-server/internal/state"
)

func linkMint(n *node, role, sub, aud string) (code int, token, id string, body map[string]any) {
	n.t.Helper()
	req := map[string]any{"role": role, "sub": sub, "aud": aud, "expires_at": time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)}
	code, body = n.admin("POST", "/api/admin/tokens", req)
	token, _ = body["token"].(string)
	id, _ = body["id"].(string)
	return
}

// requireLinkMint skips the test until the root mints EdDSA link tokens.
func requireLinkMint(t *testing.T, n *node) {
	t.Helper()
	code, tok, _, _ := linkMint(n, "relay-child", "probe-child", "probe-parent")
	if code != http.StatusCreated || tok == "" || !strings.HasPrefix(tok, "ey") {
		t.Skipf("PENDING L1d: the root does not mint relay-child tokens yet (HTTP %d)", code)
	}
	if h, _, err := jwt.NewParser().ParseUnverified(tok, jwt.MapClaims{}); err != nil || h.Header["alg"] != "EdDSA" {
		t.Skipf("PENDING L1d: the minted link token is not EdDSA yet (%v %v)", err, h)
	}
}

func parseLink(t *testing.T, tok string) (header map[string]any, claims jwt.MapClaims) {
	t.Helper()
	p, _, err := jwt.NewParser().ParseUnverified(tok, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("a link token must be a JWT: %v", err)
	}
	return p.Header, p.Claims.(jwt.MapClaims)
}

func TestLinkMint_RootMintsAnEdDSATokenCarryingTheSpecifiedClaims(t *testing.T) {
	parallel(t)
	root := startNode(t, nodeSpec{ID: "root"})
	requireLinkMint(t, root)

	for _, role := range []string{"relay-child", "relay-parent"} {
		code, tok, id, body := linkMint(root, role, "relay-x", "relay-p")
		if code != http.StatusCreated || tok == "" || id == "" {
			t.Fatalf("%s: %d %v", role, code, body)
		}
		h, c := parseLink(t, tok)
		if h["alg"] != "EdDSA" {
			t.Errorf("%s: alg %v, EdDSA is the only algorithm", role, h["alg"])
		}
		if kid, _ := h["kid"].(string); kid == "" {
			t.Errorf("%s: kid (fingerprint of the root key) is mandatory", role)
		}
		want := map[string]any{"iss": "root", "sub": "relay-x", "aud": "relay-p", "role": role}
		for k, v := range want {
			if c[k] != v {
				t.Errorf("%s: claim %s = %v, want %v", role, k, c[k], v)
			}
		}
		for _, k := range []string{"jti", "iat", "exp"} {
			if c[k] == nil {
				t.Errorf("%s: claim %s is mandatory", role, k)
			}
		}
	}

	// the registry lists metadata only: never the token, its hash, nor key material
	_, raw := root.callOn(root.adminURL(), "GET", "/api/admin/tokens", root.adminTok, nil)
	list := string(raw)
	if strings.Contains(list, "eyJ") {
		t.Error("the token list must never contain a token")
	}
	for _, forbidden := range []string{"PRIVATE KEY", "link_signing_key", "token_hash"} {
		if strings.Contains(list, forbidden) {
			t.Errorf("the token list leaks %q", forbidden)
		}
	}
}

func TestLinkMint_MalformedRequestsAreRefused(t *testing.T) {
	parallel(t)
	root := startNode(t, nodeSpec{ID: "root"})
	requireLinkMint(t, root)
	for name, req := range map[string]map[string]any{
		"legacy role relay is no longer mintable": {"role": "relay", "sub": "x", "aud": "p"},
		"missing sub":      {"role": "relay-child", "aud": "p"},
		"missing aud":      {"role": "relay-child", "sub": "x"},
		"sub with a space": {"role": "relay-child", "sub": "bad id", "aud": "p"},
		"aud with a slash": {"role": "relay-parent", "sub": "x", "aud": "../p"},
		"sub equals aud (a relay linking itself)": {"role": "relay-child", "sub": "x", "aud": "x"},
	} {
		if code, _ := root.admin("POST", "/api/admin/tokens", req); code != http.StatusBadRequest {
			t.Errorf("%s: %d, want 400", name, code)
		}
	}
}

// test 7: only the root signs. A relay that has a parent never mints a link token.
func TestLinkMint_ANonRootRelayRefusesWith409NotRoot(t *testing.T) {
	parallel(t)
	root := startNode(t, nodeSpec{ID: "root"})
	requireLinkMint(t, root)
	child := startNode(t, nodeSpec{ID: "relay1", ParentURL: root.wssURL(), ParentToken: root.registerChild("relay1")})
	for _, role := range []string{"relay-child", "relay-parent"} {
		code, tok, _, body := linkMint(child, role, "relay-x", "relay-p")
		if code != http.StatusConflict || body["error"] != "not_root" || tok != "" {
			t.Errorf("%s on a non-root relay: %d %v, want 409 not_root and no token", role, code, body)
		}
	}
	// and it did not generate a signing key either
	if v := child.statePayload()["server_config"]; strings.Contains(string(v), state.ConfigLinkSigningKeyCurrent) {
		t.Error("a non-root relay must never hold a link signing key")
	}
}

// §1.3: the private key lives in server_config, encrypted under the master key, and nowhere else.
func TestLinkMint_ThePrivateKeyIsEncryptedAtRestAndNeverLogged(t *testing.T) {
	parallel(t)
	root := startNode(t, nodeSpec{ID: "root"})
	requireLinkMint(t, root)
	_, tok, _, _ := linkMint(root, "relay-child", "relay-x", "relay-p")

	raw, err := os.ReadFile(filepath.Join(root.stateDir, state.StateFile))
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]string
	if err := json.Unmarshal(root.statePayload()["server_config"], &cfg); err != nil {
		t.Fatal(err)
	}
	stored := cfg[state.ConfigLinkSigningKeyCurrent]
	if stored == "" || !strings.HasPrefix(stored, state.EncPrefix) {
		t.Fatalf("link_signing_key_current = %q: must exist, enc:-prefixed", stored)
	}
	if strings.Contains(string(raw), "PRIVATE KEY") {
		t.Error("the state file holds a clear private key")
	}
	logs := root.logs.String()
	if strings.Contains(logs, stored) || strings.Contains(logs, "PRIVATE KEY") || strings.Contains(logs, tok) {
		t.Error("the node logged key material or a link token")
	}
	assertNoSecrets(t, logs, tok, root.adminTok, root.jwtSecret)

	// T10c: nor in `state verify`, nor in any API answer
	rep, err := state.VerifyFile(filepath.Join(root.stateDir, state.StateFile), state.VerifyOptions{MasterKey: "integration-master-key-root"})
	if err != nil {
		t.Fatalf("state verify: %v", err)
	}
	if !rep.LinkSigningKeyCurrent {
		t.Error("state verify must say that a signing key exists (a boolean, never the key)")
	}
	reportText, _ := json.Marshal(rep)
	for _, path := range []string{"/api/admin/tokens", "/api/admin/relays", "/api/admin/status", "/api/admin/security/keys/status", "/api/admin/security/tokens", "/api/admin/stats"} {
		_, body := root.callOn(root.adminURL(), "GET", path, root.adminTok, nil)
		for _, leak := range []string{stored, "link_signing_key_current\":\"", "PRIVATE KEY"} {
			if strings.Contains(string(body), leak) {
				t.Errorf("%s leaks key material (%q)", path, leak)
			}
		}
	}
	for _, leak := range []string{stored, "PRIVATE KEY"} {
		if strings.Contains(string(reportText), leak) || strings.Contains(fmt.Sprintf("%+v", *rep), leak) {
			t.Errorf("state verify leaks key material (%q)", leak)
		}
	}
}

// test 8: active/passive. After a switchover the new master signs with the SAME key (same kid):
// the tokens already distributed keep working, nothing has to be redistributed.
func TestLinkMint_SwitchoverKeepsTheSameKey(t *testing.T) {
	parallel(t)
	a := startNode(t, nodeSpec{ID: "root"})
	requireLinkMint(t, a)
	_, tok1, _, _ := linkMint(a, "relay-child", "relay-x", "relay-p")
	h1, _ := parseLink(t, tok1)

	b := a.sibling()
	b.launchSecondary(nil)
	t.Cleanup(b.stop)
	a.stop() // clean stop: the lock is released, the secondary takes over
	if !b.awaitPromotion(30 * time.Second) {
		t.Fatalf("the secondary did not take over:\n%s", b.logs.String())
	}
	code, tok2, _, body := linkMint(b, "relay-child", "relay-y", "relay-p")
	if code != http.StatusCreated {
		t.Fatalf("mint on the new master: %d %v", code, body)
	}
	h2, _ := parseLink(t, tok2)
	if h1["kid"] != h2["kid"] || h1["kid"] == nil {
		t.Errorf("kid before/after the switchover: %v / %v — the key must be the same", h1["kid"], h2["kid"])
	}
}

// ── pending L1d / L1e: they need both ends of the link ───────────────────────

// linkTokenIDBySub returns the registry id and JTI of the link token minted for sub on the root.
func linkTokenIDBySub(t *testing.T, root *node, sub string) (id, jti string) {
	t.Helper()
	_, raw := root.callOn(root.adminURL(), "GET", "/api/admin/tokens?role=relay-child", root.adminTok, nil)
	var list []map[string]any
	if err := json.Unmarshal(raw, &list); err != nil {
		t.Fatalf("token list: %v %s", err, raw)
	}
	for _, e := range list {
		if e["sub"] == sub {
			return e["id"].(string), e["jti"].(string)
		}
	}
	t.Fatalf("no link token for %s in %s", sub, raw)
	return
}

func blacklisted(n *node, jti string) bool {
	_, ok := n.stateSection("blacklist")[jti]
	return ok
}

func TestLinkRevocation_ClosesTheTargetedLinkTwoLevelsDeepWith4010(t *testing.T) {
	parallel(t)
	root, relay1, relay2 := threeLevels(t)
	id, jti := linkTokenIDBySub(t, root, "relay2")

	if code, m := root.admin("POST", "/api/admin/tokens/"+id+"/revoke", map[string]any{}); code != http.StatusOK || m["seq"] != float64(1) {
		t.Fatalf("revoke on the root: %d %v", code, m)
	}
	// relay2 (two levels below the root) is cut with the permanent code and stops for good
	waitFor(t, "relay2 refused_permanent", func() bool { return relay2.upstreamState() == "refused_permanent" })
	if got := relay1.upstreamState(); got != "connected" {
		t.Errorf("relay1's own link must be untouched, got %q", got)
	}
	// the JTI is in the blacklist of every level
	waitFor(t, "the JTI is blacklisted on the root, relay1 and relay2", func() bool {
		ok := blacklisted(root, jti) && blacklisted(relay1, jti) && blacklisted(relay2, jti)
		if !ok {
			t.Logf("blacklisted root=%v relay1=%v relay2=%v", blacklisted(root, jti), blacklisted(relay1, jti), blacklisted(relay2, jti))
		}
		return ok
	})
	if !relay2.logs.has("revoked") {
		t.Errorf("relay2 must log why it stopped:\n%s", relay2.logs.String())
	}
	// a relay that joins relay1 AFTER the revocation learns it (full list when its link is established)
	relay3 := startNode(t, nodeSpec{ID: "relay3", ParentURL: relay1.wssURL(), ParentToken: relay1.registerChild("relay3")})
	waitFor(t, "relay3 linked", func() bool { return relay3.upstreamState() == "connected" })
	waitFor(t, "relay3 received the revocation list", func() bool { return blacklisted(relay3, jti) })
}

// dialRelayLink opens /ws/relay on parent with a bearer token (the upgrade may succeed, then the node
// closes with a code).
func dialRelayLink(parent *node, token string) (*websocket.Conn, *http.Response, error) {
	h := http.Header{}
	h.Set("Authorization", "Bearer "+token)
	d := websocket.Dialer{TLSClientConfig: tlsClientConfig(), HandshakeTimeout: 5 * time.Second}
	return d.Dial(parent.wssURL()+"/ws/relay", h)
}

func closeCodeOf(t *testing.T, c *websocket.Conn) int {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
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

func TestLinkFailClosed_ANonRootRelayWithoutAnchorRefusesEveryIncomingLink(t *testing.T) {
	parallel(t)
	root := startNode(t, nodeSpec{ID: "root"})

	t.Run("no anchor: every incoming link is closed 4010", func(t *testing.T) {
		relay1 := startNode(t, nodeSpec{ID: "relay1", ParentURL: root.wssURL(), ParentToken: "not-a-link-token"}) // has a parent, no anchor
		_, tk := root.admin("POST", "/api/admin/tokens", map[string]any{"role": "relay-child", "sub": "hostile", "aud": "relay1"})
		c, _, err := dialRelayLink(relay1, tk["token"].(string))
		if err != nil {
			t.Fatalf("the upgrade then the permanent close is expected: %v", err)
		}
		defer func() { _ = c.Close() }()
		if got := closeCodeOf(t, c); got != 4010 {
			t.Errorf("close code = %d, want 4010 (link_trust_missing)", got)
		}
		waitFor(t, "a [SECURITY WARNING] names the missing anchor", func() bool {
			return relay1.logs.has("SECURITY WARNING") && relay1.logs.has("trust anchor")
		})
	})

	t.Run("the right anchor: a link signed by that root is accepted", func(t *testing.T) {
		relay1 := startNode(t, nodeSpec{ID: "relay1b", Root: root})
		_ = newFakeChild(t, relay1, "child-ok") // registerChild mints on the root, aud = relay1b: handshake must succeed
	})

	t.Run("a pinned key that disagrees with the persisted link_trust: the node refuses to start", func(t *testing.T) {
		otherRoot := startNode(t, nodeSpec{ID: "other-root"})
		relay1 := startNode(t, nodeSpec{ID: "relay1c", Root: root})
		relay1.stop()
		relay1.anchorTo(otherRoot) // another key and another root id, outside any rotation chain
		_, _ = relay1.startProcess(nil)
		code, exited := relay1.waitExit(20 * time.Second)
		if !exited || code == 0 {
			t.Fatalf("the node must refuse to start (exited=%v code=%d); logs:\n%s", exited, code, relay1.logs.String())
		}
		if !relay1.logs.has("trust") {
			t.Errorf("the refusal must name the trust anchor:\n%s", relay1.logs.String())
		}
	})
}

func TestLinkFailClosed_MintWithoutMasterKeyIs503(t *testing.T) {
	parallel(t)
	n := startNode(t, nodeSpec{ID: "root", NoMasterKey: true})
	// the node really runs without a master key (otherwise this test proves nothing)
	if code, _ := n.admin("GET", "/api/admin/status", nil); code != http.StatusOK {
		t.Fatalf("a node without master key on a clear test state must serve: %d", code)
	}
	for _, role := range []string{"relay-child", "relay-parent"} {
		code, tok, _, body := linkMint(n, role, "relay-x", "relay-p")
		if code == http.StatusBadRequest && body["error"] != nil && strings.Contains(fmt.Sprint(body["error"]), "role") {
			t.Skipf("PENDING L1d: the root does not mint %s yet (HTTP %d)", role, code)
		}
		if code != http.StatusServiceUnavailable || tok != "" {
			t.Errorf("%s without RSA_MASTER_KEY: %d %v, want 503 and no token", role, code, body)
		}
	}
	// and nothing was generated: no signing key in the state
	if v := n.statePayload()["server_config"]; strings.Contains(string(v), state.ConfigLinkSigningKeyCurrent) {
		t.Error("a refused mint must not generate a signing key")
	}
	n.logs.expectLog(t, "RSA_MASTER_KEY", "the refusal must name the missing master key in the log")
}
