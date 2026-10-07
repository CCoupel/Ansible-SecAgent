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
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

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

func TestLinkRevocation_ClosesTheTargetedLinkTwoLevelsDeepWith4001(t *testing.T) {
	t.Skip("PENDING L1d+L1e: needs link_revocations on both ends (root → relay1 → relay2). Spec (rev2 §3 test 6): chain root→relay1→relay2 up; " +
		"`tokens revoke <id of relay2's link token>` on the ROOT; relay2's link is closed with code 4001 and relay2 reports refused_permanent; " +
		"relay1's link is untouched; the JTI is in the blacklist of relay1 and relay2; a relay2 reconnecting after a cut gets the full list. " +
		"Write the body with the harness ParentToken/ROOT_LINK_KEY_FILE wiring chosen by L1e.")
}

func TestLinkFailClosed_ANonRootRelayWithoutAnchorRefusesEveryIncomingLink(t *testing.T) {
	t.Skip("PENDING L1e: needs REPEATER_ROOT_LINK_KEY_FILE (rev2 §1.5). Spec (test 10): relay1 (has a parent) started WITHOUT the anchor " +
		"refuses every /ws/relay link with a [SECURITY WARNING]; started with a key file that disagrees with its stored link_trust " +
		"(outside a valid rotation chain) it refuses to START; started with the right file it accepts a link whose token is signed by that root key.")
}

func TestLinkFailClosed_MintWithoutMasterKeyIs503(t *testing.T) {
	t.Skip("PENDING L1d: the harness always starts nodes with a master key. Spec (test 10): a root whose RSA_MASTER_KEY is absent answers 503 " +
		"to POST /api/admin/tokens {role:relay-child} and writes no key (same rule as SealPushToken). Covered at handler level by dev-relay, " +
		"or here once the harness can start a node without a master key.")
}
