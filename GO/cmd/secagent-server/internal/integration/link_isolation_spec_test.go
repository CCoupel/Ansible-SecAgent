package integration

// #146 (L1, plan rev2 §3 test 11) — a LINK token (the credential of a relay: `relay` today,
// `relay-child` / `relay-parent` once L1d lands) opens NOTHING but the relay link itself: not the plugin
// API (exec / upload / fetch / inventory, port 7770 and the admin port 7771), not the admin API, not
// /ws/agent. One test per endpoint and per role, on a REAL node.
//
// linkTokens is the only function that knows how a link token is obtained. It uses the API of
// v3.0.3 today (register a pull child → role `relay`; mint a relay-parent token). L1d changes both
// (tokens come from the root, `relay-child` / `relay-parent`): dev-relay updates ONLY linkTokens, the
// matrix below must not change (it is the specification).

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// linkTokens returns one valid token per link role, named by role.
func linkTokens(t *testing.T, n *node) map[string]string {
	t.Helper()
	return map[string]string{
		"relay-child":  n.registerChild("isolation-child"),
		"relay-parent": firstOf(n.mintParentToken("isolation-parent")),
	}
}

func firstOf(token, _ string) string { return token }

type isolationEndpoint struct {
	name   string
	listen string // "api" (7770) or "admin" (7771)
	method string
	path   string
	body   any
}

// isolationMatrix is every route of the plugin API and of the admin API, with harmless dummy
// parameters: a link token must be refused on ALL of them (a route added later must be added here).
func isolationMatrix() []isolationEndpoint {
	exec := map[string]any{"command": "id"}
	m := []isolationEndpoint{
		{"exec", "api", "POST", "/api/exec/some-host", exec},
		{"upload", "api", "POST", "/api/upload/some-host", map[string]any{"dest": "/tmp/x", "data": "eA=="}},
		{"fetch", "api", "POST", "/api/fetch/some-host", map[string]any{"src": "/etc/hostname"}},
		{"inventory (7770)", "api", "GET", "/api/inventory", nil},
		{"authorize (7770)", "api", "POST", "/api/admin/authorize", map[string]any{"hostname": "evil", "public_key_pem": "x"}},
		{"inventory (7771)", "admin", "GET", "/api/inventory", nil},
		{"authorize (7771)", "admin", "POST", "/api/admin/authorize", map[string]any{"hostname": "evil", "public_key_pem": "x"}},
	}
	for _, r := range [][3]string{
		{"GET", "/api/admin/minions", ""}, {"GET", "/api/admin/minions/h", ""},
		{"POST", "/api/admin/minions/h/suspend", ""}, {"POST", "/api/admin/minions/h/resume", ""},
		{"POST", "/api/admin/minions/h/set-state", `{"state":"x"}`},
		{"GET", "/api/admin/minions/h/vars", ""}, {"POST", "/api/admin/minions/h/vars", `{"vars":{}}`},
		{"DELETE", "/api/admin/minions/h/vars/k", ""}, {"DELETE", "/api/admin/minions/h", ""},
		{"POST", "/api/admin/revoke/h", ""}, {"POST", "/api/admin/keys/rotate", ""},
		{"GET", "/api/admin/security/keys/status", ""}, {"GET", "/api/admin/security/tokens", ""},
		{"GET", "/api/admin/security/blacklist", ""}, {"POST", "/api/admin/security/blacklist/purge", ""},
		{"POST", "/api/admin/tokens", `{"role":"plugin","description":"stolen"}`},
		{"POST", "/api/admin/tokens", `{"role":"enrollment","description":"stolen"}`},
		{"GET", "/api/admin/tokens", ""}, {"POST", "/api/admin/tokens/x/revoke", ""},
		{"DELETE", "/api/admin/tokens/x", ""}, {"POST", "/api/admin/tokens/purge", ""},
		{"GET", "/api/admin/status", ""}, {"GET", "/api/admin/stats", ""}, {"GET", "/api/admin/hooks/log", ""},
		{"POST", "/api/admin/relays", `{"relay_id":"evil-relay","mode":"pull"}`},
		{"GET", "/api/admin/relays", ""}, {"GET", "/api/admin/relays/status", ""},
		{"DELETE", "/api/admin/relays/x", ""}, {"POST", "/api/admin/relays/x/revoke", ""},
	} {
		var body any
		if r[2] != "" {
			body = rawJSON(r[2])
		}
		m = append(m, isolationEndpoint{r[0] + " " + r[1], "admin", r[0], r[1], body})
	}
	return m
}

type rawJSON string

func (r rawJSON) MarshalJSON() ([]byte, error) { return []byte(r), nil }

// dialAgentWS opens /ws/agent on base (wss://…) with the token: the HTTP status, 101 on success.
func dialAgentWS(base, token string) int {
	h := http.Header{}
	h.Set("Authorization", "Bearer "+token)
	d := websocket.Dialer{TLSClientConfig: tlsClientConfig(), HandshakeTimeout: 5 * time.Second}
	conn, resp, err := d.Dial(base+"/ws/agent", h)
	if err != nil {
		if resp != nil {
			return resp.StatusCode
		}
		return 0
	}
	_ = conn.Close()
	return http.StatusSwitchingProtocols
}

func TestLinkIsolation_ALinkTokenOpensNoEndpointButTheLink(t *testing.T) {
	parallel(t)
	root := startNode(t, nodeSpec{ID: "root"})
	tokens := linkTokens(t, root)
	// witnesses that the state is not touched by the barrage
	_, tokBefore := root.admin("GET", "/api/admin/tokens", nil)
	_, relBefore := root.admin("GET", "/api/admin/relays", nil)

	for role, tok := range tokens {
		for _, ep := range isolationMatrix() {
			t.Run(fmt.Sprintf("%s/%s", role, ep.name), func(t *testing.T) {
				base := root.adminURL()
				if ep.listen == "api" {
					base = root.apiURL()
				}
				code, body := root.callOn(base, ep.method, ep.path, tok, ep.body)
				if code != http.StatusUnauthorized && code != http.StatusForbidden {
					t.Errorf("a %s token on %s %s (%s): %d %s, want 401/403", role, ep.method, ep.path, ep.listen, code, strings.TrimSpace(string(body)))
				}
			})
		}
		t.Run(role+"/ws-agent on the WS listener", func(t *testing.T) {
			if c := dialAgentWS(root.wssURL(), tok); c != http.StatusUnauthorized && c != http.StatusForbidden {
				t.Errorf("a %s token must not open /ws/agent: %d", role, c)
			}
		})
		t.Run(role+"/ws-agent on the API listener", func(t *testing.T) {
			if c := dialAgentWS("wss://"+root.ready.API, tok); c != http.StatusUnauthorized && c != http.StatusForbidden {
				t.Errorf("a %s token must not open /ws/agent on 7770: %d", role, c)
			}
		})
	}

	_, tokAfter := root.admin("GET", "/api/admin/tokens", nil)
	_, relAfter := root.admin("GET", "/api/admin/relays", nil)
	if fmt.Sprint(tokBefore) != fmt.Sprint(tokAfter) {
		t.Errorf("the barrage created or removed tokens:\n before %v\n after  %v", tokBefore, tokAfter)
	}
	if fmt.Sprint(relBefore) != fmt.Sprint(relAfter) {
		t.Errorf("the barrage created or removed relays:\n before %v\n after  %v", relBefore, relAfter)
	}
}

// The other direction: neither an agent token nor a plugin token nor the admin token opens a LINK
// (/ws/relay). Roles are not interchangeable in any direction.
func TestLinkIsolation_NoOtherCredentialOpensTheRelayLink(t *testing.T) {
	parallel(t)
	root := startNode(t, nodeSpec{ID: "root"})
	agentTok := root.enrollAgent("isolation-agent")
	for name, tok := range map[string]string{
		"agent token":  agentTok,
		"plugin token": root.pluginToken(),
		"admin token":  root.adminTok,
	} {
		h := http.Header{}
		h.Set("Authorization", "Bearer "+tok)
		d := websocket.Dialer{TLSClientConfig: tlsClientConfig(), HandshakeTimeout: 5 * time.Second}
		conn, resp, err := d.Dial(root.wssURL()+"/ws/relay", h)
		if err == nil {
			_ = conn.Close()
			t.Errorf("%s opened /ws/relay", name)
			continue
		}
		if resp == nil || (resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusForbidden) {
			t.Errorf("%s on /ws/relay: %v (resp %v), want 401/403", name, err, resp)
		}
	}
}
