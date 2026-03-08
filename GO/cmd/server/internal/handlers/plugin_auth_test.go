package handlers

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"relay-server/cmd/server/internal/storage"
)

// ========================================================================
// Helpers
// ========================================================================

// insertPluginTokenFull inserts a plugin token with all constraint fields.
func insertPluginTokenFull(t *testing.T, id, plain, desc, allowedIPs, hostPattern string, expiresAt *time.Time, revoked bool) {
	t.Helper()
	h := sha256.Sum256([]byte(plain))
	tok := storage.PluginToken{
		ID:                     id,
		TokenHash:              fmt.Sprintf("%x", h),
		Description:            desc,
		Role:                   "plugin",
		AllowedIPs:             allowedIPs,
		AllowedHostnamePattern: hostPattern,
		CreatedAt:              time.Now().UTC(),
		ExpiresAt:              expiresAt,
		Revoked:                revoked,
	}
	if err := adminStore.CreatePluginToken(context.Background(), tok); err != nil {
		t.Fatalf("insertPluginTokenFull: %v", err)
	}
	// Apply revoke flag if needed (CreatePluginToken sets revoked=0 by default)
	if revoked {
		if _, err := adminStore.RevokePluginToken(context.Background(), id); err != nil {
			t.Fatalf("insertPluginTokenFull revoke: %v", err)
		}
	}
}

// pluginReq builds an HTTP request with plugin Bearer token.
func pluginReq(method, path, tokenPlain string) *http.Request {
	req := httptest.NewRequest(method, path, nil)
	req.Header.Set("Authorization", "Bearer "+tokenPlain)
	return req
}

// pluginReqWithIP adds remote addr and optional X-Forwarded-For + X-Relay-Client-Host.
func pluginReqWithDetails(method, path, tokenPlain, remoteAddr, xff, relayHost string) *http.Request {
	req := httptest.NewRequest(method, path, nil)
	req.Header.Set("Authorization", "Bearer "+tokenPlain)
	req.RemoteAddr = remoteAddr
	if xff != "" {
		req.Header.Set("X-Forwarded-For", xff)
	}
	if relayHost != "" {
		req.Header.Set("X-Relay-Client-Host", relayHost)
	}
	return req
}

// ========================================================================
// extractClientIP
// ========================================================================

func TestExtractClientIPRemoteAddr(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.5:4321"
	ip := extractClientIP(req)
	if ip != "10.0.0.5" {
		t.Errorf("got %q, want %q", ip, "10.0.0.5")
	}
}

func TestExtractClientIPXForwardedFor(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:80"
	req.Header.Set("X-Forwarded-For", "192.168.1.100, 10.0.0.1")
	ip := extractClientIP(req)
	// First entry from X-Forwarded-For takes precedence
	if ip != "192.168.1.100" {
		t.Errorf("got %q, want %q", ip, "192.168.1.100")
	}
}

func TestExtractClientIPXForwardedForSingle(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "172.16.0.1:9000"
	req.Header.Set("X-Forwarded-For", "203.0.113.5")
	ip := extractClientIP(req)
	if ip != "203.0.113.5" {
		t.Errorf("got %q, want %q", ip, "203.0.113.5")
	}
}

func TestExtractClientIPNoPort(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "127.0.0.1"
	ip := extractClientIP(req)
	if ip != "127.0.0.1" {
		t.Errorf("got %q, want %q", ip, "127.0.0.1")
	}
}

// ========================================================================
// requirePluginAuth — basic auth checks
// ========================================================================

func TestPluginAuthMissingToken(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)

	req := httptest.NewRequest("POST", "/api/exec/host", nil)
	w := httptest.NewRecorder()
	_, ok := requirePluginAuth(w, req)
	if ok {
		t.Error("expected auth failure for missing token")
	}
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestPluginAuthUnknownToken(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)

	req := pluginReq("POST", "/api/exec/host", "relay_plg_does_not_exist")
	req.RemoteAddr = "10.0.0.1:80"
	w := httptest.NewRecorder()
	_, ok := requirePluginAuth(w, req)
	if ok {
		t.Error("expected auth failure for unknown token")
	}
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}
}

// ========================================================================
// requirePluginAuth — token state checks
// ========================================================================

func TestPluginAuthRevokedToken(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)
	plain := "relay_plg_revoked_01"
	insertPluginTokenFull(t, "tok-auth-rev-01", plain, "revoked", "", "", nil, true)

	req := pluginReq("POST", "/api/exec/host", plain)
	req.RemoteAddr = "10.0.0.1:80"
	w := httptest.NewRecorder()
	_, ok := requirePluginAuth(w, req)
	if ok {
		t.Error("expected auth failure for revoked token")
	}

	var body map[string]string
	json.Unmarshal(w.Body.Bytes(), &body)
	if body["error"] != "token_revoked" {
		t.Errorf("expected token_revoked, got %q", body["error"])
	}
}

func TestPluginAuthExpiredToken(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)
	plain := "relay_plg_expired_01"
	past := time.Now().UTC().Add(-time.Hour)
	insertPluginTokenFull(t, "tok-auth-exp-01", plain, "expired", "", "", &past, false)

	req := pluginReq("POST", "/api/exec/host", plain)
	req.RemoteAddr = "10.0.0.1:80"
	w := httptest.NewRecorder()
	_, ok := requirePluginAuth(w, req)
	if ok {
		t.Error("expected auth failure for expired token")
	}

	var body map[string]string
	json.Unmarshal(w.Body.Bytes(), &body)
	if body["error"] != "token_expired" {
		t.Errorf("expected token_expired, got %q", body["error"])
	}
}

// ========================================================================
// requirePluginAuth — CIDR IP validation
// ========================================================================

func TestPluginAuthIPAllowedInCIDR(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)
	plain := "relay_plg_cidr_ok_01"
	insertPluginTokenFull(t, "tok-cidr-ok-01", plain, "cidr-ok", "10.0.0.0/8", "", nil, false)

	req := pluginReqWithDetails("POST", "/api/exec/host", plain, "10.5.6.7:4321", "", "")
	w := httptest.NewRecorder()
	result, ok := requirePluginAuth(w, req)
	if !ok {
		t.Errorf("expected auth success, got %d — %s", w.Code, w.Body.String())
		return
	}
	if result.ClientIP != "10.5.6.7" {
		t.Errorf("ClientIP: got %q, want %q", result.ClientIP, "10.5.6.7")
	}
}

func TestPluginAuthIPMultipleCIDRs(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)
	plain := "relay_plg_cidr_multi_01"
	insertPluginTokenFull(t, "tok-cidr-multi-01", plain, "multi-cidr", "192.168.1.0/24,10.0.0.0/8", "", nil, false)

	// First CIDR match
	req1 := pluginReqWithDetails("POST", "/api/exec/host", plain, "192.168.1.55:443", "", "")
	w1 := httptest.NewRecorder()
	if _, ok := requirePluginAuth(w1, req1); !ok {
		t.Errorf("first CIDR: expected success, got %d", w1.Code)
	}

	// Second CIDR match
	req2 := pluginReqWithDetails("POST", "/api/exec/host", plain, "10.200.1.1:80", "", "")
	w2 := httptest.NewRecorder()
	if _, ok := requirePluginAuth(w2, req2); !ok {
		t.Errorf("second CIDR: expected success, got %d", w2.Code)
	}
}

func TestPluginAuthIPOutsideCIDR(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)
	plain := "relay_plg_cidr_deny_01"
	insertPluginTokenFull(t, "tok-cidr-deny-01", plain, "cidr-deny", "192.168.1.0/24", "", nil, false)

	req := pluginReqWithDetails("POST", "/api/exec/host", plain, "10.0.0.1:80", "", "")
	w := httptest.NewRecorder()
	_, ok := requirePluginAuth(w, req)
	if ok {
		t.Error("expected auth failure for IP outside CIDR")
	}
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}

	var body map[string]string
	json.Unmarshal(w.Body.Bytes(), &body)
	if body["error"] != "ip_not_allowed" {
		t.Errorf("expected ip_not_allowed, got %q", body["error"])
	}
}

func TestPluginAuthIPNoRestriction(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)
	plain := "relay_plg_cidr_none_01"
	insertPluginTokenFull(t, "tok-cidr-none-01", plain, "no-cidr", "", "", nil, false)

	// Any IP should pass when allowed_ips is empty
	req := pluginReqWithDetails("POST", "/api/exec/host", plain, "203.0.113.1:80", "", "")
	w := httptest.NewRecorder()
	if _, ok := requirePluginAuth(w, req); !ok {
		t.Errorf("expected success with no IP restriction, got %d", w.Code)
	}
}

func TestPluginAuthIPFromXForwardedFor(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)
	plain := "relay_plg_xff_01"
	insertPluginTokenFull(t, "tok-xff-01", plain, "xff-test", "192.168.10.0/24", "", nil, false)

	// RemoteAddr is the proxy, XFF contains the real client
	req := pluginReqWithDetails("POST", "/api/exec/host", plain, "10.0.0.100:80", "192.168.10.50", "")
	w := httptest.NewRecorder()
	result, ok := requirePluginAuth(w, req)
	if !ok {
		t.Errorf("expected success via X-Forwarded-For, got %d — %s", w.Code, w.Body.String())
		return
	}
	// ClientIP must be the XFF value, not RemoteAddr
	if result.ClientIP != "192.168.10.50" {
		t.Errorf("ClientIP: got %q, want %q", result.ClientIP, "192.168.10.50")
	}
}

// ========================================================================
// requirePluginAuth — hostname pattern validation
// ========================================================================

func TestPluginAuthHostnameMatch(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)
	plain := "relay_plg_host_ok_01"
	insertPluginTokenFull(t, "tok-host-ok-01", plain, "host-ok", "", "ansible-control-[0-9]+", nil, false)

	req := pluginReqWithDetails("POST", "/api/exec/host", plain, "10.0.0.1:80", "", "ansible-control-01")
	w := httptest.NewRecorder()
	if _, ok := requirePluginAuth(w, req); !ok {
		t.Errorf("expected hostname match success, got %d — %s", w.Code, w.Body.String())
	}
}

func TestPluginAuthHostnameMismatch(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)
	plain := "relay_plg_host_deny_01"
	insertPluginTokenFull(t, "tok-host-deny-01", plain, "host-deny", "", "ansible-control-[0-9]+", nil, false)

	req := pluginReqWithDetails("POST", "/api/exec/host", plain, "10.0.0.1:80", "", "not-ansible-control")
	w := httptest.NewRecorder()
	_, ok := requirePluginAuth(w, req)
	if ok {
		t.Error("expected auth failure for hostname mismatch")
	}

	var body map[string]string
	json.Unmarshal(w.Body.Bytes(), &body)
	if body["error"] != "hostname_not_allowed" {
		t.Errorf("expected hostname_not_allowed, got %q", body["error"])
	}
}

func TestPluginAuthHostnameAnchoredNoPartial(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)
	plain := "relay_plg_host_anchor_01"
	insertPluginTokenFull(t, "tok-host-anchor-01", plain, "anchored", "", "vp.*", nil, false)

	// Pattern "vp.*" anchored → "notavp" should not match
	req := pluginReqWithDetails("POST", "/api/exec/host", plain, "10.0.0.1:80", "", "notavp")
	w := httptest.NewRecorder()
	_, ok := requirePluginAuth(w, req)
	if ok {
		t.Error("expected auth failure for partial hostname match (not anchored properly)")
	}
}

func TestPluginAuthHostnameNoRestriction(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)
	plain := "relay_plg_host_none_01"
	insertPluginTokenFull(t, "tok-host-none-01", plain, "no-host-restriction", "", "", nil, false)

	// Any hostname (or no hostname) should pass
	req := pluginReqWithDetails("POST", "/api/exec/host", plain, "10.0.0.1:80", "", "")
	w := httptest.NewRecorder()
	if _, ok := requirePluginAuth(w, req); !ok {
		t.Errorf("expected success with no hostname restriction, got %d", w.Code)
	}
}

// ========================================================================
// requirePluginAuth — combined CIDR + hostname
// ========================================================================

func TestPluginAuthBothConstraintsPass(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)
	plain := "relay_plg_both_ok_01"
	insertPluginTokenFull(t, "tok-both-ok-01", plain, "both-ok", "10.0.0.0/8", "ansible-.*", nil, false)

	req := pluginReqWithDetails("POST", "/api/exec/host", plain, "10.1.2.3:443", "", "ansible-control-prod")
	w := httptest.NewRecorder()
	if _, ok := requirePluginAuth(w, req); !ok {
		t.Errorf("expected success with both constraints passing, got %d — %s", w.Code, w.Body.String())
	}
}

func TestPluginAuthCIDRPassHostnameFail(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)
	plain := "relay_plg_cidr_ok_host_fail_01"
	insertPluginTokenFull(t, "tok-cidr-ok-host-fail-01", plain, "cidr-ok-host-fail",
		"10.0.0.0/8", "ansible-.*", nil, false)

	// IP is OK, hostname fails
	req := pluginReqWithDetails("POST", "/api/exec/host", plain, "10.1.2.3:443", "", "terraform-runner")
	w := httptest.NewRecorder()
	_, ok := requirePluginAuth(w, req)
	if ok {
		t.Error("expected auth failure when hostname does not match")
	}
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}
}

func TestPluginAuthHostnamePassCIDRFail(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)
	plain := "relay_plg_host_ok_cidr_fail_01"
	insertPluginTokenFull(t, "tok-host-ok-cidr-fail-01", plain, "host-ok-cidr-fail",
		"192.168.1.0/24", "ansible-.*", nil, false)

	// Hostname is OK, IP fails
	req := pluginReqWithDetails("POST", "/api/exec/host", plain, "10.99.0.1:80", "", "ansible-control-01")
	w := httptest.NewRecorder()
	_, ok := requirePluginAuth(w, req)
	if ok {
		t.Error("expected auth failure when IP not in CIDR")
	}
}

// ========================================================================
// requirePluginAuth — audit: last_used_at updated
// ========================================================================

func TestPluginAuthAuditTouchCalled(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)
	plain := "relay_plg_audit_01"
	insertPluginTokenFull(t, "tok-audit-01", plain, "audit-test", "", "", nil, false)

	req := pluginReqWithDetails("POST", "/api/exec/host", plain, "10.0.0.1:80", "", "")
	w := httptest.NewRecorder()
	if _, ok := requirePluginAuth(w, req); !ok {
		t.Fatalf("expected success, got %d", w.Code)
	}

	// Verify last_used_at is set
	tok, err := adminStore.GetPluginTokenByID(context.Background(), "tok-audit-01")
	if err != nil {
		t.Fatalf("GetPluginTokenByID: %v", err)
	}
	if tok.LastUsedAt == nil {
		t.Error("expected LastUsedAt to be set after successful auth")
	}
	if tok.LastUsedIP != "10.0.0.1" {
		t.Errorf("LastUsedIP: got %q, want %q", tok.LastUsedIP, "10.0.0.1")
	}
}

// ========================================================================
// End-to-end: plugin auth on actual handlers
// ========================================================================

func TestExecCommandRequiresPluginAuth(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)

	// No auth header → must get 401
	body, _ := json.Marshal(map[string]interface{}{"cmd": "ls", "timeout": 10})
	req := httptest.NewRequest("POST", "/api/exec/some-host", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("hostname", "some-host")
	w := httptest.NewRecorder()
	ExecCommand(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("ExecCommand: expected 401 without auth, got %d", w.Code)
	}
}

func TestUploadFileRequiresPluginAuth(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)

	req := httptest.NewRequest("POST", "/api/upload/some-host", nil)
	req.SetPathValue("hostname", "some-host")
	w := httptest.NewRecorder()
	UploadFile(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("UploadFile: expected 401 without auth, got %d", w.Code)
	}
}

func TestFetchFileRequiresPluginAuth(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)

	req := httptest.NewRequest("POST", "/api/fetch/some-host", nil)
	req.SetPathValue("hostname", "some-host")
	w := httptest.NewRecorder()
	FetchFile(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("FetchFile: expected 401 without auth, got %d", w.Code)
	}
}

func TestGetInventoryRequiresPluginAuth(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)

	req := httptest.NewRequest("GET", "/api/inventory", nil)
	w := httptest.NewRecorder()
	GetInventory(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("GetInventory: expected 401 without auth, got %d", w.Code)
	}
}

func TestExecCommandWithValidPluginToken(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)
	plain := "relay_plg_exec_e2e_01"
	insertPluginTokenFull(t, "tok-exec-e2e-01", plain, "exec-e2e", "", "", nil, false)

	body, _ := json.Marshal(map[string]interface{}{"cmd": "ls", "timeout": 10})
	req := httptest.NewRequest("POST", "/api/exec/some-host", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+plain)
	req.RemoteAddr = "10.0.0.1:80"
	req.SetPathValue("hostname", "some-host")
	w := httptest.NewRecorder()
	ExecCommand(w, req)

	// Should pass auth and reach agent-online check (200 since checkAgentOnline is stub)
	if w.Code == http.StatusUnauthorized || w.Code == http.StatusForbidden {
		t.Errorf("ExecCommand: expected past auth, got %d — %s", w.Code, w.Body.String())
	}
}

func TestGetInventoryWithValidPluginToken(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)
	plain := "relay_plg_inv_e2e_01"
	insertPluginTokenFull(t, "tok-inv-e2e-01", plain, "inv-e2e", "", "", nil, false)

	req := httptest.NewRequest("GET", "/api/inventory", nil)
	req.Header.Set("Authorization", "Bearer "+plain)
	req.RemoteAddr = "10.0.0.1:80"
	w := httptest.NewRecorder()
	GetInventory(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("GetInventory: expected 200, got %d — %s", w.Code, w.Body.String())
	}
}

// ========================================================================
// Token prefix verification (create + use)
// ========================================================================

func TestPluginTokenPrefixRelay_plg(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)

	req := adminReq("POST", "/api/admin/tokens", TokenCreateRequest{
		Role:        "plugin",
		Description: "prefix-test",
	})
	w := httptest.NewRecorder()
	AdminCreateToken(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("AdminCreateToken: expected 201, got %d", w.Code)
	}

	var resp TokenCreateResponse
	json.NewDecoder(w.Body).Decode(&resp)
	plain := resp.Token

	if len(plain) < 10 || plain[:10] != "relay_plg_" {
		t.Errorf("expected relay_plg_ prefix, got %q", plain)
	}

	// Use the token immediately
	plugReq := pluginReqWithDetails("GET", "/api/inventory", plain, "127.0.0.1:80", "", "")
	pw := httptest.NewRecorder()
	GetInventory(pw, plugReq)

	if pw.Code != http.StatusOK {
		t.Errorf("GetInventory with freshly-created token: expected 200, got %d — %s", pw.Code, pw.Body.String())
	}
}

// ========================================================================
// base64 / stdlib sanity — verify SHA-256 hash is consistent
// ========================================================================

func TestPluginTokenHashConsistency(t *testing.T) {
	plain := "relay_plg_hash_test_abc123"
	h1 := sha256.Sum256([]byte(plain))
	h2 := sha256.Sum256([]byte(plain))
	if fmt.Sprintf("%x", h1) != fmt.Sprintf("%x", h2) {
		t.Error("SHA-256 hash must be deterministic")
	}
	// The hex string must be 64 chars (256 bits / 4 bits per hex char)
	if len(fmt.Sprintf("%x", h1)) != 64 {
		t.Errorf("expected 64-char hex hash, got %d", len(fmt.Sprintf("%x", h1)))
	}
}

// Unused import suppressor for base64 (used elsewhere in package)
var _ = base64.StdEncoding
