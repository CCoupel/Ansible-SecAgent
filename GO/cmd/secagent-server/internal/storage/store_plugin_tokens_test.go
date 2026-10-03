package storage

import (
	"context"
	"testing"
	"time"
)

// ========================================================================
// plugin_tokens — CRUD
// ========================================================================

func makePluginToken(id, hash, desc, allowedIPs, hostPattern string, expiresAt *time.Time) PluginToken {
	return PluginToken{
		ID:                     id,
		TokenHash:              hash,
		Description:            desc,
		Role:                   "plugin",
		AllowedIPs:             allowedIPs,
		AllowedHostnamePattern: hostPattern,
		CreatedAt:              time.Now().UTC(),
		ExpiresAt:              expiresAt,
	}
}

func TestCreateAndGetPluginTokenByHash(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	tok := makePluginToken("uuid-p1", "phash-aaa", "ansible-control-prod", "192.168.1.0/24", "ansible-control-[0-9]+", nil)
	if err := store.CreatePluginToken(ctx, tok); err != nil {
		t.Fatalf("CreatePluginToken: %v", err)
	}

	got, err := store.GetPluginTokenByHash(ctx, "phash-aaa")
	if err != nil {
		t.Fatalf("GetPluginTokenByHash: %v", err)
	}
	if got == nil {
		t.Fatal("expected token, got nil")
	}
	if got.ID != "uuid-p1" {
		t.Errorf("ID: got %q, want %q", got.ID, "uuid-p1")
	}
	if got.TokenHash != "phash-aaa" {
		t.Errorf("TokenHash: got %q, want %q", got.TokenHash, "phash-aaa")
	}
	if got.Description != "ansible-control-prod" {
		t.Errorf("Description: got %q, want %q", got.Description, "ansible-control-prod")
	}
	if got.Role != "plugin" {
		t.Errorf("Role: got %q, want %q", got.Role, "plugin")
	}
	if got.AllowedIPs != "192.168.1.0/24" {
		t.Errorf("AllowedIPs: got %q, want %q", got.AllowedIPs, "192.168.1.0/24")
	}
	if got.AllowedHostnamePattern != "ansible-control-[0-9]+" {
		t.Errorf("AllowedHostnamePattern: got %q, want %q", got.AllowedHostnamePattern, "ansible-control-[0-9]+")
	}
	if got.Revoked {
		t.Error("expected Revoked=false")
	}
	if got.LastUsedAt != nil {
		t.Error("expected LastUsedAt=nil before first use")
	}
	if got.ExpiresAt != nil {
		t.Error("expected ExpiresAt=nil for permanent token")
	}
}

func TestGetPluginTokenByHashNotFound(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	got, err := store.GetPluginTokenByHash(ctx, "nonexistent")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil, got %+v", got)
	}
}

func TestGetPluginTokenByID(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	tok := makePluginToken("uuid-p2", "phash-bbb", "dev", "", "", nil)
	if err := store.CreatePluginToken(ctx, tok); err != nil {
		t.Fatalf("CreatePluginToken: %v", err)
	}

	got, err := store.GetPluginTokenByID(ctx, "uuid-p2")
	if err != nil {
		t.Fatalf("GetPluginTokenByID: %v", err)
	}
	if got == nil {
		t.Fatal("expected token, got nil")
	}
	if got.AllowedIPs != "" {
		t.Errorf("expected empty AllowedIPs, got %q", got.AllowedIPs)
	}
	if got.AllowedHostnamePattern != "" {
		t.Errorf("expected empty AllowedHostnamePattern, got %q", got.AllowedHostnamePattern)
	}
}

func TestGetPluginTokenByIDNotFound(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	got, err := store.GetPluginTokenByID(ctx, "nonexistent-uuid")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil, got %+v", got)
	}
}

func TestCreatePluginTokenWithExpiry(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	expiry := time.Now().UTC().Add(365 * 24 * time.Hour)
	tok := makePluginToken("uuid-pexp", "phash-exp", "expiring-token", "", "", &expiry)
	if err := store.CreatePluginToken(ctx, tok); err != nil {
		t.Fatalf("CreatePluginToken: %v", err)
	}

	got, _ := store.GetPluginTokenByHash(ctx, "phash-exp")
	if got.ExpiresAt == nil {
		t.Fatal("expected ExpiresAt to be set")
	}
	diff := got.ExpiresAt.Sub(expiry)
	if diff > 2*time.Second || diff < -2*time.Second {
		t.Errorf("ExpiresAt mismatch: got %v, want ~%v", got.ExpiresAt, expiry)
	}
}

func TestListPluginTokens(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	for i, id := range []string{"uuid-pa", "uuid-pb", "uuid-pc"} {
		tok := makePluginToken(id, "phash-list-"+id, "token"+string(rune('A'+i)), "", "", nil)
		if err := store.CreatePluginToken(ctx, tok); err != nil {
			t.Fatalf("CreatePluginToken %s: %v", id, err)
		}
	}

	list, err := store.ListPluginTokens(ctx)
	if err != nil {
		t.Fatalf("ListPluginTokens: %v", err)
	}
	if len(list) != 3 {
		t.Errorf("expected 3 tokens, got %d", len(list))
	}
}

func TestListPluginTokensEmpty(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	list, err := store.ListPluginTokens(ctx)
	if err != nil {
		t.Fatalf("ListPluginTokens: %v", err)
	}
	if len(list) != 0 {
		t.Errorf("expected 0 tokens, got %d", len(list))
	}
}

func TestRevokePluginToken(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	tok := makePluginToken("uuid-rev", "phash-rev", "revocable", "", "", nil)
	if err := store.CreatePluginToken(ctx, tok); err != nil {
		t.Fatalf("CreatePluginToken: %v", err)
	}

	found, err := store.RevokePluginToken(ctx, "uuid-rev")
	if err != nil {
		t.Fatalf("RevokePluginToken: %v", err)
	}
	if !found {
		t.Error("expected found=true")
	}

	got, _ := store.GetPluginTokenByHash(ctx, "phash-rev")
	if got == nil {
		t.Fatal("expected token to still exist (soft-delete)")
	}
	if !got.Revoked {
		t.Error("expected Revoked=true after revocation")
	}
}

func TestRevokePluginTokenNotFound(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	found, err := store.RevokePluginToken(ctx, "nonexistent-uuid")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if found {
		t.Error("expected found=false for nonexistent token")
	}
}

func TestDeletePluginToken(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	tok := makePluginToken("uuid-pdel", "phash-pdel", "deletable", "", "", nil)
	if err := store.CreatePluginToken(ctx, tok); err != nil {
		t.Fatalf("CreatePluginToken: %v", err)
	}

	deleted, err := store.DeletePluginToken(ctx, "uuid-pdel")
	if err != nil {
		t.Fatalf("DeletePluginToken: %v", err)
	}
	if !deleted {
		t.Error("expected deleted=true")
	}

	got, _ := store.GetPluginTokenByHash(ctx, "phash-pdel")
	if got != nil {
		t.Error("expected token to be gone after deletion")
	}
}

func TestDeletePluginTokenNotFound(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	deleted, err := store.DeletePluginToken(ctx, "nonexistent-uuid")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if deleted {
		t.Error("expected deleted=false for nonexistent token")
	}
}

func TestTouchPluginToken(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	tok := makePluginToken("uuid-touch", "phash-touch", "touchable", "", "", nil)
	if err := store.CreatePluginToken(ctx, tok); err != nil {
		t.Fatalf("CreatePluginToken: %v", err)
	}

	if err := store.TouchPluginToken(ctx, "uuid-touch", "10.0.0.5"); err != nil {
		t.Fatalf("TouchPluginToken: %v", err)
	}

	got, _ := store.GetPluginTokenByHash(ctx, "phash-touch")
	if got.LastUsedAt == nil {
		t.Error("expected LastUsedAt to be set after touch")
	}
	if got.LastUsedIP != "10.0.0.5" {
		t.Errorf("LastUsedIP: got %q, want %q", got.LastUsedIP, "10.0.0.5")
	}
}

func TestTouchPluginTokenNotFound(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	err := store.TouchPluginToken(ctx, "nonexistent-uuid", "10.0.0.1")
	if err == nil {
		t.Error("expected error for nonexistent token")
	}
}

func TestCreatePluginTokenDuplicateHashRejected(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	tok1 := makePluginToken("uuid-pd1", "phash-dup", "first", "", "", nil)
	if err := store.CreatePluginToken(ctx, tok1); err != nil {
		t.Fatalf("first CreatePluginToken: %v", err)
	}

	tok2 := makePluginToken("uuid-pd2", "phash-dup", "second", "", "", nil)
	err := store.CreatePluginToken(ctx, tok2)
	if err == nil {
		t.Error("expected error for duplicate token_hash, got nil")
	}
}

// ========================================================================
// plugin_tokens — IP validation (SECURITY.md §6)
// ========================================================================

func TestPluginTokenCheckIPAllowed(t *testing.T) {
	cases := []struct {
		name       string
		allowedIPs string
		remoteAddr string
		want       bool
	}{
		{"no restriction", "", "10.0.0.5:1234", true},
		{"exact match /32", "10.0.0.5/32", "10.0.0.5:9000", true},
		{"in /24 subnet", "10.0.0.0/24", "10.0.0.100:443", true},
		{"in /8 subnet", "10.0.0.0/8", "10.255.1.2:80", true},
		{"multiple CIDRs first match", "192.168.1.0/24,10.0.0.0/8", "10.1.2.3:80", true},
		{"multiple CIDRs second match", "192.168.1.0/24,10.0.0.0/8", "192.168.1.55:443", true},
		{"outside CIDR", "192.168.1.0/24", "10.0.0.1:80", false},
		{"no port in addr", "10.0.0.0/8", "10.1.2.3", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := PluginTokenCheckIP(tc.allowedIPs, tc.remoteAddr)
			if err != nil {
				t.Fatalf("PluginTokenCheckIP: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %v, want %v (allowedIPs=%q remoteAddr=%q)",
					got, tc.want, tc.allowedIPs, tc.remoteAddr)
			}
		})
	}
}

func TestPluginTokenCheckIPInvalidCIDR(t *testing.T) {
	_, err := PluginTokenCheckIP("not-a-cidr", "10.0.0.1:80")
	if err == nil {
		t.Error("expected error for invalid CIDR")
	}
}

func TestPluginTokenCheckIPInvalidRemoteAddr(t *testing.T) {
	_, err := PluginTokenCheckIP("10.0.0.0/8", "not-an-ip")
	if err == nil {
		t.Error("expected error for invalid remote IP")
	}
}

// ========================================================================
// plugin_tokens — hostname validation (SECURITY.md §6)
// ========================================================================

func TestPluginTokenCheckHostnameAllowed(t *testing.T) {
	cases := []struct {
		name     string
		pattern  string
		hostname string
		want     bool
	}{
		{"no restriction", "", "anything.example.com", true},
		{"exact match", "ansible-control-01", "ansible-control-01", true},
		{"regexp numeric suffix", "ansible-control-[0-9]+", "ansible-control-42", true},
		{"regexp numeric suffix no match", "ansible-control-[0-9]+", "ansible-control-prod", false},
		{"wildcard prefix", "ansible-.*", "ansible-control-prod", true},
		{"wildcard prefix no match", "ansible-.*", "notansible-control", false},
		{"anchored — no partial match", "vp.*", "notavp", false},
		{"anchored full string", "vp.*", "vp-server-01", true},
		{"complex pattern prod", ".*-prod-.*", "app-prod-01", true},
		{"complex pattern staging", ".*-prod-.*", "app-staging-01", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := PluginTokenCheckHostname(tc.pattern, tc.hostname)
			if err != nil {
				t.Fatalf("PluginTokenCheckHostname: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %v, want %v (pattern=%q hostname=%q)",
					got, tc.want, tc.pattern, tc.hostname)
			}
		})
	}
}

func TestPluginTokenCheckHostnameInvalidRegexp(t *testing.T) {
	_, err := PluginTokenCheckHostname("[invalid-regexp", "anything")
	if err == nil {
		t.Error("expected error for invalid regexp")
	}
}

// TestPluginTokenCheckHostname_AlternationAnchored verifies that alternation
// patterns are fully anchored at both ends, preventing partial-string bypass.
//
// Regression for #143: "^web1|db$" was interpreted as "(^web1)|(db$)", allowing
// "xdb" (matches db$) and "web1-evil" (matches ^web1) to bypass the check.
// The fix wraps the user pattern in a non-capturing group: "^(?:web1|db)$".
func TestPluginTokenCheckHostname_AlternationAnchored(t *testing.T) {
	cases := []struct {
		name     string
		pattern  string
		hostname string
		want     bool
	}{
		// ── Security regression cases (these FAILED before the fix) ────────
		{"alternation rejects suffix bypass", "web1|db", "xdb", false},
		{"alternation rejects prefix bypass", "web1|db", "web1-evil", false},
		{"alternation rejects web1x", "web1|db", "web1x", false},
		{"alternation rejects dbx", "web1|db", "dbx", false},

		// ── Alternation should still match valid hostnames ─────────────────
		{"alternation accepts first choice", "web1|db", "web1", true},
		{"alternation accepts second choice", "web1|db", "db", true},

		// ── Three-way alternation ──────────────────────────────────────────
		{"three-way alternation match first", "web1|db|app", "web1", true},
		{"three-way alternation match last", "web1|db|app", "app", true},
		{"three-way alternation rejects bypass", "web1|db|app", "xapp", false},
		{"three-way alternation rejects prefix bypass", "web1|db|app", "web1-extra", false},

		// ── Non-regression: simple patterns must be unchanged ─────────────
		{"non-regression exact", "vp-db-01", "vp-db-01", true},
		{"non-regression exact no match", "vp-db-01", "vp-db-02", false},
		{"non-regression wildcard", "vp.*", "vp-server-01", true},
		{"non-regression wildcard no match", "vp.*", "notavp", false},
		{"non-regression numeric suffix", "web[0-9]+", "web42", true},
		{"non-regression numeric suffix no match", "web[0-9]+", "webx", false},
		{"non-regression complex prod", ".*-prod-.*", "app-prod-01", true},
		{"non-regression complex staging", ".*-prod-.*", "app-staging-01", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := PluginTokenCheckHostname(tc.pattern, tc.hostname)
			if err != nil {
				t.Fatalf("unexpected error for pattern=%q hostname=%q: %v", tc.pattern, tc.hostname, err)
			}
			if got != tc.want {
				t.Errorf("pattern=%q hostname=%q: got %v, want %v",
					tc.pattern, tc.hostname, got, tc.want)
			}
		})
	}
}

// TestPluginTokenCheckHostname_AlternationAnchoredInvalidRegexp verifies that
// wrapping in ^(?:...)$ does not change the error behaviour for invalid patterns.
func TestPluginTokenCheckHostname_AlternationAnchoredInvalidRegexp(t *testing.T) {
	cases := []string{"[invalid", "(?P<", "**bad"}
	for _, p := range cases {
		_, err := PluginTokenCheckHostname(p, "anything")
		if err == nil {
			t.Errorf("expected error for invalid pattern %q, got nil", p)
		}
	}
}

// TestPluginTokenCheckHostname_InjectionRejected verifies that patterns with
// unbalanced groups (which would escape the ^(?:...)$ wrapper and create a
// partial-anchor bypass) are rejected as invalid (#143 group-injection vector).
//
// Example: "web1)|(db" → "^(?:web1)|(db)$" compiles but anchors incorrectly
// as "(^(?:web1))|(db)$", accepting "xdb". The fix pre-compiles the raw pattern,
// which fails on the unbalanced ")" before wrapping is applied.
func TestPluginTokenCheckHostname_InjectionRejected(t *testing.T) {
	injectionPatterns := []struct {
		name    string
		pattern string
	}{
		{"unbalanced paren — bypass injection", "web1)|(db"},
		{"extra close paren", "web1))"},
		{"open paren injection", "web1|(db"},
	}

	for _, tc := range injectionPatterns {
		t.Run(tc.name, func(t *testing.T) {
			_, err := PluginTokenCheckHostname(tc.pattern, "anything")
			if err == nil {
				t.Errorf("SECURITY: pattern %q should be rejected as invalid but compiled — injection possible", tc.pattern)
			}
		})
	}
}

// TestPluginTokenCheckHostname_InjectionHostnameBypassPrevented verifies that
// even if "web1)|(db" were somehow stored, it cannot match hostnames that
// should be excluded. (Belt-and-suspenders: the pattern is now rejected at
// creation time, so this case is doubly defended.)
func TestPluginTokenCheckHostname_ValidAlternationDoesNotBypass(t *testing.T) {
	// Valid alternation — must not accept bypass hostnames
	bypassCases := []struct {
		hostname string
		want     bool
	}{
		{"web1", true},
		{"db", true},
		{"xdb", false},
		{"web1-evil", false},
		{"web1x", false},
	}
	for _, tc := range bypassCases {
		got, err := PluginTokenCheckHostname("web1|db", tc.hostname)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != tc.want {
			t.Errorf("pattern=web1|db hostname=%q: got %v, want %v", tc.hostname, got, tc.want)
		}
	}
}
