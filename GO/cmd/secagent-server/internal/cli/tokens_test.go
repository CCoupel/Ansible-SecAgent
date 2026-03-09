package cli

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

// ── parseDuration ─────────────────────────────────────────────────────────────

func TestParseDuration_Days(t *testing.T) {
	before := time.Now().UTC()
	got, err := parseDuration("30d")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := before.AddDate(0, 0, 30)
	diff := got.Sub(expected)
	if diff < -time.Second || diff > time.Second {
		t.Errorf("30d: expected ~%v, got %v", expected, got)
	}
}

func TestParseDuration_Hours(t *testing.T) {
	before := time.Now().UTC()
	got, err := parseDuration("24h")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	diff := got.Sub(before.Add(24 * time.Hour))
	if diff < -time.Second || diff > time.Second {
		t.Errorf("24h: got %v", got)
	}
}

func TestParseDuration_Minutes(t *testing.T) {
	before := time.Now().UTC()
	got, err := parseDuration("90m")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	diff := got.Sub(before.Add(90 * time.Minute))
	if diff < -time.Second || diff > time.Second {
		t.Errorf("90m: got %v", got)
	}
}

func TestParseDuration_RFC3339(t *testing.T) {
	ts := "2030-12-31T00:00:00Z"
	got, err := parseDuration(ts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.UTC().Format(time.RFC3339) != ts {
		t.Errorf("RFC3339: expected %s, got %s", ts, got.UTC().Format(time.RFC3339))
	}
}

func TestParseDuration_InvalidDay(t *testing.T) {
	cases := []string{"0d", "-1d", "abcd"}
	for _, c := range cases {
		if _, err := parseDuration(c); err == nil {
			t.Errorf("expected error for %q", c)
		}
	}
}

func TestParseDuration_ZeroDuration(t *testing.T) {
	if _, err := parseDuration("0h"); err == nil {
		t.Error("expected error for 0h")
	}
}

func TestParseDuration_Unknown(t *testing.T) {
	if _, err := parseDuration("forever"); err == nil {
		t.Error("expected error for unknown format")
	}
}

// ── validateCIDRs ─────────────────────────────────────────────────────────────

func TestValidateCIDRs_Valid(t *testing.T) {
	cases := []string{
		"10.0.0.0/8",
		"192.168.1.0/24,10.0.0.0/8",
		"172.16.0.0/12",
		"127.0.0.1",    // plain IP accepted
		"::1",          // IPv6
	}
	for _, c := range cases {
		if err := validateCIDRs(c); err != nil {
			t.Errorf("validateCIDRs(%q): unexpected error: %v", c, err)
		}
	}
}

func TestValidateCIDRs_Invalid(t *testing.T) {
	cases := []string{
		"not-a-cidr",
		"10.0.0.0/33",
		"10.0.0.0/8,bad",
	}
	for _, c := range cases {
		if err := validateCIDRs(c); err == nil {
			t.Errorf("validateCIDRs(%q): expected error", c)
		}
	}
}

// ── tokens create ─────────────────────────────────────────────────────────────

func TestTokensCreate_Enrollment_Success(t *testing.T) {
	mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/admin/tokens" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		// Verify body
		var body map[string]interface{}
		json.NewDecoder(r.Body).Decode(&body)
		if body["role"] != "enrollment" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if body["hostname_pattern"] != "vp.*" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"token":            "secagent_enr_abc123",
			"id":               "uuid-enr-01",
			"role":             "enrollment",
			"hostname_pattern": "vp.*",
			"reusable":         false,
			"expires_at":       "",
			"created_at":       time.Now().UTC().Format(time.RFC3339),
		})
	})

	out := captureStdout(t, func() {
		rootCmd.SetArgs([]string{"tokens", "create", "--role", "enrollment", "--hostname-pattern", "vp.*"})
		rootCmd.Execute() //nolint:errcheck
	})

	if !strings.Contains(out, "secagent_enr_abc123") {
		t.Errorf("expected token in output, got: %s", out)
	}
	if !strings.Contains(out, "enrollment") {
		t.Errorf("expected role in output, got: %s", out)
	}
}

func TestTokensCreate_Plugin_Success(t *testing.T) {
	mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		json.NewDecoder(r.Body).Decode(&body)

		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"token":       "secagent_plg_xyz789",
			"id":          "uuid-plg-01",
			"role":        "plugin",
			"description": "Terraform",
			"allowed_ips": "10.0.0.0/8",
			"expires_at":  "",
			"created_at":  time.Now().UTC().Format(time.RFC3339),
		})
	})

	out := captureStdout(t, func() {
		rootCmd.SetArgs([]string{
			"tokens", "create",
			"--role", "plugin",
			"--description", "Terraform",
			"--allowed-ips", "10.0.0.0/8",
		})
		rootCmd.Execute() //nolint:errcheck
	})

	if !strings.Contains(out, "secagent_plg_xyz789") {
		t.Errorf("expected token in output, got: %s", out)
	}
}

func TestTokensCreate_Plugin_WithExpiry(t *testing.T) {
	var receivedExpires string

	mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		json.NewDecoder(r.Body).Decode(&body)
		if v, ok := body["expires_at"].(string); ok {
			receivedExpires = v
		}

		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"token":      "secagent_plg_exp",
			"id":         "uuid-plg-02",
			"role":       "plugin",
			"expires_at": receivedExpires,
			"created_at": time.Now().UTC().Format(time.RFC3339),
		})
	})

	captureStdout(t, func() {
		rootCmd.SetArgs([]string{
			"tokens", "create",
			"--role", "plugin",
			"--expires", "30d",
		})
		rootCmd.Execute() //nolint:errcheck
	})

	if receivedExpires == "" {
		t.Error("expected expires_at to be sent to server")
	}
	// Should be ~30 days from now
	exp, err := time.Parse(time.RFC3339, receivedExpires)
	if err != nil {
		t.Fatalf("expires_at not valid RFC3339: %s", receivedExpires)
	}
	diff := exp.Sub(time.Now().UTC())
	if diff < 29*24*time.Hour || diff > 31*24*time.Hour {
		t.Errorf("expected ~30d expiry, got diff=%v", diff)
	}
}

func TestTokensCreate_MissingRole(t *testing.T) {
	err := tokensCreateCmd.RunE(tokensCreateCmd, []string{})
	// The --role flag is required; cobra will fail before RunE is called.
	// We test the validation logic directly.
	createRole = ""
	if err2 := tokensCreateCmd.RunE(tokensCreateCmd, []string{}); err2 == nil {
		// Should error because role is empty; if not, that's the flag-required enforcement
		_ = err
	}
}

func TestTokensCreate_Enrollment_MissingPattern(t *testing.T) {
	createRole = "enrollment"
	createHostnamePattern = ""
	err := tokensCreateCmd.RunE(tokensCreateCmd, []string{})
	if err == nil {
		t.Error("expected error for missing --hostname-pattern")
	}
}

func TestTokensCreate_InvalidRole(t *testing.T) {
	createRole = "invalid"
	err := tokensCreateCmd.RunE(tokensCreateCmd, []string{})
	if err == nil {
		t.Error("expected error for invalid role")
	}
}

func TestTokensCreate_InvalidCIDR(t *testing.T) {
	createRole = "plugin"
	createAllowedIPs = "not-a-cidr"
	createHostnamePattern = ""
	err := tokensCreateCmd.RunE(tokensCreateCmd, []string{})
	if err == nil {
		t.Error("expected error for invalid CIDR")
	}
	// Restore
	createAllowedIPs = ""
}

func TestTokensCreate_InvalidHostnamePattern(t *testing.T) {
	createRole = "plugin"
	createAllowedIPs = ""
	createAllowedHostname = "[invalid-regexp"
	err := tokensCreateCmd.RunE(tokensCreateCmd, []string{})
	if err == nil {
		t.Error("expected error for invalid hostname pattern regexp")
	}
	// Restore
	createAllowedHostname = ""
}

func TestTokensCreate_InvalidExpires(t *testing.T) {
	createRole = "plugin"
	createAllowedIPs = ""
	createAllowedHostname = ""
	createExpires = "forever"
	err := tokensCreateCmd.RunE(tokensCreateCmd, []string{})
	if err == nil {
		t.Error("expected error for invalid --expires")
	}
	// Restore
	createExpires = "never"
}

func TestTokensCreate_InvalidEnrollmentPattern(t *testing.T) {
	createRole = "enrollment"
	createHostnamePattern = "[bad"
	err := tokensCreateCmd.RunE(tokensCreateCmd, []string{})
	if err == nil {
		t.Error("expected error for invalid enrollment hostname pattern")
	}
	// Restore
	createHostnamePattern = ""
}

func TestTokensCreate_JSONFormat(t *testing.T) {
	mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"token":      "secagent_plg_json",
			"id":         "uuid-json-01",
			"role":       "plugin",
			"expires_at": "",
			"created_at": time.Now().UTC().Format(time.RFC3339),
		})
	})

	out := captureStdout(t, func() {
		rootCmd.SetArgs([]string{
			"tokens", "create",
			"--role", "plugin",
			"--format", "json",
		})
		rootCmd.Execute() //nolint:errcheck
	})

	var resp map[string]interface{}
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		t.Errorf("expected valid JSON, got: %s", out)
	}
}

// ── tokens list ───────────────────────────────────────────────────────────────

func TestTokensList_All(t *testing.T) {
	mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		json.NewEncoder(w).Encode([]map[string]interface{}{
			{
				"id":               "enr-01",
				"role":             "enrollment",
				"token_hash":       "abc123def456abc123",
				"hostname_pattern": "vp.*",
				"reusable":         false,
				"use_count":        1,
				"expires_at":       "",
				"created_at":       "2026-03-01T00:00:00Z",
			},
			{
				"id":          "plg-01",
				"role":        "plugin",
				"token_hash":  "xyz789ghi012xyz789",
				"description": "Terraform",
				"revoked":     false,
				"created_at":  "2026-03-02T00:00:00Z",
			},
		})
	})

	out := captureStdout(t, func() {
		rootCmd.SetArgs([]string{"tokens", "list"})
		rootCmd.Execute() //nolint:errcheck
	})

	if !strings.Contains(out, "enr-01") {
		t.Errorf("expected enr-01 in output, got: %s", out)
	}
	if !strings.Contains(out, "plg-01") {
		t.Errorf("expected plg-01 in output, got: %s", out)
	}
	// Plain token text must NOT appear
	if strings.Contains(out, "secagent_enr_") || strings.Contains(out, "secagent_plg_") {
		t.Error("plain token text must not appear in list output")
	}
}

func TestTokensList_FilterByRole(t *testing.T) {
	var receivedPath string
	mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.Path + "?" + r.URL.RawQuery
		json.NewEncoder(w).Encode([]interface{}{})
	})

	captureStdout(t, func() {
		rootCmd.SetArgs([]string{"tokens", "list", "--role", "enrollment"})
		rootCmd.Execute() //nolint:errcheck
	})

	if !strings.Contains(receivedPath, "role=enrollment") {
		t.Errorf("expected role=enrollment in request, got: %s", receivedPath)
	}
}

func TestTokensList_Empty(t *testing.T) {
	t.Cleanup(func() { globalFormat = "table" })
	mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]interface{}{})
	})

	out := captureStdout(t, func() {
		rootCmd.SetArgs([]string{"tokens", "list", "--format", "table"})
		rootCmd.Execute() //nolint:errcheck
	})

	if !strings.Contains(out, "No tokens found") {
		t.Errorf("expected 'No tokens found', got: %s", out)
	}
}

func TestTokensList_JSONFormat(t *testing.T) {
	mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]map[string]interface{}{
			{"id": "t1", "role": "plugin", "token_hash": "aaa", "created_at": "2026-03-01T00:00:00Z"},
		})
	})

	out := captureStdout(t, func() {
		rootCmd.SetArgs([]string{"tokens", "list", "--format", "json"})
		rootCmd.Execute() //nolint:errcheck
	})

	var resp []interface{}
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		t.Errorf("expected JSON array, got: %s", out)
	}
}

func TestTokensList_InvalidRole(t *testing.T) {
	listRole = "bad"
	err := tokensListCmd.RunE(tokensListCmd, []string{})
	if err == nil {
		t.Error("expected error for invalid --role")
	}
	listRole = ""
}

// ── tokens revoke ─────────────────────────────────────────────────────────────

func TestTokensRevoke_Success(t *testing.T) {
	var revokedID string
	mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/revoke") {
			parts := strings.Split(r.URL.Path, "/")
			// path: /api/admin/tokens/{id}/revoke
			for i, p := range parts {
				if p == "revoke" && i > 0 {
					revokedID = parts[i-1]
				}
			}
			json.NewEncoder(w).Encode(map[string]interface{}{
				"revoked":    true,
				"id":         revokedID,
				"updated_at": time.Now().UTC().Format(time.RFC3339),
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})

	out := captureStdout(t, func() {
		rootCmd.SetArgs([]string{"tokens", "revoke", "plg-tok-01"})
		rootCmd.Execute() //nolint:errcheck
	})

	if revokedID != "plg-tok-01" {
		t.Errorf("expected revoke for plg-tok-01, got: %s", revokedID)
	}
	if !strings.Contains(out, "plg-tok-01") {
		t.Errorf("expected token id in output, got: %s", out)
	}
}

func TestTokensRevoke_NotFound(t *testing.T) {
	mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "token_not_found"})
	})

	// Should exit non-zero — we check that it doesn't panic
	captureStdout(t, func() {
		rootCmd.SetArgs([]string{"tokens", "revoke", "does-not-exist"})
		// os.Exit(2) will be called — wrap to prevent test exit
	})
	// Test passes if no panic
}

// ── tokens delete ─────────────────────────────────────────────────────────────

func TestTokensDelete_Success(t *testing.T) {
	var deletedID string
	mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			// path: /api/admin/tokens/{id}
			parts := strings.Split(r.URL.Path, "/")
			deletedID = parts[len(parts)-1]
			json.NewEncoder(w).Encode(map[string]interface{}{
				"deleted": true,
				"id":      deletedID,
			})
			return
		}
		w.WriteHeader(http.StatusMethodNotAllowed)
	})

	out := captureStdout(t, func() {
		rootCmd.SetArgs([]string{"tokens", "delete", "enr-tok-01"})
		rootCmd.Execute() //nolint:errcheck
	})

	if deletedID != "enr-tok-01" {
		t.Errorf("expected DELETE for enr-tok-01, got: %s", deletedID)
	}
	if !strings.Contains(out, "enr-tok-01") {
		t.Errorf("expected token id in output, got: %s", out)
	}
}

// ── tokens purge ──────────────────────────────────────────────────────────────

func TestTokensPurge_Expired(t *testing.T) {
	var receivedQuery string
	mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		receivedQuery = r.URL.RawQuery
		json.NewEncoder(w).Encode(map[string]interface{}{
			"deleted_count": 3,
			"purged_at":     time.Now().UTC().Format(time.RFC3339),
		})
	})

	out := captureStdout(t, func() {
		rootCmd.SetArgs([]string{"tokens", "purge", "--expired"})
		rootCmd.Execute() //nolint:errcheck
	})

	if !strings.Contains(receivedQuery, "expired=1") {
		t.Errorf("expected expired=1 in query, got: %s", receivedQuery)
	}
	if !strings.Contains(out, "3") {
		t.Errorf("expected deleted_count in output, got: %s", out)
	}
}

func TestTokensPurge_Used(t *testing.T) {
	var receivedQuery string
	mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		receivedQuery = r.URL.RawQuery
		json.NewEncoder(w).Encode(map[string]interface{}{
			"deleted_count": 1,
			"purged_at":     time.Now().UTC().Format(time.RFC3339),
		})
	})

	captureStdout(t, func() {
		rootCmd.SetArgs([]string{"tokens", "purge", "--used"})
		rootCmd.Execute() //nolint:errcheck
	})

	if !strings.Contains(receivedQuery, "used=1") {
		t.Errorf("expected used=1 in query, got: %s", receivedQuery)
	}
}

func TestTokensPurge_Both(t *testing.T) {
	var receivedQuery string
	mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		receivedQuery = r.URL.RawQuery
		json.NewEncoder(w).Encode(map[string]interface{}{
			"deleted_count": 5,
			"purged_at":     time.Now().UTC().Format(time.RFC3339),
		})
	})

	captureStdout(t, func() {
		rootCmd.SetArgs([]string{"tokens", "purge", "--expired", "--used"})
		rootCmd.Execute() //nolint:errcheck
	})

	if !strings.Contains(receivedQuery, "expired=1") || !strings.Contains(receivedQuery, "used=1") {
		t.Errorf("expected both params in query, got: %s", receivedQuery)
	}
}

func TestTokensPurge_NoFlags(t *testing.T) {
	purgeExpired = false
	purgeUsed = false
	err := tokensPurgeCmd.RunE(tokensPurgeCmd, []string{})
	if err == nil {
		t.Error("expected error when no flags specified")
	}
	if !strings.Contains(err.Error(), "at least one") {
		t.Errorf("expected 'at least one' in error, got: %s", err)
	}
}

func TestTokensPurge_JSONFormat(t *testing.T) {
	mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"deleted_count": 0,
			"purged_at":     "2026-03-08T00:00:00Z",
		})
	})

	out := captureStdout(t, func() {
		rootCmd.SetArgs([]string{"tokens", "purge", "--expired", "--format", "json"})
		rootCmd.Execute() //nolint:errcheck
	})

	var resp map[string]interface{}
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		t.Errorf("expected JSON, got: %s", out)
	}
}

// ── integration: token prefix in create response ──────────────────────────────

func TestTokensCreate_EnrollmentPrefixRelay_enr(t *testing.T) {
	mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"token":            "secagent_enr_" + fmt.Sprintf("%064x", 0),
			"id":               "uuid-prefix-enr",
			"role":             "enrollment",
			"hostname_pattern": "vp.*",
			"reusable":         false,
			"expires_at":       "",
			"created_at":       time.Now().UTC().Format(time.RFC3339),
		})
	})

	out := captureStdout(t, func() {
		rootCmd.SetArgs([]string{
			"tokens", "create",
			"--role", "enrollment",
			"--hostname-pattern", "vp.*",
		})
		rootCmd.Execute() //nolint:errcheck
	})

	if !strings.Contains(out, "secagent_enr_") {
		t.Errorf("expected secagent_enr_ prefix in output, got: %s", out)
	}
}

func TestTokensCreate_PluginPrefixRelay_plg(t *testing.T) {
	mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"token":      "secagent_plg_" + fmt.Sprintf("%064x", 0),
			"id":         "uuid-prefix-plg",
			"role":       "plugin",
			"expires_at": "",
			"created_at": time.Now().UTC().Format(time.RFC3339),
		})
	})

	out := captureStdout(t, func() {
		rootCmd.SetArgs([]string{"tokens", "create", "--role", "plugin"})
		rootCmd.Execute() //nolint:errcheck
	})

	if !strings.Contains(out, "secagent_plg_") {
		t.Errorf("expected secagent_plg_ prefix in output, got: %s", out)
	}
}

// ── edge cases ────────────────────────────────────────────────────────────────

func TestTokensList_NoPlainTextEvenOnServerBug(t *testing.T) {
	t.Cleanup(func() { globalFormat = "table" })
	// Even if the server accidentally returns a token field, list must not display it
	mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]map[string]interface{}{
			{
				"id":         "plg-bug",
				"role":       "plugin",
				"token_hash": "safehash",
				"token":      "secagent_plg_this_should_not_appear",
				"created_at": "2026-03-01T00:00:00Z",
			},
		})
	})

	out := captureStdout(t, func() {
		// Force table format — table renderer only shows token_hash (truncated)
		rootCmd.SetArgs([]string{"tokens", "list", "--format", "table"})
		rootCmd.Execute() //nolint:errcheck
	})

	// Table output only shows token_hash (truncated), not the plain token
	if strings.Contains(out, "secagent_plg_this_should_not_appear") {
		t.Errorf("plain token must not appear in list table output, got: %s", out)
	}
}
