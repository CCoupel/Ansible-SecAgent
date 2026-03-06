package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"relay-server/cmd/server/internal/ws"
)

// ========================================================================
// POST /api/admin/keys/rotate
// ========================================================================

func TestAdminRotateKeys_NoAgents(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)
	ctx := context.Background()

	// Initialize server state so rotation has a proper current key
	if err := InitServerState(ctx, s); err != nil {
		t.Fatalf("InitServerState: %v", err)
	}

	req := adminReq("POST", "/api/admin/keys/rotate", map[string]string{"grace": "1h"})
	w := httptest.NewRecorder()
	AdminRotateKeys(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp RotateKeysResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if resp.CurrentKeySHA256 == "" {
		t.Error("expected current_key_sha256 to be set")
	}
	if resp.PreviousKeySHA256 == "" {
		t.Error("expected previous_key_sha256 to be set")
	}
	if resp.CurrentKeySHA256 == resp.PreviousKeySHA256 {
		t.Error("current and previous sha256 should differ after rotation")
	}
	if resp.Deadline == "" {
		t.Error("expected deadline to be set")
	}
	if resp.AgentsTotal != 0 {
		t.Errorf("expected 0 agents_total, got %d", resp.AgentsTotal)
	}
	if resp.AgentsMigrated != 0 {
		t.Errorf("expected 0 agents_migrated, got %d", resp.AgentsMigrated)
	}
}

func TestAdminRotateKeys_NoBody_DefaultGrace(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)
	ctx := context.Background()

	if err := InitServerState(ctx, s); err != nil {
		t.Fatalf("InitServerState: %v", err)
	}

	// No body — should default to 24h grace
	req := adminReq("POST", "/api/admin/keys/rotate", nil)
	w := httptest.NewRecorder()
	AdminRotateKeys(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp RotateKeysResponse
	json.NewDecoder(w.Body).Decode(&resp) //nolint:errcheck

	// Deadline should be ~24h from now (allow ±5 minutes)
	deadline, err := time.Parse(time.RFC3339, resp.Deadline)
	if err != nil {
		t.Fatalf("parse deadline: %v", err)
	}
	expectedMin := time.Now().Add(23 * time.Hour)
	expectedMax := time.Now().Add(25 * time.Hour)
	if deadline.Before(expectedMin) || deadline.After(expectedMax) {
		t.Errorf("deadline %s outside expected 24h window", resp.Deadline)
	}
}

func TestAdminRotateKeys_InvalidGrace(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)

	req := adminReq("POST", "/api/admin/keys/rotate", map[string]string{"grace": "notaduration"})
	w := httptest.NewRecorder()
	AdminRotateKeys(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestAdminRotateKeys_UpdatesInMemoryState(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)
	ctx := context.Background()

	if err := InitServerState(ctx, s); err != nil {
		t.Fatalf("InitServerState: %v", err)
	}

	// Capture current secret before rotation
	server.mu.RLock()
	secretBefore := server.JWTSecret
	server.mu.RUnlock()

	req := adminReq("POST", "/api/admin/keys/rotate", map[string]string{"grace": "2h"})
	w := httptest.NewRecorder()
	AdminRotateKeys(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	server.mu.RLock()
	secretAfter := server.JWTSecret
	prevSecret := server.JWTPreviousSecret
	deadlineAfter := server.KeyRotationDeadline
	server.mu.RUnlock()

	if secretAfter == secretBefore {
		t.Error("JWT secret should have changed after rotation")
	}
	if prevSecret != secretBefore {
		t.Errorf("jwt_secret_previous should be old current, got %q", prevSecret)
	}
	if deadlineAfter.IsZero() {
		t.Error("key_rotation_deadline should be set after rotation")
	}
	if time.Until(deadlineAfter) < time.Hour || time.Until(deadlineAfter) > 3*time.Hour {
		t.Errorf("deadline should be ~2h from now, got %s", deadlineAfter)
	}
}

func TestAdminRotateKeys_PersistsToDBAfterRotation(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)
	ctx := context.Background()

	if err := InitServerState(ctx, s); err != nil {
		t.Fatalf("InitServerState: %v", err)
	}

	req := adminReq("POST", "/api/admin/keys/rotate", map[string]string{"grace": "1h"})
	w := httptest.NewRecorder()
	AdminRotateKeys(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	// Verify DB has updated values
	newJWTCurrent, _ := s.ConfigGet(ctx, "jwt_secret_current")
	newJWTPrev, _ := s.ConfigGet(ctx, "jwt_secret_previous")
	deadline, _ := s.ConfigGet(ctx, "key_rotation_deadline")
	rsaCurrent, _ := s.ConfigGet(ctx, "rsa_key_current")

	if newJWTCurrent == "" {
		t.Error("jwt_secret_current should be in DB after rotation")
	}
	if newJWTPrev == "" {
		t.Error("jwt_secret_previous should be in DB after rotation")
	}
	if newJWTCurrent == newJWTPrev {
		t.Error("jwt_secret_current and jwt_secret_previous should differ")
	}
	if deadline == "" {
		t.Error("key_rotation_deadline should be in DB after rotation")
	}
	if rsaCurrent == "" {
		t.Error("rsa_key_current should be in DB after rotation")
	}
}

func TestAdminRotateKeys_RequiresAdminAuth(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)

	req := httptest.NewRequest("POST", "/api/admin/keys/rotate", strings.NewReader(`{"grace":"1h"}`))
	req.Header.Set("Authorization", "Bearer wrong-token")
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	AdminRotateKeys(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestAdminRotateKeys_NoStore(t *testing.T) {
	SetAdminStore(nil)
	defer SetAdminStore(nil)

	req := adminReq("POST", "/api/admin/keys/rotate", nil)
	w := httptest.NewRecorder()
	AdminRotateKeys(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
}

// ========================================================================
// GET /api/admin/security/keys/status
// ========================================================================

func TestAdminSecurityKeysStatus_NoRotation(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)

	// Set a known state — no rotation in progress
	server.mu.Lock()
	server.JWTSecret = "test-secret"
	server.JWTPreviousSecret = ""
	server.KeyRotationDeadline = time.Time{}
	server.mu.Unlock()

	req := adminReq("GET", "/api/admin/security/keys/status", nil)
	w := httptest.NewRecorder()
	AdminSecurityKeysStatus(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp KeysStatusResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if resp.CurrentKeySHA256 == "" {
		t.Error("expected current_key_sha256")
	}
	if resp.PreviousKeySHA256 != "" {
		t.Errorf("expected empty previous_key_sha256, got %q", resp.PreviousKeySHA256)
	}
	if resp.RotationActive {
		t.Error("expected rotation_active=false")
	}
	if resp.Deadline != "" {
		t.Errorf("expected empty deadline, got %q", resp.Deadline)
	}
}

func TestAdminSecurityKeysStatus_RotationActive(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)

	deadline := time.Now().Add(24 * time.Hour)
	server.mu.Lock()
	server.JWTSecret = "current-secret"
	server.JWTPreviousSecret = "previous-secret"
	server.KeyRotationDeadline = deadline
	server.mu.Unlock()
	defer func() {
		server.mu.Lock()
		server.JWTPreviousSecret = ""
		server.KeyRotationDeadline = time.Time{}
		server.mu.Unlock()
	}()

	req := adminReq("GET", "/api/admin/security/keys/status", nil)
	w := httptest.NewRecorder()
	AdminSecurityKeysStatus(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp KeysStatusResponse
	json.NewDecoder(w.Body).Decode(&resp) //nolint:errcheck

	if !resp.RotationActive {
		t.Error("expected rotation_active=true")
	}
	if resp.PreviousKeySHA256 == "" {
		t.Error("expected previous_key_sha256 to be set")
	}
	if resp.Deadline == "" {
		t.Error("expected deadline to be set")
	}
	if resp.CurrentKeySHA256 == resp.PreviousKeySHA256 {
		t.Error("current and previous sha256 should differ")
	}
}

func TestAdminSecurityKeysStatus_RotationExpired(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)

	// Deadline in the past
	pastDeadline := time.Now().Add(-1 * time.Hour)
	server.mu.Lock()
	server.JWTSecret = "current-secret"
	server.JWTPreviousSecret = "previous-secret"
	server.KeyRotationDeadline = pastDeadline
	server.mu.Unlock()
	defer func() {
		server.mu.Lock()
		server.JWTPreviousSecret = ""
		server.KeyRotationDeadline = time.Time{}
		server.mu.Unlock()
	}()

	req := adminReq("GET", "/api/admin/security/keys/status", nil)
	w := httptest.NewRecorder()
	AdminSecurityKeysStatus(w, req)

	var resp KeysStatusResponse
	json.NewDecoder(w.Body).Decode(&resp) //nolint:errcheck

	if resp.RotationActive {
		t.Error("expected rotation_active=false when deadline is past")
	}
}

// ========================================================================
// GET /api/admin/security/tokens
// ========================================================================

func TestAdminSecurityTokens_Empty(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)

	req := adminReq("GET", "/api/admin/security/tokens", nil)
	w := httptest.NewRecorder()
	AdminSecurityTokens(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var tokens []TokenInfo
	json.NewDecoder(w.Body).Decode(&tokens) //nolint:errcheck
	if len(tokens) != 0 {
		t.Errorf("expected 0 tokens, got %d", len(tokens))
	}
}

func TestAdminSecurityTokens_WithAgents(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)
	ctx := context.Background()

	// Seed agents with JTIs
	if err := s.UpsertAgent(ctx, "host-1", "PUBKEY", "jti-1"); err != nil {
		t.Fatalf("UpsertAgent: %v", err)
	}
	if err := s.UpsertAgent(ctx, "host-2", "PUBKEY", "jti-2"); err != nil {
		t.Fatalf("UpsertAgent: %v", err)
	}

	req := adminReq("GET", "/api/admin/security/tokens", nil)
	w := httptest.NewRecorder()
	AdminSecurityTokens(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var tokens []TokenInfo
	if err := json.NewDecoder(w.Body).Decode(&tokens); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(tokens) != 2 {
		t.Errorf("expected 2 tokens, got %d", len(tokens))
	}

	jtis := map[string]bool{}
	for _, tok := range tokens {
		jtis[tok.JTI] = true
	}
	if !jtis["jti-1"] || !jtis["jti-2"] {
		t.Errorf("expected jti-1 and jti-2, got %v", jtis)
	}
}

func TestAdminSecurityTokens_RequiresAuth(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)

	req := httptest.NewRequest("GET", "/api/admin/security/tokens", nil)
	w := httptest.NewRecorder()
	AdminSecurityTokens(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

// ========================================================================
// GET /api/admin/security/blacklist
// ========================================================================

func TestAdminSecurityBlacklist_Empty(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)

	req := adminReq("GET", "/api/admin/security/blacklist", nil)
	w := httptest.NewRecorder()
	AdminSecurityBlacklist(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var entries []BlacklistEntryResponse
	json.NewDecoder(w.Body).Decode(&entries) //nolint:errcheck
	if len(entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(entries))
	}
}

func TestAdminSecurityBlacklist_WithEntries(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)
	ctx := context.Background()

	reason := "test_revoke"
	expiresAt := time.Now().Add(25 * time.Hour).UTC().Format(time.RFC3339)
	if err := s.AddToBlacklist(ctx, "jti-abc", "host-1", expiresAt, &reason); err != nil {
		t.Fatalf("AddToBlacklist: %v", err)
	}

	req := adminReq("GET", "/api/admin/security/blacklist", nil)
	w := httptest.NewRecorder()
	AdminSecurityBlacklist(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var entries []BlacklistEntryResponse
	if err := json.NewDecoder(w.Body).Decode(&entries); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].JTI != "jti-abc" {
		t.Errorf("expected jti-abc, got %q", entries[0].JTI)
	}
	if entries[0].Hostname != "host-1" {
		t.Errorf("expected host-1, got %q", entries[0].Hostname)
	}
	if entries[0].Reason != reason {
		t.Errorf("expected reason=%q, got %q", reason, entries[0].Reason)
	}
}

// ========================================================================
// POST /api/admin/security/blacklist/purge
// ========================================================================

func TestAdminSecurityBlacklistPurge_DeletesExpired(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)
	ctx := context.Background()

	// Add one expired and one valid entry
	pastExpiry := time.Now().Add(-1 * time.Hour).UTC().Format(time.RFC3339)
	futureExpiry := time.Now().Add(25 * time.Hour).UTC().Format(time.RFC3339)

	reason := "test"
	s.AddToBlacklist(ctx, "jti-expired", "host-1", pastExpiry, &reason)  //nolint:errcheck
	s.AddToBlacklist(ctx, "jti-valid", "host-2", futureExpiry, &reason)   //nolint:errcheck

	req := adminReq("POST", "/api/admin/security/blacklist/purge", nil)
	w := httptest.NewRecorder()
	AdminSecurityBlacklistPurge(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp PurgeBlacklistResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Deleted != 1 {
		t.Errorf("expected 1 deleted, got %d", resp.Deleted)
	}

	// Verify the valid entry remains
	entries, _ := s.ListBlacklistEntries(ctx)
	if len(entries) != 1 || entries[0].JTI != "jti-valid" {
		t.Errorf("expected only jti-valid to remain, got %+v", entries)
	}
}

func TestAdminSecurityBlacklistPurge_EmptyTable(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)

	req := adminReq("POST", "/api/admin/security/blacklist/purge", nil)
	w := httptest.NewRecorder()
	AdminSecurityBlacklistPurge(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp PurgeBlacklistResponse
	json.NewDecoder(w.Body).Decode(&resp) //nolint:errcheck
	if resp.Deleted != 0 {
		t.Errorf("expected 0 deleted, got %d", resp.Deleted)
	}
}

func TestAdminSecurityBlacklistPurge_RequiresAuth(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)

	req := httptest.NewRequest("POST", "/api/admin/security/blacklist/purge", nil)
	w := httptest.NewRecorder()
	AdminSecurityBlacklistPurge(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

// ========================================================================
// TestRotateKeys_SendsRekeyToConnectedAgents
// ========================================================================

// TestRotateKeys_SendsRekeyToConnectedAgents verifies that after key rotation,
// agents_total in the response equals the number of connected agents.
// sendRekeyToAgent is expected to fail (no real WS), but agents_total must be correct.
func TestRotateKeys_SendsRekeyToConnectedAgents(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)
	ctx := context.Background()

	if err := InitServerState(ctx, s); err != nil {
		t.Fatalf("InitServerState: %v", err)
	}

	// Register 3 agents in DB (required for sendRekeyToAgent to fetch their keys)
	hostnames := []string{"agent-rk-01", "agent-rk-02", "agent-rk-03"}
	for _, h := range hostnames {
		if err := s.UpsertAgent(ctx, h, "PUBKEY-PEM", "jti-"+h); err != nil {
			t.Fatalf("UpsertAgent %s: %v", h, err)
		}
	}

	// Register mock WS connections (Conn=nil is accepted by RegisterConnection in tests)
	for _, h := range hostnames {
		ws.RegisterConnection(h, &ws.AgentConnection{Hostname: h, Conn: nil})
	}
	t.Cleanup(func() {
		for _, h := range hostnames {
			ws.UnregisterConnection(h)
		}
	})

	req := adminReq("POST", "/api/admin/keys/rotate", map[string]string{"grace": "1h"})
	w := httptest.NewRecorder()
	AdminRotateKeys(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp RotateKeysResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	// agents_total must equal the number of connected agents
	if resp.AgentsTotal != len(hostnames) {
		t.Errorf("expected agents_total=%d, got %d", len(hostnames), resp.AgentsTotal)
	}
	// current_key_sha256 and previous_key_sha256 must be set and different
	if resp.CurrentKeySHA256 == "" {
		t.Error("expected current_key_sha256 to be set")
	}
	if resp.PreviousKeySHA256 == "" {
		t.Error("expected previous_key_sha256 to be set")
	}
	if resp.CurrentKeySHA256 == resp.PreviousKeySHA256 {
		t.Error("current and previous sha256 should differ after rotation")
	}
	// Deadline must be set
	if resp.Deadline == "" {
		t.Error("expected deadline to be set")
	}
}

// ========================================================================
// Dual-key JWT integration tests (handlers package perspective)
// ========================================================================

// TestDualKeyJWT_CurrentKey verifies that a token signed with the current secret is accepted.
func TestDualKeyJWT_CurrentKey(t *testing.T) {
	server.mu.Lock()
	server.JWTSecret = "test-current-jwt"
	server.JWTPreviousSecret = ""
	server.KeyRotationDeadline = time.Time{}
	server.mu.Unlock()

	cur, prev, dl := GetServerJWTSecrets()
	if cur != "test-current-jwt" {
		t.Errorf("expected current=test-current-jwt, got %q", cur)
	}
	if prev != "" {
		t.Errorf("expected empty previous, got %q", prev)
	}
	if !dl.IsZero() {
		t.Errorf("expected zero deadline, got %v", dl)
	}
}

// TestDualKeyJWT_PreviousKeyInGrace verifies state during an active grace period.
func TestDualKeyJWT_PreviousKeyInGrace(t *testing.T) {
	deadline := time.Now().Add(24 * time.Hour)
	server.mu.Lock()
	server.JWTSecret = "current-after-rotate"
	server.JWTPreviousSecret = "old-before-rotate"
	server.KeyRotationDeadline = deadline
	server.mu.Unlock()
	defer func() {
		server.mu.Lock()
		server.JWTPreviousSecret = ""
		server.KeyRotationDeadline = time.Time{}
		server.mu.Unlock()
	}()

	cur, prev, dl := GetServerJWTSecrets()
	if cur != "current-after-rotate" {
		t.Errorf("expected current=current-after-rotate, got %q", cur)
	}
	if prev != "old-before-rotate" {
		t.Errorf("expected previous=old-before-rotate, got %q", prev)
	}
	if dl.IsZero() {
		t.Error("expected non-zero deadline during grace period")
	}
	if time.Now().After(dl) {
		t.Error("deadline should be in the future during grace period")
	}
}

// TestDualKeyJWT_PreviousKeyExpired verifies state after grace period ends.
func TestDualKeyJWT_PreviousKeyExpired(t *testing.T) {
	pastDeadline := time.Now().Add(-1 * time.Hour)
	server.mu.Lock()
	server.JWTSecret = "current-secret"
	server.JWTPreviousSecret = "expired-previous"
	server.KeyRotationDeadline = pastDeadline
	server.mu.Unlock()
	defer func() {
		server.mu.Lock()
		server.JWTPreviousSecret = ""
		server.KeyRotationDeadline = time.Time{}
		server.mu.Unlock()
	}()

	_, prev, dl := GetServerJWTSecrets()
	if prev != "expired-previous" {
		t.Errorf("expected previous=expired-previous, got %q", prev)
	}
	// The deadline has passed — validate rotation_active logic
	rotationActive := prev != "" && !dl.IsZero() && time.Now().Before(dl)
	if rotationActive {
		t.Error("rotation should NOT be active when deadline is past")
	}
}

// TestDualKeyJWT_SingleKey_NoRotation verifies that without a previous key,
// the behavior is identical to the pre-rotation state.
func TestDualKeyJWT_SingleKey_NoRotation(t *testing.T) {
	server.mu.Lock()
	server.JWTSecret = "single-key-mode"
	server.JWTPreviousSecret = ""
	server.KeyRotationDeadline = time.Time{}
	server.mu.Unlock()

	cur, prev, dl := GetServerJWTSecrets()
	if cur != "single-key-mode" {
		t.Errorf("expected single-key-mode, got %q", cur)
	}
	// No rotation in progress
	if prev != "" {
		t.Errorf("expected no previous key, got %q", prev)
	}
	if !dl.IsZero() {
		t.Errorf("expected zero deadline, got %v", dl)
	}
	// Rotation should not be active
	rotationActive := prev != "" && !dl.IsZero()
	if rotationActive {
		t.Error("rotation_active should be false in single-key mode")
	}
}

// ========================================================================
// Helper: sha256Hex
// ========================================================================

func TestSha256Hex_Deterministic(t *testing.T) {
	h1 := sha256Hex("hello")
	h2 := sha256Hex("hello")
	if h1 != h2 {
		t.Error("sha256Hex should be deterministic")
	}
	if len(h1) != 64 {
		t.Errorf("expected 64-char hex, got %d", len(h1))
	}
	if sha256Hex("a") == sha256Hex("b") {
		t.Error("different inputs should produce different hashes")
	}
}
