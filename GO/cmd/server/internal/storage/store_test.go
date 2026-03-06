package storage

import (
	"context"
	"testing"
	"time"
)

// newTestStore creates an in-memory SQLite store for testing
func newTestStore(t *testing.T) *Store {
	t.Helper()
	store, err := NewStore(":memory:")
	if err != nil {
		t.Fatalf("failed to create test store: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	return store
}

// ========================================================================
// authorized_keys
// ========================================================================

func TestAddAndGetAuthorizedKey(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	err := store.AddAuthorizedKey(ctx, "host-a", "---PEM---", "ci-bot")
	if err != nil {
		t.Fatalf("AddAuthorizedKey: %v", err)
	}

	rec, err := store.GetAuthorizedKey(ctx, "host-a")
	if err != nil {
		t.Fatalf("GetAuthorizedKey: %v", err)
	}
	if rec == nil {
		t.Fatal("expected record, got nil")
	}
	if rec.Hostname != "host-a" {
		t.Errorf("hostname: got %q, want %q", rec.Hostname, "host-a")
	}
	if rec.PublicKeyPEM != "---PEM---" {
		t.Errorf("public_key_pem: got %q, want %q", rec.PublicKeyPEM, "---PEM---")
	}
	if rec.ApprovedBy != "ci-bot" {
		t.Errorf("approved_by: got %q, want %q", rec.ApprovedBy, "ci-bot")
	}
}

func TestGetAuthorizedKeyNotFound(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	rec, err := store.GetAuthorizedKey(ctx, "nonexistent")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rec != nil {
		t.Errorf("expected nil, got %+v", rec)
	}
}

func TestAddAuthorizedKeyUpsert(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	// First insert
	err := store.AddAuthorizedKey(ctx, "host-a", "---PEM-1---", "bot-1")
	if err != nil {
		t.Fatalf("first AddAuthorizedKey: %v", err)
	}

	// Upsert with new data
	err = store.AddAuthorizedKey(ctx, "host-a", "---PEM-2---", "bot-2")
	if err != nil {
		t.Fatalf("second AddAuthorizedKey: %v", err)
	}

	rec, err := store.GetAuthorizedKey(ctx, "host-a")
	if err != nil {
		t.Fatalf("GetAuthorizedKey: %v", err)
	}
	if rec.PublicKeyPEM != "---PEM-2---" {
		t.Errorf("expected updated PEM, got %q", rec.PublicKeyPEM)
	}
	if rec.ApprovedBy != "bot-2" {
		t.Errorf("expected updated approved_by, got %q", rec.ApprovedBy)
	}
}

func TestRevokeKey(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	err := store.AddAuthorizedKey(ctx, "host-a", "---PEM---", "ci")
	if err != nil {
		t.Fatalf("AddAuthorizedKey: %v", err)
	}

	deleted, err := store.RevokeKey(ctx, "host-a")
	if err != nil {
		t.Fatalf("RevokeKey: %v", err)
	}
	if !deleted {
		t.Error("expected deleted=true")
	}

	// Verify it's gone
	rec, err := store.GetAuthorizedKey(ctx, "host-a")
	if err != nil {
		t.Fatalf("GetAuthorizedKey after revoke: %v", err)
	}
	if rec != nil {
		t.Error("expected nil after revoke")
	}
}

func TestRevokeKeyNotFound(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	deleted, err := store.RevokeKey(ctx, "nonexistent")
	if err != nil {
		t.Fatalf("RevokeKey: %v", err)
	}
	if deleted {
		t.Error("expected deleted=false for nonexistent key")
	}
}

// ========================================================================
// agents
// ========================================================================

func TestRegisterAndGetAgent(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	_, err := store.RegisterAgent(ctx, "host-a", "---PEM---", "jti-1")
	if err != nil {
		t.Fatalf("RegisterAgent: %v", err)
	}

	rec, err := store.GetAgent(ctx, "host-a")
	if err != nil {
		t.Fatalf("GetAgent: %v", err)
	}
	if rec == nil {
		t.Fatal("expected record, got nil")
	}
	if rec.Hostname != "host-a" {
		t.Errorf("hostname: got %q, want %q", rec.Hostname, "host-a")
	}
	if rec.TokenJTI != "jti-1" {
		t.Errorf("token_jti: got %q, want %q", rec.TokenJTI, "jti-1")
	}
	if rec.Status != "disconnected" {
		t.Errorf("status after register: got %q, want %q", rec.Status, "disconnected")
	}
}

func TestGetAgentNotFound(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	rec, err := store.GetAgent(ctx, "nonexistent")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rec != nil {
		t.Errorf("expected nil, got %+v", rec)
	}
}

func TestRegisterAgentUpsert(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	_, err := store.RegisterAgent(ctx, "host-a", "---PEM-1---", "jti-1")
	if err != nil {
		t.Fatalf("first RegisterAgent: %v", err)
	}

	// Re-enroll with new key
	_, err = store.RegisterAgent(ctx, "host-a", "---PEM-2---", "jti-2")
	if err != nil {
		t.Fatalf("second RegisterAgent: %v", err)
	}

	rec, err := store.GetAgent(ctx, "host-a")
	if err != nil {
		t.Fatalf("GetAgent: %v", err)
	}
	if rec.PublicKeyPEM != "---PEM-2---" {
		t.Errorf("expected updated PEM, got %q", rec.PublicKeyPEM)
	}
	if rec.TokenJTI != "jti-2" {
		t.Errorf("expected updated JTI, got %q", rec.TokenJTI)
	}
}

func TestUpsertAgentAlias(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	err := store.UpsertAgent(ctx, "host-b", "---PEM---", "jti-99")
	if err != nil {
		t.Fatalf("UpsertAgent: %v", err)
	}

	rec, err := store.GetAgent(ctx, "host-b")
	if err != nil {
		t.Fatalf("GetAgent: %v", err)
	}
	if rec == nil {
		t.Fatal("expected record")
	}
}

func TestListAgentsAll(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	for _, h := range []string{"host-1", "host-2", "host-3"} {
		_, err := store.RegisterAgent(ctx, h, "---PEM---", "jti-"+h)
		if err != nil {
			t.Fatalf("RegisterAgent %s: %v", h, err)
		}
	}

	agents, err := store.ListAgents(ctx, false)
	if err != nil {
		t.Fatalf("ListAgents: %v", err)
	}
	if len(agents) != 3 {
		t.Errorf("expected 3 agents, got %d", len(agents))
	}
}

func TestListAgentsOnlyConnected(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	for _, h := range []string{"host-1", "host-2", "host-3"} {
		_, err := store.RegisterAgent(ctx, h, "---PEM---", "jti-"+h)
		if err != nil {
			t.Fatalf("RegisterAgent: %v", err)
		}
	}

	// Mark host-1 as connected
	ok, err := store.UpdateLastSeen(ctx, "host-1")
	if err != nil {
		t.Fatalf("UpdateLastSeen: %v", err)
	}
	if !ok {
		t.Error("expected UpdateLastSeen to return true")
	}

	agents, err := store.ListAgents(ctx, true)
	if err != nil {
		t.Fatalf("ListAgents connected: %v", err)
	}
	if len(agents) != 1 {
		t.Errorf("expected 1 connected agent, got %d", len(agents))
	}
	if agents[0].Hostname != "host-1" {
		t.Errorf("expected host-1, got %q", agents[0].Hostname)
	}
}

func TestUpdateLastSeenSetsConnected(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	_, err := store.RegisterAgent(ctx, "host-a", "---PEM---", "jti-1")
	if err != nil {
		t.Fatalf("RegisterAgent: %v", err)
	}

	ok, err := store.UpdateLastSeen(ctx, "host-a")
	if err != nil {
		t.Fatalf("UpdateLastSeen: %v", err)
	}
	if !ok {
		t.Error("expected true")
	}

	rec, _ := store.GetAgent(ctx, "host-a")
	if rec.Status != "connected" {
		t.Errorf("expected connected, got %q", rec.Status)
	}
}

func TestUpdateLastSeenNotFound(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	ok, err := store.UpdateLastSeen(ctx, "nonexistent")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Error("expected false for nonexistent agent")
	}
}

func TestUpdateAgentStatus(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	_, err := store.RegisterAgent(ctx, "host-a", "---PEM---", "jti-1")
	if err != nil {
		t.Fatalf("RegisterAgent: %v", err)
	}

	err = store.UpdateAgentStatus(ctx, "host-a", "connected", "")
	if err != nil {
		t.Fatalf("UpdateAgentStatus: %v", err)
	}

	rec, _ := store.GetAgent(ctx, "host-a")
	if rec.Status != "connected" {
		t.Errorf("expected connected, got %q", rec.Status)
	}

	err = store.UpdateAgentStatus(ctx, "host-a", "disconnected", "")
	if err != nil {
		t.Fatalf("UpdateAgentStatus: %v", err)
	}

	rec, _ = store.GetAgent(ctx, "host-a")
	if rec.Status != "disconnected" {
		t.Errorf("expected disconnected, got %q", rec.Status)
	}
}

func TestUpdateAgentStatusWithTimestamp(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	_, err := store.RegisterAgent(ctx, "host-a", "---PEM---", "jti-1")
	if err != nil {
		t.Fatalf("RegisterAgent: %v", err)
	}

	ts := "2026-01-01T00:00:00Z"
	err = store.UpdateAgentStatus(ctx, "host-a", "connected", ts)
	if err != nil {
		t.Fatalf("UpdateAgentStatus with ts: %v", err)
	}
}

func TestUpdateTokenJTI(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	_, err := store.RegisterAgent(ctx, "host-a", "---PEM---", "jti-old")
	if err != nil {
		t.Fatalf("RegisterAgent: %v", err)
	}

	ok, err := store.UpdateTokenJTI(ctx, "host-a", "jti-new")
	if err != nil {
		t.Fatalf("UpdateTokenJTI: %v", err)
	}
	if !ok {
		t.Error("expected true")
	}

	rec, _ := store.GetAgent(ctx, "host-a")
	if rec.TokenJTI != "jti-new" {
		t.Errorf("expected jti-new, got %q", rec.TokenJTI)
	}
}

func TestUpdateTokenJTINotFound(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	ok, err := store.UpdateTokenJTI(ctx, "nonexistent", "jti-new")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Error("expected false for nonexistent agent")
	}
}

// ========================================================================
// blacklist
// ========================================================================

func TestAddAndCheckBlacklist(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	future := time.Now().UTC().Add(time.Hour).Format(time.RFC3339)
	reason := "test revocation"

	err := store.AddToBlacklist(ctx, "jti-abc", "host-a", future, &reason)
	if err != nil {
		t.Fatalf("AddToBlacklist: %v", err)
	}

	blacklisted, err := store.IsJTIBlacklisted(ctx, "jti-abc")
	if err != nil {
		t.Fatalf("IsJTIBlacklisted: %v", err)
	}
	if !blacklisted {
		t.Error("expected jti to be blacklisted")
	}
}

func TestIsJTIBlacklistedNotFound(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	blacklisted, err := store.IsJTIBlacklisted(ctx, "unknown-jti")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if blacklisted {
		t.Error("expected false for unknown jti")
	}
}

func TestAddToBlacklistNilReason(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	future := time.Now().UTC().Add(time.Hour).Format(time.RFC3339)

	err := store.AddToBlacklist(ctx, "jti-xyz", "host-a", future, nil)
	if err != nil {
		t.Fatalf("AddToBlacklist with nil reason: %v", err)
	}

	blacklisted, _ := store.IsJTIBlacklisted(ctx, "jti-xyz")
	if !blacklisted {
		t.Error("expected blacklisted")
	}
}

func TestAddToBlacklistIdempotent(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	future := time.Now().UTC().Add(time.Hour).Format(time.RFC3339)
	reason := "duplicate"

	// First insert
	err := store.AddToBlacklist(ctx, "jti-dup", "host-a", future, &reason)
	if err != nil {
		t.Fatalf("first AddToBlacklist: %v", err)
	}

	// Second insert (ON CONFLICT DO NOTHING)
	err = store.AddToBlacklist(ctx, "jti-dup", "host-a", future, &reason)
	if err != nil {
		t.Fatalf("second AddToBlacklist (idempotent): %v", err)
	}
}

func TestPurgeExpiredBlacklist(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	// Add expired entry
	past := time.Now().UTC().Add(-time.Hour).Format(time.RFC3339)
	reason := "expired"
	err := store.AddToBlacklist(ctx, "jti-expired", "host-a", past, &reason)
	if err != nil {
		t.Fatalf("AddToBlacklist expired: %v", err)
	}

	// Add valid entry
	future := time.Now().UTC().Add(time.Hour).Format(time.RFC3339)
	err = store.AddToBlacklist(ctx, "jti-valid", "host-a", future, nil)
	if err != nil {
		t.Fatalf("AddToBlacklist valid: %v", err)
	}

	count, err := store.PurgeExpiredBlacklist(ctx)
	if err != nil {
		t.Fatalf("PurgeExpiredBlacklist: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 purged, got %d", count)
	}

	// Verify expired is gone
	bl, _ := store.IsJTIBlacklisted(ctx, "jti-expired")
	if bl {
		t.Error("expected expired jti to be purged")
	}

	// Verify valid is still there
	bl, _ = store.IsJTIBlacklisted(ctx, "jti-valid")
	if !bl {
		t.Error("expected valid jti to remain")
	}
}

func TestCleanupExpiredBlacklistAlias(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	past := time.Now().UTC().Add(-time.Hour).Format(time.RFC3339)
	reason := "old"
	_ = store.AddToBlacklist(ctx, "jti-old", "host-a", past, &reason)

	count, err := store.CleanupExpiredBlacklist(ctx)
	if err != nil {
		t.Fatalf("CleanupExpiredBlacklist: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1, got %d", count)
	}
}

// ========================================================================
// DDL idempotency
// ========================================================================

func TestNewStoreIdempotent(t *testing.T) {
	// Opening the same in-memory store twice is independent — but we can test
	// that creating a second store from scratch runs DDL without error
	store1 := newTestStore(t)
	store2 := newTestStore(t)

	ctx := context.Background()
	_ = store1.AddAuthorizedKey(ctx, "h1", "pem", "bot")
	_ = store2.AddAuthorizedKey(ctx, "h1", "pem", "bot")
}
