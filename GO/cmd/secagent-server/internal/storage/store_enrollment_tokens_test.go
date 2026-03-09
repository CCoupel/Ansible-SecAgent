package storage

import (
	"context"
	"testing"
	"time"
)

// ========================================================================
// enrollment_tokens
// ========================================================================

func makeToken(id, hash, pattern string, reusable bool, expiresAt *time.Time) EnrollmentToken {
	return EnrollmentToken{
		ID:              id,
		TokenHash:       hash,
		HostnamePattern: pattern,
		Reusable:        reusable,
		CreatedAt:       time.Now().UTC(),
		ExpiresAt:       expiresAt,
		CreatedBy:       "admin-cli",
	}
}

func TestCreateAndGetEnrollmentTokenByHash(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	tok := makeToken("uuid-1", "hash-aaa", "vp.*", false, nil)
	if err := store.CreateEnrollmentToken(ctx, tok); err != nil {
		t.Fatalf("CreateEnrollmentToken: %v", err)
	}

	got, err := store.GetEnrollmentTokenByHash(ctx, "hash-aaa")
	if err != nil {
		t.Fatalf("GetEnrollmentTokenByHash: %v", err)
	}
	if got == nil {
		t.Fatal("expected token, got nil")
	}
	if got.ID != "uuid-1" {
		t.Errorf("ID: got %q, want %q", got.ID, "uuid-1")
	}
	if got.TokenHash != "hash-aaa" {
		t.Errorf("TokenHash: got %q, want %q", got.TokenHash, "hash-aaa")
	}
	if got.HostnamePattern != "vp.*" {
		t.Errorf("HostnamePattern: got %q, want %q", got.HostnamePattern, "vp.*")
	}
	if got.Reusable {
		t.Error("expected Reusable=false for one-shot token")
	}
	if got.UseCount != 0 {
		t.Errorf("UseCount: got %d, want 0", got.UseCount)
	}
	if got.LastUsedAt != nil {
		t.Error("expected LastUsedAt=nil before first use")
	}
	if got.ExpiresAt != nil {
		t.Error("expected ExpiresAt=nil for permanent token")
	}
	if got.CreatedBy != "admin-cli" {
		t.Errorf("CreatedBy: got %q, want %q", got.CreatedBy, "admin-cli")
	}
}

func TestGetEnrollmentTokenByHashNotFound(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	got, err := store.GetEnrollmentTokenByHash(ctx, "nonexistent-hash")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil, got %+v", got)
	}
}

func TestGetEnrollmentTokenByID(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	tok := makeToken("uuid-42", "hash-bbb", "web[0-9]+", true, nil)
	if err := store.CreateEnrollmentToken(ctx, tok); err != nil {
		t.Fatalf("CreateEnrollmentToken: %v", err)
	}

	got, err := store.GetEnrollmentTokenByID(ctx, "uuid-42")
	if err != nil {
		t.Fatalf("GetEnrollmentTokenByID: %v", err)
	}
	if got == nil {
		t.Fatal("expected token, got nil")
	}
	if got.ID != "uuid-42" {
		t.Errorf("ID: got %q, want %q", got.ID, "uuid-42")
	}
	if !got.Reusable {
		t.Error("expected Reusable=true")
	}
}

func TestGetEnrollmentTokenByIDNotFound(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	got, err := store.GetEnrollmentTokenByID(ctx, "nonexistent-uuid")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil, got %+v", got)
	}
}

func TestCreateEnrollmentTokenWithExpiry(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	expiry := time.Now().UTC().Add(24 * time.Hour)
	tok := makeToken("uuid-exp", "hash-exp", ".*-prod-.*", false, &expiry)
	if err := store.CreateEnrollmentToken(ctx, tok); err != nil {
		t.Fatalf("CreateEnrollmentToken: %v", err)
	}

	got, err := store.GetEnrollmentTokenByHash(ctx, "hash-exp")
	if err != nil {
		t.Fatalf("GetEnrollmentTokenByHash: %v", err)
	}
	if got.ExpiresAt == nil {
		t.Fatal("expected ExpiresAt to be set")
	}
	// Allow 2 seconds of rounding due to Unix() conversion
	diff := got.ExpiresAt.Sub(expiry)
	if diff > 2*time.Second || diff < -2*time.Second {
		t.Errorf("ExpiresAt mismatch: got %v, want ~%v", got.ExpiresAt, expiry)
	}
}

func TestListEnrollmentTokens(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	tokens := []EnrollmentToken{
		makeToken("uuid-a", "hash-1", "vp.*", false, nil),
		makeToken("uuid-b", "hash-2", "web.*", true, nil),
		makeToken("uuid-c", "hash-3", ".*", false, nil),
	}
	for _, tok := range tokens {
		if err := store.CreateEnrollmentToken(ctx, tok); err != nil {
			t.Fatalf("CreateEnrollmentToken %s: %v", tok.ID, err)
		}
	}

	list, err := store.ListEnrollmentTokens(ctx)
	if err != nil {
		t.Fatalf("ListEnrollmentTokens: %v", err)
	}
	if len(list) != 3 {
		t.Errorf("expected 3 tokens, got %d", len(list))
	}
}

func TestListEnrollmentTokensEmpty(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	list, err := store.ListEnrollmentTokens(ctx)
	if err != nil {
		t.Fatalf("ListEnrollmentTokens: %v", err)
	}
	// nil or empty slice are both acceptable
	if len(list) != 0 {
		t.Errorf("expected 0 tokens, got %d", len(list))
	}
}

func TestConsumeEnrollmentToken(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	tok := makeToken("uuid-consume", "hash-consume", "vp.*", false, nil)
	if err := store.CreateEnrollmentToken(ctx, tok); err != nil {
		t.Fatalf("CreateEnrollmentToken: %v", err)
	}

	if err := store.ConsumeEnrollmentToken(ctx, "uuid-consume"); err != nil {
		t.Fatalf("ConsumeEnrollmentToken: %v", err)
	}

	got, err := store.GetEnrollmentTokenByHash(ctx, "hash-consume")
	if err != nil {
		t.Fatalf("GetEnrollmentTokenByHash: %v", err)
	}
	if got.UseCount != 1 {
		t.Errorf("UseCount: got %d, want 1", got.UseCount)
	}
	if got.LastUsedAt == nil {
		t.Error("expected LastUsedAt to be set after consumption")
	}
}

func TestConsumeEnrollmentTokenMultipleTimes(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	tok := makeToken("uuid-multi", "hash-multi", "vp.*", true, nil) // reusable
	if err := store.CreateEnrollmentToken(ctx, tok); err != nil {
		t.Fatalf("CreateEnrollmentToken: %v", err)
	}

	for i := 1; i <= 3; i++ {
		if err := store.ConsumeEnrollmentToken(ctx, "uuid-multi"); err != nil {
			t.Fatalf("ConsumeEnrollmentToken iteration %d: %v", i, err)
		}
	}

	got, _ := store.GetEnrollmentTokenByHash(ctx, "hash-multi")
	if got.UseCount != 3 {
		t.Errorf("UseCount: got %d, want 3", got.UseCount)
	}
}

func TestConsumeEnrollmentTokenNotFound(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	err := store.ConsumeEnrollmentToken(ctx, "nonexistent-uuid")
	if err == nil {
		t.Error("expected error for nonexistent token")
	}
}

func TestDeleteEnrollmentToken(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	tok := makeToken("uuid-del", "hash-del", "vp.*", false, nil)
	if err := store.CreateEnrollmentToken(ctx, tok); err != nil {
		t.Fatalf("CreateEnrollmentToken: %v", err)
	}

	deleted, err := store.DeleteEnrollmentToken(ctx, "uuid-del")
	if err != nil {
		t.Fatalf("DeleteEnrollmentToken: %v", err)
	}
	if !deleted {
		t.Error("expected deleted=true")
	}

	got, _ := store.GetEnrollmentTokenByHash(ctx, "hash-del")
	if got != nil {
		t.Error("expected token to be gone after deletion")
	}
}

func TestDeleteEnrollmentTokenNotFound(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	deleted, err := store.DeleteEnrollmentToken(ctx, "nonexistent-uuid")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if deleted {
		t.Error("expected deleted=false for nonexistent token")
	}
}

func TestPurgeExpiredEnrollmentTokens(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	// Expired token
	past := time.Now().UTC().Add(-time.Hour)
	tokExpired := makeToken("uuid-expired", "hash-past", "vp.*", false, &past)
	if err := store.CreateEnrollmentToken(ctx, tokExpired); err != nil {
		t.Fatalf("CreateEnrollmentToken expired: %v", err)
	}

	// Valid token with expiry
	future := time.Now().UTC().Add(time.Hour)
	tokFuture := makeToken("uuid-future", "hash-future", "web.*", false, &future)
	if err := store.CreateEnrollmentToken(ctx, tokFuture); err != nil {
		t.Fatalf("CreateEnrollmentToken future: %v", err)
	}

	// Permanent token (no expiry)
	tokPermanent := makeToken("uuid-perm", "hash-perm", ".*", true, nil)
	if err := store.CreateEnrollmentToken(ctx, tokPermanent); err != nil {
		t.Fatalf("CreateEnrollmentToken permanent: %v", err)
	}

	count, err := store.PurgeExpiredEnrollmentTokens(ctx)
	if err != nil {
		t.Fatalf("PurgeExpiredEnrollmentTokens: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 purged, got %d", count)
	}

	// Expired token should be gone
	got, _ := store.GetEnrollmentTokenByHash(ctx, "hash-past")
	if got != nil {
		t.Error("expected expired token to be purged")
	}

	// Future token should remain
	got, _ = store.GetEnrollmentTokenByHash(ctx, "hash-future")
	if got == nil {
		t.Error("expected future token to remain")
	}

	// Permanent token should remain
	got, _ = store.GetEnrollmentTokenByHash(ctx, "hash-perm")
	if got == nil {
		t.Error("expected permanent token to remain")
	}
}

func TestPurgeUsedOneShotEnrollmentTokens(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	// One-shot consumed
	tokUsed := makeToken("uuid-used", "hash-used", "vp.*", false, nil)
	if err := store.CreateEnrollmentToken(ctx, tokUsed); err != nil {
		t.Fatalf("CreateEnrollmentToken: %v", err)
	}
	if err := store.ConsumeEnrollmentToken(ctx, "uuid-used"); err != nil {
		t.Fatalf("ConsumeEnrollmentToken: %v", err)
	}

	// One-shot not yet consumed
	tokFresh := makeToken("uuid-fresh", "hash-fresh", "web.*", false, nil)
	if err := store.CreateEnrollmentToken(ctx, tokFresh); err != nil {
		t.Fatalf("CreateEnrollmentToken fresh: %v", err)
	}

	// Reusable consumed (must NOT be purged)
	tokReusable := makeToken("uuid-reusable", "hash-reusable", ".*", true, nil)
	if err := store.CreateEnrollmentToken(ctx, tokReusable); err != nil {
		t.Fatalf("CreateEnrollmentToken reusable: %v", err)
	}
	if err := store.ConsumeEnrollmentToken(ctx, "uuid-reusable"); err != nil {
		t.Fatalf("ConsumeEnrollmentToken reusable: %v", err)
	}

	count, err := store.PurgeUsedOneShotEnrollmentTokens(ctx)
	if err != nil {
		t.Fatalf("PurgeUsedOneShotEnrollmentTokens: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 purged, got %d", count)
	}

	// Used one-shot should be gone
	got, _ := store.GetEnrollmentTokenByHash(ctx, "hash-used")
	if got != nil {
		t.Error("expected used one-shot token to be purged")
	}

	// Fresh one-shot should remain
	got, _ = store.GetEnrollmentTokenByHash(ctx, "hash-fresh")
	if got == nil {
		t.Error("expected fresh one-shot token to remain")
	}

	// Reusable should remain (not purged even if consumed)
	got, _ = store.GetEnrollmentTokenByHash(ctx, "hash-reusable")
	if got == nil {
		t.Error("expected reusable token to remain")
	}
}

func TestCreateEnrollmentTokenDuplicateHashRejected(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	tok1 := makeToken("uuid-dup-1", "hash-dup", "vp.*", false, nil)
	if err := store.CreateEnrollmentToken(ctx, tok1); err != nil {
		t.Fatalf("first CreateEnrollmentToken: %v", err)
	}

	// Same token_hash with different ID must fail (UNIQUE constraint)
	tok2 := makeToken("uuid-dup-2", "hash-dup", "web.*", false, nil)
	err := store.CreateEnrollmentToken(ctx, tok2)
	if err == nil {
		t.Error("expected error for duplicate token_hash, got nil")
	}
}
