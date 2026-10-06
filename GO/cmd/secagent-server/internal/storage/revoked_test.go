package storage

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"secagent-server/cmd/secagent-server/internal/state"
)

func revokedStore(t *testing.T) *Store {
	t.Helper()
	s, err := OpenTemp()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if err := s.UpsertAgent(context.Background(), "h1", "pem", "jti-1"); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestRevokeAgent_FlagAndBlacklistInOneWrite(t *testing.T) {
	s := revokedStore(t)
	ctx := context.Background()
	writes := s.Engine().Writes()
	found, err := s.RevokeAgent(ctx, "h1", "jti-1", "admin_revoke", time.Now().Add(25*time.Hour))
	if err != nil || !found {
		t.Fatalf("revoke: %v %v", found, err)
	}
	if got := s.Engine().Writes() - writes; got != 1 {
		t.Errorf("%d state writes, want exactly ONE (flag and blacklist together)", got)
	}
	if r, _ := s.IsAgentRevoked(ctx, "h1"); !r {
		t.Error("the agent must carry the persistent flag")
	}
	if bl, _ := s.IsJTIBlacklisted(ctx, "jti-1"); !bl {
		t.Error("the JTI must be blacklisted")
	}
	// unknown agent: nothing written
	w := s.Engine().Writes()
	if found, err := s.RevokeAgent(ctx, "nobody", "x", "r", time.Now().Add(time.Hour)); err != nil || found {
		t.Errorf("unknown agent: %v %v", found, err)
	}
	if s.Engine().Writes() != w+1 && s.Engine().Writes() != w { // an empty mutation may or may not write; it must not flag anything
		t.Error("unexpected writes")
	}
	if r, _ := s.IsAgentRevoked(ctx, "nobody"); r {
		t.Error("an unknown agent cannot be revoked")
	}
}

func TestRevokedAgent_EnrollmentIsRefusedAndConsumesNothing(t *testing.T) {
	s := revokedStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	if err := s.CreateEnrollmentToken(ctx, EnrollmentToken{ID: "t1", TokenHash: "h", HostnamePattern: ".*", Reusable: true, CreatedAt: now, CreatedBy: "t"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RevokeAgent(ctx, "h1", "jti-1", "admin_revoke", now.Add(25*time.Hour)); err != nil {
		t.Fatal(err)
	}
	before, _ := s.GetAgent(ctx, "h1")
	tokBefore, _ := s.GetEnrollmentTokenByID(ctx, "t1")
	writes := s.Engine().Writes()

	if err := s.EnrollAgent(ctx, "t1", "h1", "pem2", "jti-new", "test"); !errors.Is(err, ErrAgentRevoked) {
		t.Fatalf("EnrollAgent on a revoked host: %v, want ErrAgentRevoked", err)
	}
	if _, err := s.RegisterAgent(ctx, "h1", "pem2", "jti-new"); !errors.Is(err, ErrAgentRevoked) {
		t.Fatalf("RegisterAgent on a revoked host: %v, want ErrAgentRevoked", err)
	}
	after, _ := s.GetAgent(ctx, "h1")
	if after.TokenJTI != before.TokenJTI || after.PublicKeyPEM != before.PublicKeyPEM || !after.Revoked {
		t.Errorf("the revoked agent changed: %+v -> %+v", before, after)
	}
	tokAfter, _ := s.GetEnrollmentTokenByID(ctx, "t1")
	if tokAfter.UseCount != tokBefore.UseCount {
		t.Errorf("the token was consumed (%d -> %d)", tokBefore.UseCount, tokAfter.UseCount)
	}
	if s.Engine().Writes() != writes {
		t.Error("a refused enrollment must write nothing")
	}
}

// The flag outlives the blacklist entry (retention 25 h): purging the expired entries leaves the host revoked.
func TestRevokedFlag_SurvivesTheExpiryOfTheBlacklistEntry(t *testing.T) {
	s := revokedStore(t)
	ctx := context.Background()
	if _, err := s.RevokeAgent(ctx, "h1", "jti-1", "admin_revoke", time.Now().Add(-time.Hour)); err != nil { // already expired
		t.Fatal(err)
	}
	if _, err := s.PurgeExpiredBlacklist(ctx); err != nil {
		t.Fatal(err)
	}
	if bl, _ := s.IsJTIBlacklisted(ctx, "jti-1"); bl {
		t.Fatal("setup: the entry must be purged")
	}
	if r, _ := s.IsAgentRevoked(ctx, "h1"); !r {
		t.Fatal("the persistent flag must outlive the blacklist entry")
	}
	if err := s.EnrollAgent(ctx, "", "h1", "pem", "j", "t"); !errors.Is(err, ErrAgentRevoked) {
		t.Fatalf("a host whose blacklist entry expired must still be refused: %v", err)
	}
}

// An explicit admin action lifts it: deleting the agent, then enrolling again.
func TestRevokedFlag_IsLiftedByDeletingTheAgent(t *testing.T) {
	s := revokedStore(t)
	ctx := context.Background()
	if _, err := s.RevokeAgent(ctx, "h1", "jti-1", "admin_revoke", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if ok, err := s.DeleteAgent(ctx, "h1"); err != nil || !ok {
		t.Fatalf("delete: %v %v", ok, err)
	}
	if err := s.EnrollAgent(ctx, "", "h1", "pem", "jti-new", "t"); err != nil {
		t.Fatalf("after the explicit lifting the host can enroll again: %v", err)
	}
	if r, _ := s.IsAgentRevoked(ctx, "h1"); r {
		t.Error("the new enrollment must not be flagged")
	}
}

// Agents revoked BEFORE the flag existed (only their blacklisted JTI remembers it) are flagged once.
func TestRepairRevokedFlags(t *testing.T) {
	s := revokedStore(t)
	ctx := context.Background()
	for _, h := range []string{"old-revoked", "healthy"} {
		if err := s.UpsertAgent(ctx, h, "pem", "jti-"+h); err != nil {
			t.Fatal(err)
		}
	}
	reason := "admin_revoke"
	if err := s.AddToBlacklist(ctx, "jti-old-revoked", "old-revoked", time.Now().Add(time.Hour).Format(time.RFC3339), &reason); err != nil {
		t.Fatal(err)
	}
	writes := s.Engine().Writes()
	n, err := s.RepairRevokedFlags(ctx)
	if err != nil || n != 1 {
		t.Fatalf("repair: %d %v, want 1", n, err)
	}
	if r, _ := s.IsAgentRevoked(ctx, "old-revoked"); !r {
		t.Error("the pre-flag revocation must be flagged")
	}
	for _, h := range []string{"healthy", "h1"} {
		if r, _ := s.IsAgentRevoked(ctx, h); r {
			t.Errorf("%s must not be flagged", h)
		}
	}
	if s.Engine().Writes() != writes+1 {
		t.Error("the repair is ONE write")
	}
	w := s.Engine().Writes()
	if n, err := s.RepairRevokedFlags(ctx); err != nil || n != 0 || s.Engine().Writes() != w {
		t.Errorf("a second pass must find nothing and write nothing: %d %v", n, err)
	}
}

// Compatibility of the state format: the field is optional at read (a state written by an older build
// has no "revoked"), omitted when false (an older build keeps reading a state nobody was revoked in),
// and persisted across a reopen.
func TestRevokedField_FormatCompatibilityAndPersistence(t *testing.T) {
	plain, _ := json.Marshal(state.Agent{Hostname: "h"})
	if strings.Contains(string(plain), "revoked") {
		t.Errorf("a non-revoked agent must not serialize the field: %s", plain)
	}
	flagged, _ := json.Marshal(state.Agent{Hostname: "h", Revoked: true})
	if !strings.Contains(string(flagged), `"revoked":true`) {
		t.Errorf("a revoked agent must serialize the field: %s", flagged)
	}
	var old state.Agent
	if err := json.Unmarshal([]byte(`{"hostname":"h","public_key_pem":"p","enrolled_at":"2026-01-01T00:00:00Z"}`), &old); err != nil || old.Revoked {
		t.Errorf("an agent written without the field reads as not revoked: %+v %v", old, err)
	}

	dir := t.TempDir()
	s, err := OpenTestDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := s.UpsertAgent(ctx, "h1", "pem", "jti-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RevokeAgent(ctx, "h1", "jti-1", "r", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	s2, err := OpenTestDir(dir) // a restart (kill -9 after the acknowledged revocation leaves the same file)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s2.Close() }()
	if r, _ := s2.IsAgentRevoked(ctx, "h1"); !r {
		t.Error("the revocation must survive a reopen of the state")
	}
}
