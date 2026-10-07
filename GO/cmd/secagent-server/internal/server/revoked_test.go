package server

import (
	"context"
	"strings"
	"testing"
	"time"

	"secagent-server/cmd/secagent-server/internal/storage"
)

// The /ws/agent handshake refuses a revoked agent by the persistent flag, whatever the state of the
// blacklist (its entry lasts 25 h, the revocation does not) (#193).
func TestAgentJTICheck_RevokedFlagRefusesEvenWithoutABlacklistEntry(t *testing.T) {
	st, err := storage.OpenTemp()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	ctx := context.Background()
	if err := st.UpsertAgent(ctx, "h1", "pem", "jti-1"); err != nil {
		t.Fatal(err)
	}
	check := agentJTICheck(st)
	if err := check("h1", "jti-1", false); err != nil {
		t.Fatalf("a healthy agent is accepted: %v", err)
	}
	// revoked, and the blacklist entry already expired and purged
	if _, err := st.RevokeAgent(ctx, "h1", "jti-1", "admin_revoke", time.Now().Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := st.PurgeExpiredBlacklist(ctx); err != nil {
		t.Fatal(err)
	}
	if bl, _ := st.IsJTIBlacklisted(ctx, "jti-1"); bl {
		t.Fatal("setup: the entry must be gone")
	}
	for _, prev := range []bool{false, true} {
		if err := check("h1", "jti-1", prev); err == nil || !strings.Contains(err.Error(), "token_revoked") {
			t.Fatalf("usedPrevious=%v: a revoked agent must be refused as token_revoked, got %v", prev, err)
		}
	}
}

// Agents revoked before the flag existed (a blacklisted JTI is all that remembers it) are flagged when
// the master starts: Build repairs the state in one write.
func TestBuild_FlagsTheAgentsRevokedBeforeThePersistentFlag(t *testing.T) {
	dir := seedDB(t, func(st *storage.Store) {
		ctx := context.Background()
		for _, h := range []string{"old-revoked", "fine"} {
			if err := st.UpsertAgent(ctx, h, "pem", "jti-"+h); err != nil {
				t.Fatal(err)
			}
		}
		reason := "admin_revoke"
		if err := st.AddToBlacklist(ctx, "jti-old-revoked", "old-revoked", time.Now().Add(time.Hour).Format(time.RFC3339), &reason); err != nil {
			t.Fatal(err)
		}
	})
	n := buildWith(t, dir, nil)
	ctx := context.Background()
	if r, _ := n.store.IsAgentRevoked(ctx, "old-revoked"); !r {
		t.Error("the pre-flag revocation must be flagged by the start of the master")
	}
	if r, _ := n.store.IsAgentRevoked(ctx, "fine"); r {
		t.Error("a healthy agent must not be flagged")
	}
}
