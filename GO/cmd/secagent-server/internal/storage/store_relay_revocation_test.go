package storage

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"
)

func TestRelayRevocation_TokenInfoRoundTripAndMigration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	raw, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`CREATE TABLE relay_nodes (id TEXT PRIMARY KEY, relay_id TEXT NOT NULL UNIQUE, url TEXT, description TEXT,
			token_hash TEXT, mode TEXT NOT NULL DEFAULT 'pull', is_proxy INTEGER NOT NULL DEFAULT 0,
			created_at INTEGER NOT NULL, last_seen INTEGER, status TEXT NOT NULL DEFAULT 'disconnected')`,
		`INSERT INTO relay_nodes (id, relay_id, created_at) VALUES ('u1', 'legacy', 1)`,
	} {
		if _, err := raw.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	_ = raw.Close()

	s, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	// legacy row survives the migration with a defined state: no JTI, not revoked
	info, err := s.GetRelayTokenInfo("legacy")
	if err != nil || info.JTI != "" || info.Revoked || info.Exp != 0 {
		t.Fatalf("legacy info = %+v %v", info, err)
	}
	if n, _ := s.GetRelayNode("legacy"); n == nil {
		t.Fatal("legacy row lost")
	}
	if err := s.SetRelayTokenInfo("legacy", "jti-9", 123456); err != nil {
		t.Fatal(err)
	}
	if info, _ := s.GetRelayTokenInfo("legacy"); info.JTI != "jti-9" || info.Exp != 123456 {
		t.Errorf("info = %+v", info)
	}
	if err := s.SetRelayTokenInfo("nobody", "x", 1); err == nil {
		t.Error("unknown relay must be an error")
	}
	if info, err := s.GetRelayTokenInfo("nobody"); err != nil || info != (RelayTokenInfo{}) {
		t.Errorf("unknown relay info = %+v %v", info, err)
	}
	// re-opening (columns already there) must not fail
	s2, err := NewStore(path)
	if err != nil {
		t.Fatalf("re-open: %v", err)
	}
	_ = s2.Close()
}

func TestRelayRevocation_RevokeBlacklistsAndFlags(t *testing.T) {
	s := newRelayTestStore(t)
	ctx := context.Background()
	seedNodes(t, s, "dmz1", "dmz2")
	exp := time.Now().Add(24 * time.Hour).Unix()
	if err := s.SetRelayTokenInfo("dmz1", "jti-dmz1", exp); err != nil {
		t.Fatal(err)
	}
	info, found, err := s.RevokeRelayNode(ctx, "dmz1", "admin revoke")
	if err != nil || !found || info.JTI != "jti-dmz1" {
		t.Fatalf("revoke = %+v %v %v", info, found, err)
	}
	if bl, _ := s.IsJTIBlacklisted(ctx, "jti-dmz1"); !bl {
		t.Error("JTI must be blacklisted")
	}
	if got, _ := s.GetRelayTokenInfo("dmz1"); !got.Revoked {
		t.Error("relay must be flagged revoked")
	}
	// other relays untouched
	if other, _ := s.GetRelayTokenInfo("dmz2"); other.Revoked {
		t.Error("dmz2 must not be affected")
	}
	// idempotent
	if _, found, err := s.RevokeRelayNode(ctx, "dmz1", "again"); err != nil || !found {
		t.Errorf("second revoke: %v %v", found, err)
	}
	// fresh token re-enables the relay
	if err := s.SetRelayTokenInfo("dmz1", "jti-new", exp); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.GetRelayTokenInfo("dmz1"); got.Revoked || got.JTI != "jti-new" {
		t.Errorf("after re-issue: %+v", got)
	}
	if bl, _ := s.IsJTIBlacklisted(ctx, "jti-dmz1"); !bl {
		t.Error("the old JTI must stay blacklisted")
	}
}

func TestRelayRevocation_LegacyRelayWithoutJTIIsFlaggedNotBlacklisted(t *testing.T) {
	s := newRelayTestStore(t)
	seedNodes(t, s, "legacy")
	info, found, err := s.RevokeRelayNode(context.Background(), "legacy", "r")
	if err != nil || !found || info.JTI != "" {
		t.Fatalf("revoke = %+v %v %v", info, found, err)
	}
	if got, _ := s.GetRelayTokenInfo("legacy"); !got.Revoked {
		t.Error("a legacy relay must still be flagged revoked (the flag alone makes /ws/relay refuse it)")
	}
	if _, found, _ := s.RevokeRelayNode(context.Background(), "ghost", "r"); found {
		t.Error("unknown relay: found must be false")
	}
}
