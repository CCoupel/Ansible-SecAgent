package storage

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"secagent-server/cmd/secagent-server/internal/state"
)

// #160: the Store lives on the state file. These tests cover what the move changes: restart,
// volatile data, atomicity, read-only without a guard, no write on the hot paths.

func reopen(t *testing.T, dir string) *Store {
	t.Helper()
	s, err := OpenTestDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestRestart_ReloadsEverythingPermanentAndNothingVolatile(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	s := reopen(t, dir)
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	_, err := s.RegisterAgent(ctx, "h1", "PEM", "jti-1")
	must(err)
	must(s.SetAgentVar(ctx, "h1", "env", "prod"))
	_, err = s.SetSuspended(ctx, "h1", true)
	must(err)
	must(s.AddAuthorizedKey(ctx, "h2", "PEM2", "ci"))
	must(s.CreateEnrollmentToken(ctx, EnrollmentToken{ID: "e1", TokenHash: "he1", HostnamePattern: ".*", CreatedAt: time.Now()}))
	must(s.CreatePluginToken(ctx, PluginToken{ID: "p1", TokenHash: "hp1", CreatedAt: time.Now()}))
	reason := "test"
	must(s.AddToBlacklist(ctx, "bad-jti", "h1", time.Now().Add(time.Hour).Format(time.RFC3339), &reason))
	must(s.ConfigSet(ctx, "key_rotation_deadline", "2026-10-06T00:00:00Z"))
	must(s.UpsertRelayNode(RelayNode{ID: "u1", RelayID: "dmz1", Mode: "pull", TokenHash: "th", Status: "connected"}))
	_, err = s.SetRelayGroupVars("dmz1", `{"site":"paris","n":3}`)
	must(err)
	must(s.SetRelayTokenInfo("dmz1", "relay-jti", time.Now().Add(time.Hour).Unix()))
	// volatile: never reaches a restart
	must(s.BulkUpsertRelayRouting("dmz1", []string{"host-a"}))
	must(s.UpdateRelayStatus("dmz1", "connected", 123))
	_, err = s.SetRelayChain("dmz1", []string{"dmz1"})
	must(err)
	_, err = s.UpdateLastSeen(ctx, "h1")
	must(err)
	_ = s.Close()

	r := reopen(t, dir)
	if a, _ := r.GetAgent(ctx, "h1"); a == nil || a.TokenJTI != "jti-1" || !a.Suspended || a.Vars != `{"env":"prod"}` {
		t.Errorf("agent after restart: %+v", a)
	} else if a.Status != "disconnected" {
		t.Errorf("status is volatile: %q after a restart, want disconnected", a.Status)
	}
	if k, _ := r.GetAuthorizedKey(ctx, "h2"); k == nil || k.PublicKeyPEM != "PEM2" {
		t.Errorf("authorized key lost: %+v", k)
	}
	if tok, _ := r.GetEnrollmentTokenByHash(ctx, "he1"); tok == nil {
		t.Error("enrollment token lost")
	}
	if tok, _ := r.GetPluginTokenByHash(ctx, "hp1"); tok == nil {
		t.Error("plugin token lost")
	}
	if bl, _ := r.IsJTIBlacklisted(ctx, "bad-jti"); !bl {
		t.Error("blacklist lost")
	}
	if v, _ := r.ConfigGet(ctx, "key_rotation_deadline"); v != "2026-10-06T00:00:00Z" {
		t.Errorf("config lost: %q", v)
	}
	n, _ := r.GetRelayNode("dmz1")
	if n == nil || n.TokenHash != "th" || n.Status != "pending" || n.LastSeen != nil {
		t.Errorf("relay node after restart (status/last_seen are volatile): %+v", n)
	}
	if gv, _ := r.ListRelayGroupVars(); gv["dmz1"] != `{"n":3,"site":"paris"}` {
		t.Errorf("group vars: %v", gv)
	}
	if info, _ := r.GetRelayTokenInfo("dmz1"); info.JTI != "relay-jti" {
		t.Errorf("relay token info: %+v", info)
	}
	if routes, _ := r.ListRelayRoutes(); len(routes) != 0 {
		t.Errorf("routing is volatile and must be rebuilt by the children: %v", routes)
	}
	if chains, _ := r.ListRelayChains(); len(chains) != 0 {
		t.Errorf("relay chains are volatile: %v", chains)
	}
}

func TestHotPathsNeverWriteTheDisk(t *testing.T) {
	ctx := context.Background()
	s := reopen(t, t.TempDir())
	if _, err := s.RegisterAgent(ctx, "h1", "PEM", "j"); err != nil {
		t.Fatal(err)
	}
	if err := s.CreatePluginToken(ctx, PluginToken{ID: "p1", TokenHash: "hp1", CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertRelayNode(RelayNode{ID: "u1", RelayID: "dmz1", Mode: "pull"}); err != nil {
		t.Fatal(err)
	}
	before := s.Engine().Writes()
	for i := 0; i < 500; i++ {
		_ = s.TouchPluginToken(ctx, "p1", "10.0.0.1")
		_, _ = s.UpdateLastSeen(ctx, "h1")
		_ = s.UpdateAgentStatus(ctx, "h1", "connected", "")
		_ = s.UpdateRelayStatus("dmz1", "connected", int64(i))
		_ = s.UpsertRelayRouting("host", "dmz1")
		_ = s.BulkUpsertRelayRouting("dmz1", []string{"a", "b"})
		_, _ = s.IsJTIBlacklisted(ctx, "x")
		_, _ = s.GetAgent(ctx, "h1")
		_, _ = s.GetPluginTokenByHash(ctx, "hp1")
	}
	if after := s.Engine().Writes(); after != before {
		t.Errorf("%d disk writes on the hot paths, want 0", after-before)
	}
}

func TestPiggyback_LastUsedIsPersistedWithTheNextWrite(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	s := reopen(t, dir)
	_ = s.CreatePluginToken(ctx, PluginToken{ID: "p1", TokenHash: "hp1", CreatedAt: time.Now()})
	_, _ = s.RegisterAgent(ctx, "h1", "PEM", "j")
	if err := s.TouchPluginToken(ctx, "p1", "192.0.2.7"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpdateLastSeen(ctx, "h1"); err != nil {
		t.Fatal(err)
	}
	// crash before any other write: the use is lost (documented: approximate)
	crashed := reopen(t, dir)
	if tok, _ := crashed.GetPluginTokenByID(ctx, "p1"); tok.LastUsedAt != nil {
		t.Errorf("an unpersisted use survived a restart: %+v", tok)
	}
	// a natural write persists it
	if err := s.AddAuthorizedKey(ctx, "other", "PEM", "ci"); err != nil {
		t.Fatal(err)
	}
	r := reopen(t, dir)
	tok, _ := r.GetPluginTokenByID(ctx, "p1")
	if tok.LastUsedAt == nil || tok.LastUsedIP != "192.0.2.7" {
		t.Errorf("last_used not piggybacked: %+v", tok)
	}
	if a, _ := r.GetAgent(ctx, "h1"); a.LastSeen.IsZero() {
		t.Error("last_seen not piggybacked")
	}
}

func TestEnrollAgent_IsAllOrNothing(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	fail := false
	s0, err := OpenTestDir(dir) // creates the initial state
	if err != nil {
		t.Fatal(err)
	}
	_ = s0
	s, err := Open(state.Options{Dir: dir, InsecureTestMode: true, BeforeWrite: func() error {
		if fail {
			return errors.New("disk refused")
		}
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CreateEnrollmentToken(ctx, EnrollmentToken{ID: "e1", TokenHash: "he1", HostnamePattern: ".*", CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	fail = true
	if err := s.EnrollAgent(ctx, "e1", "h1", "PEM", "jti", "enrollment_token:e1"); err == nil {
		t.Fatal("the write was refused: the enrollment must fail")
	}
	tok, _ := s.GetEnrollmentTokenByID(ctx, "e1")
	a, _ := s.GetAgent(ctx, "h1")
	k, _ := s.GetAuthorizedKey(ctx, "h1")
	if tok.UseCount != 0 || a != nil || k != nil {
		t.Fatalf("partial enrollment: use_count=%d agent=%v key=%v", tok.UseCount, a, k)
	}
	fail = false
	if err := s.EnrollAgent(ctx, "e1", "h1", "PEM", "jti", "enrollment_token:e1"); err != nil {
		t.Fatal(err)
	}
	r := reopen(t, dir)
	tok, _ = r.GetEnrollmentTokenByID(ctx, "e1")
	a, _ = r.GetAgent(ctx, "h1")
	k, _ = r.GetAuthorizedKey(ctx, "h1")
	if tok.UseCount != 1 || a == nil || k == nil || k.ApprovedBy != "enrollment_token:e1" {
		t.Fatalf("enrollment not complete after restart: %+v %+v %+v", tok, a, k)
	}
	// unknown token: nothing is written
	if err := r.EnrollAgent(ctx, "ghost", "h2", "PEM", "j", "x"); err == nil {
		t.Error("an unknown token must fail the enrollment")
	}
	if a, _ := r.GetAgent(ctx, "h2"); a != nil {
		t.Error("an agent was registered by a failed enrollment")
	}
}

func TestRevocations_FlagAndBlacklistAreOneMutation(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	s := reopen(t, dir)
	exp := time.Now().Add(time.Hour).Unix()
	_ = s.UpsertRelayNode(RelayNode{ID: "u1", RelayID: "dmz1", Mode: "pull"})
	_ = s.SetRelayTokenInfo("dmz1", "jti-dmz1", exp)
	if _, found, err := s.RevokeRelayNode(ctx, "dmz1", "test"); err != nil || !found {
		t.Fatal(found, err)
	}
	// a restart sees both (the engine refuses to load a revoked relay that is not blacklisted)
	r := reopen(t, dir)
	if info, _ := r.GetRelayTokenInfo("dmz1"); !info.Revoked {
		t.Error("revoked flag lost")
	}
	if bl, _ := r.IsJTIBlacklisted(ctx, "jti-dmz1"); !bl {
		t.Error("blacklist entry lost")
	}
	// relay-parent token: same
	now := time.Now().UTC().Truncate(time.Second)
	_ = r.CreateRelayParentToken(ctx, RelayParentToken{ID: "t1", JTI: "pjti", ParentID: "central", CreatedAt: now, ExpiresAt: now.Add(time.Hour)})
	if _, found, err := r.RevokeRelayParentToken(ctx, "t1"); err != nil || !found {
		t.Fatal(found, err)
	}
	r2 := reopen(t, dir)
	if tok, _ := r2.GetRelayParentToken(ctx, "t1"); tok == nil || !tok.Revoked() {
		t.Error("parent token revocation lost")
	}
	if bl, _ := r2.IsJTIBlacklisted(ctx, "pjti"); !bl {
		t.Error("parent token jti not blacklisted")
	}
}

func TestPurgeBlacklist_RemovesExpiredEntriesAndWritesNothingWhenThereIsNone(t *testing.T) {
	ctx := context.Background()
	s := reopen(t, t.TempDir())
	now := time.Now().UTC()
	r := "t"
	_ = s.AddToBlacklist(ctx, "old", "h", now.Add(-time.Hour).Format(time.RFC3339), &r)
	_ = s.AddToBlacklist(ctx, "new", "h", now.Add(time.Hour).Format(time.RFC3339), &r)
	w := s.Engine().Writes()
	n, err := s.PurgeBlacklistAt(now)
	if err != nil || n != 1 {
		t.Fatalf("purged %d %v", n, err)
	}
	if bl, _ := s.IsJTIBlacklisted(ctx, "old"); bl {
		t.Error("expired entry still there")
	}
	if bl, _ := s.IsJTIBlacklisted(ctx, "new"); !bl {
		t.Error("live entry purged")
	}
	if s.Engine().Writes() != w+1 {
		t.Error("exactly one write for the purge")
	}
	w = s.Engine().Writes()
	if n, _ := s.PurgeBlacklistAt(now); n != 0 || s.Engine().Writes() != w {
		t.Errorf("nothing to purge must not write (purged %d, writes +%d)", n, s.Engine().Writes()-w)
	}
	// the clock moves: the second entry expires
	if n, _ := s.PurgeBlacklistAt(now.Add(2 * time.Hour)); n != 1 {
		t.Errorf("purged %d at t+2h, want 1", n)
	}
}

func TestWithoutAWriteGuardTheStoreIsReadOnly(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	s0 := reopen(t, dir)
	_, _ = s0.RegisterAgent(ctx, "h1", "PEM", "j")
	before, _ := os.ReadDir(dir)

	ro, err := Open(state.Options{Dir: dir, InsecureTestMode: true}) // no BeforeWrite: not the confirmed master
	if err != nil {
		t.Fatal(err)
	}
	if a, _ := ro.GetAgent(ctx, "h1"); a == nil {
		t.Error("reads must work without a guard")
	}
	for name, err := range map[string]error{
		"RegisterAgent": func() error { _, e := ro.RegisterAgent(ctx, "h2", "P", "j"); return e }(),
		"AddAuthorized": ro.AddAuthorizedKey(ctx, "h3", "P", "ci"),
		"ConfigSet":     ro.ConfigSet(ctx, "k", "v"),
		"UpsertRelay":   ro.UpsertRelayNode(RelayNode{ID: "u", RelayID: "r", Mode: "pull"}),
		"CreateEnroll":  ro.CreateEnrollmentToken(ctx, EnrollmentToken{ID: "e", TokenHash: "h", HostnamePattern: ".*", CreatedAt: time.Now()}),
		"EnrollAgent":   ro.EnrollAgent(ctx, "", "h4", "P", "j", "x"),
	} {
		if !errors.Is(err, ErrReadOnly) {
			t.Errorf("%s without a guard: %v, want ErrReadOnly", name, err)
		}
	}
	after, _ := os.ReadDir(dir)
	if len(after) != len(before) {
		t.Errorf("files changed in a read-only store: %v → %v", before, after)
	}
	// connecting the guard (promotion, #163) enables the writes
	ro.SetWriteGuard(func() error { return nil })
	if err := ro.AddAuthorizedKey(ctx, "h3", "P", "ci"); err != nil {
		t.Fatal(err)
	}
	_ = filepath.Join
}

func TestPushRelayNeedsASealedTokenSecret(t *testing.T) {
	s := reopen(t, t.TempDir())
	if err := s.UpsertRelayNode(RelayNode{ID: "u", RelayID: "p1", Mode: "push", URL: "https://x", TokenSecret: "plaintext-token"}); err == nil {
		t.Error("a clear push token must be refused")
	}
	if err := s.UpsertRelayNode(RelayNode{ID: "u", RelayID: "p1", Mode: "push", URL: "https://x", TokenHash: "h"}); err == nil {
		t.Error("a push relay without token_secret must be refused")
	}
	if err := s.UpsertRelayNode(RelayNode{ID: "u", RelayID: "p1", Mode: "push", URL: "https://x", TokenSecret: "enc:abc"}); err != nil {
		t.Errorf("sealed push relay refused: %v", err)
	}
	if n, _ := s.GetRelayNode("p1"); n == nil || n.TokenSecret != "enc:abc" || n.TokenHash != "" {
		t.Errorf("stored: %+v", n)
	}
}
