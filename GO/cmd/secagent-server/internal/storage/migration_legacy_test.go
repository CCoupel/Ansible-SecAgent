package storage

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
)

// Migration of a REAL v3.0.0 database (schema of c884dde, before the relay tree) populated with
// representative rows: opened by the current code twice, nothing lost, every added column present,
// and the inherited rows still usable.

// legacyDatabase writes a v3.0.0 database file (schema + rows from testdata/legacy_v3_0_0.sql).
func legacyDatabase(t *testing.T) string {
	t.Helper()
	script, err := os.ReadFile("testdata/legacy_v3_0_0.sql")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "legacy.db")
	raw, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(string(script)); err != nil {
		t.Fatalf("load the legacy fixture: %v", err)
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func rawQuery(t *testing.T, path, query string, args ...any) []string {
	t.Helper()
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	rows, err := db.Query(query, args...)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var s sql.NullString
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		out = append(out, s.String)
	}
	return out
}

func columns(t *testing.T, path, table string) map[string]bool {
	t.Helper()
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	rows, err := db.Query("PRAGMA table_info(" + table + ")")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	cols := map[string]bool{}
	for rows.Next() {
		var cid int
		var name, typ string
		var notnull, pk int
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &typ, &notnull, &dflt, &pk); err != nil {
			t.Fatal(err)
		}
		cols[name] = true
	}
	return cols
}

var legacyCounts = map[string]int{
	"agents": 2, "authorized_keys": 1, "blacklist": 1, "server_config": 1, "enrollment_tokens": 1,
	"plugin_tokens": 1, "relay_nodes": 3, "relay_routing": 3,
}

func countRows(t *testing.T, path, table string) int {
	t.Helper()
	n := 0
	for _, s := range rawQuery(t, path, "SELECT COUNT(*) FROM "+table) {
		for _, c := range s {
			n = n*10 + int(c-'0')
		}
	}
	return n
}

func TestLegacyMigration_V300DatabaseIsMigratedIdempotentlyWithoutLosingARow(t *testing.T) {
	path := legacyDatabase(t)
	// the fixture really is the OLD schema: none of the later columns / tables exists yet
	if columns(t, path, "relay_nodes")["jti"] || columns(t, path, "relay_routing")["relay_chain"] || len(columns(t, path, "relay_parent_tokens")) != 0 {
		t.Fatal("the fixture is not a v3.0.0 schema")
	}
	for table, want := range legacyCounts {
		if got := countRows(t, path, table); got != want {
			t.Fatalf("fixture %s has %d rows, want %d", table, got, want)
		}
	}

	for open := 1; open <= 2; open++ { // idempotent: a second open on the migrated file changes nothing
		s, err := NewStore(path)
		if err != nil {
			t.Fatalf("open #%d: %v", open, err)
		}
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
		for _, c := range []struct{ table, col string }{
			{"relay_routing", "hop_type"}, {"relay_routing", "relay_chain"},
			{"relay_nodes", "jti"}, {"relay_nodes", "token_exp"}, {"relay_nodes", "revoked"},
			{"relay_nodes", "group_vars"}, {"relay_nodes", "relay_chain"},
			{"agents", "suspended"}, {"agents", "vars"},
		} {
			if !columns(t, path, c.table)[c.col] {
				t.Errorf("open #%d: column %s.%s was not added by the migration", open, c.table, c.col)
			}
		}
		if len(columns(t, path, "relay_parent_tokens")) == 0 {
			t.Errorf("open #%d: table relay_parent_tokens was not created", open)
		}
		for table, want := range legacyCounts {
			if got := countRows(t, path, table); got != want {
				t.Errorf("open #%d: %s has %d rows after the migration, want %d (a row was lost or duplicated)", open, table, got, want)
			}
		}
	}

	// representative values survive byte for byte
	if got := rawQuery(t, path, "SELECT token_hash FROM relay_nodes WHERE relay_id = 'legacy-push'"); len(got) != 1 || got[0] != "legacy-plain-push-token-0123456789" {
		t.Errorf("the push token stored in clear was rewritten by the migration: %v", got)
	}
	if got := rawQuery(t, path, "SELECT vars FROM agents WHERE hostname = 'agent-a'"); len(got) != 1 || got[0] != `{"env":"prod"}` {
		t.Errorf("agent vars changed: %v", got)
	}
	if got := rawQuery(t, path, "SELECT jti FROM blacklist"); len(got) != 1 || got[0] != "jti-old-revoked" {
		t.Errorf("the blacklist changed: %v", got)
	}
}

func TestLegacyMigration_InheritedRowsStayUsable(t *testing.T) {
	path := legacyDatabase(t)
	s, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	ctx := context.Background()

	// relay without JTI (issued before #153): defined state, then revocation by the FLAG alone
	info, err := s.GetRelayTokenInfo("legacy-pull")
	if err != nil || info.JTI != "" || info.Revoked || info.Exp != 0 {
		t.Fatalf("legacy token info = %+v %v, want no JTI, not revoked", info, err)
	}
	got, found, err := s.RevokeRelayNode(ctx, "legacy-pull", "legacy revoke")
	if err != nil || !found || got.JTI != "" {
		t.Fatalf("RevokeRelayNode(legacy) = %+v found=%v err=%v", got, found, err)
	}
	if info, _ := s.GetRelayTokenInfo("legacy-pull"); !info.Revoked {
		t.Error("a legacy relay must be revoked by the flag alone")
	}
	if n := countRows(t, path, "blacklist"); n != 1 {
		t.Errorf("a legacy revocation has no JTI to blacklist, the blacklist must stay at 1 row, got %d", n)
	}

	// routes without a chain: the next hop falls back to the declaring relay (a direct child)
	for host, relay := range map[string]string{"host-1": "legacy-pull", "host-2": "legacy-pull", "host-3": "legacy-push"} {
		r, err := s.GetRelayRoute(host)
		if err != nil || r == nil {
			t.Fatalf("route of %s lost: %v %v", host, r, err)
		}
		if len(r.RelayChain) != 0 || r.RelayID != relay || r.NextHop() != relay {
			t.Errorf("%s: route = %+v next hop %q, want the direct child %q", host, r, r.NextHop(), relay)
		}
		if hop, err := s.GetNextHopForHostname(host); err != nil || hop != relay {
			t.Errorf("%s: next hop = %q %v, want %q", host, hop, err, relay)
		}
	}
	if hosts, err := s.ListRelayRouting("legacy-pull"); err != nil || len(hosts) != 2 {
		t.Errorf("ListRelayRouting(legacy-pull) = %v %v", hosts, err)
	}

	// the relay node rows are readable with their new columns defaulted
	for _, id := range []string{"legacy-pull", "legacy-push", "legacy-idle"} {
		if n, err := s.GetRelayNode(id); err != nil || n == nil {
			t.Errorf("relay node %s lost: %v %v", id, n, err)
		}
	}
	if blacklisted, err := s.IsJTIBlacklisted(ctx, "jti-old-revoked"); err != nil || !blacklisted {
		t.Errorf("the inherited blacklist entry must still be honoured: %v %v", blacklisted, err)
	}
	// a new write after the migration works (the migrated schema is complete)
	if _, err := s.UpsertRelayRoute("host-new", "legacy-pull", []string{"legacy-pull"}); err != nil {
		t.Errorf("UpsertRelayRoute on a migrated database: %v", err)
	}
}

// State written AFTER the first migration must survive every later start-up: the migration runs
// again at each open of an already-migrated database and must never reset what it did not create
// (revoked flags, JTI / expiry, blacklist, group vars, relay chains, routes with their chains).
func TestLegacyMigration_StateWrittenAfterTheFirstMigrationSurvivesReplays(t *testing.T) {
	path := legacyDatabase(t)
	ctx := context.Background()

	s, err := NewStore(path) // first migration of the v3.0.0 file
	if err != nil {
		t.Fatal(err)
	}
	if _, found, err := s.RevokeRelayNode(ctx, "legacy-pull", "revoked after the first migration"); err != nil || !found {
		t.Fatalf("revoke: found=%v err=%v", found, err)
	}
	if err := s.SetRelayTokenInfo("legacy-push", "jti-after-migration", 4102444800); err != nil {
		t.Fatal(err)
	}
	if err := s.BlacklistJTI(ctx, "jti-blacklisted-after-migration", "legacy-idle", "test", 4102444800); err != nil {
		t.Fatal(err)
	}
	if ok, err := s.SetRelayGroupVars("legacy-idle", `{"env":"staging"}`); err != nil || !ok {
		t.Fatalf("group vars: %v %v", ok, err)
	}
	if ok, err := s.SetRelayChain("legacy-idle", []string{"legacy-pull", "legacy-idle"}); err != nil || !ok {
		t.Fatalf("relay chain: %v %v", ok, err)
	}
	if _, err := s.UpsertRelayRoute("host-deep", "legacy-idle", []string{"legacy-pull", "legacy-idle"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	for open := 2; open <= 4; open++ { // the migration is replayed at every start-up
		s, err := NewStore(path)
		if err != nil {
			t.Fatalf("open #%d: %v", open, err)
		}
		if info, err := s.GetRelayTokenInfo("legacy-pull"); err != nil || !info.Revoked {
			t.Errorf("open #%d: the revoked flag of legacy-pull was reset by the migration: %+v %v", open, info, err)
		}
		if info, err := s.GetRelayTokenInfo("legacy-push"); err != nil || info.JTI != "jti-after-migration" || info.Exp != 4102444800 || info.Revoked {
			t.Errorf("open #%d: jti / token_exp of legacy-push changed by the migration: %+v %v", open, info, err)
		}
		for _, jti := range []string{"jti-blacklisted-after-migration", "jti-old-revoked"} {
			if bl, err := s.IsJTIBlacklisted(ctx, jti); err != nil || !bl {
				t.Errorf("open #%d: blacklist entry %s lost: %v %v", open, jti, bl, err)
			}
		}
		if vars, err := s.ListRelayGroupVars(); err != nil || vars["legacy-idle"] != `{"env":"staging"}` {
			t.Errorf("open #%d: group vars changed by the migration: %v %v", open, vars, err)
		}
		if chains, err := s.ListRelayChains(); err != nil || len(chains["legacy-idle"]) != 2 || chains["legacy-idle"][0] != "legacy-pull" {
			t.Errorf("open #%d: relay chain changed by the migration: %v %v", open, chains, err)
		}
		if r, err := s.GetRelayRoute("host-deep"); err != nil || r == nil || len(r.RelayChain) != 2 || r.NextHop() != "legacy-pull" {
			t.Errorf("open #%d: the route chain written after the migration changed: %+v %v", open, r, err)
		}
		// rows of the original fixture still there
		for table, want := range map[string]int{"agents": 2, "relay_nodes": 3} {
			if got := countRows(t, path, table); got != want {
				t.Errorf("open #%d: %s has %d rows, want %d", open, table, got, want)
			}
		}
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
	}
}
