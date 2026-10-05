package storage

import (
	"database/sql"
	"path/filepath"
	"testing"
)

func TestRelayGroupVars_StoreListClear(t *testing.T) {
	s := newRelayTestStore(t)
	seedNodes(t, s, "dmz1", "dmz2")
	if ok, err := s.SetRelayGroupVars("dmz1", `{"env":"staging"}`); err != nil || !ok {
		t.Fatalf("set: %v %v", ok, err)
	}
	if ok, _ := s.SetRelayGroupVars("ghost", `{"a":1}`); ok {
		t.Error("an unknown relay must report false")
	}
	got, err := s.ListRelayGroupVars()
	if err != nil || len(got) != 1 || got["dmz1"] != `{"env":"staging"}` {
		t.Fatalf("list = %v %v", got, err)
	}
	if _, err := s.SetRelayGroupVars("dmz1", ""); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.ListRelayGroupVars(); len(got) != 0 {
		t.Errorf("cleared vars still listed: %v", got)
	}
}

func TestRelayGroupVars_MigrationKeepsOldDatabases(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")
	raw, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`CREATE TABLE relay_nodes (id TEXT PRIMARY KEY, relay_id TEXT NOT NULL UNIQUE, url TEXT, description TEXT,
			token_hash TEXT, mode TEXT NOT NULL DEFAULT 'pull', is_proxy INTEGER NOT NULL DEFAULT 0,
			created_at INTEGER NOT NULL, last_seen INTEGER, status TEXT NOT NULL DEFAULT 'disconnected')`,
		`INSERT INTO relay_nodes (id, relay_id, created_at) VALUES ('u1', 'old', 1)`,
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
	if ok, err := s.SetRelayGroupVars("old", `{"a":1}`); err != nil || !ok {
		t.Fatalf("set on a migrated database: %v %v", ok, err)
	}
}
