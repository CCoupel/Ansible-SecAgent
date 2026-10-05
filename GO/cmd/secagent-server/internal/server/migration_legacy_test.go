package server

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// The REAL start-up sequence (Build + Run) on a v3.0.0 database (schema of c884dde with
// representative rows, shared with the storage tests): the server starts, the inherited relays are
// still usable and the push token stored in clear is read as before and never rewritten.

func legacyDatabaseFile(t *testing.T) string {
	t.Helper()
	script, err := os.ReadFile("../storage/testdata/legacy_v3_0_0.sql")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "legacy.db")
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(string(script)); err != nil {
		t.Fatalf("load the legacy fixture: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func scalar(t *testing.T, path, query string) string {
	t.Helper()
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	var s sql.NullString
	if err := db.QueryRow(query).Scan(&s); err != nil {
		t.Fatal(err)
	}
	return s.String
}

func relayToken(t *testing.T, relayID string) string {
	t.Helper()
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": relayID, "role": "relay", "jti": "legacy-jti-" + relayID,
		"iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(),
	}).SignedString([]byte("legacy-secret")) // the secret persisted in the legacy server_config wins over the environment
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func TestLegacyDatabase_NodeStartsAndInheritedRowsStayUsable(t *testing.T) {
	path := legacyDatabaseFile(t)
	pushBefore := scalar(t, path, "SELECT token_hash FROM relay_nodes WHERE relay_id = 'legacy-push'")

	n, _, admin, wsAddr := startNode(t, func(c *Config) { c.DatabaseURL = path })

	// the inherited routes (without hop_type / relay_chain) are still in the table at start-up
	for relay, want := range map[string]string{"legacy-pull": "2", "legacy-push": "1"} {
		if got := scalar(t, path, "SELECT COUNT(*) FROM relay_routing WHERE relay_id = '"+relay+"'"); got != want {
			t.Errorf("routes of %s after start-up: %s rows, want %s", relay, got, want)
		}
	}

	// every inherited relay is listed
	code, body := adminCall(t, admin, "GET", "/api/admin/relays", nil)
	if code != http.StatusOK {
		t.Fatalf("list relays: %d %s", code, body)
	}
	for _, id := range []string{"legacy-pull", "legacy-push", "legacy-idle"} {
		if !contains(string(body), `"`+id+`"`) {
			t.Errorf("relay %s lost by the migration: %s", id, body)
		}
	}

	// the push relay stored in CLEAR is read as before: its dialer runs, and the row is never rewritten
	found := false
	for _, s := range n.dialers.Statuses() {
		found = found || s.RelayID == "legacy-push"
	}
	if !found {
		t.Error("the dialer of the legacy push relay (token stored in clear) was not started")
	}
	if got := scalar(t, path, "SELECT token_hash FROM relay_nodes WHERE relay_id = 'legacy-push'"); got != pushBefore {
		t.Errorf("the push token was rewritten: %q → %q", pushBefore, got)
	}

	// a legacy pull relay (no JTI) can still connect with a token signed by this node...
	c, status, err := dialRelayWS(wsAddr, relayToken(t, "legacy-pull"))
	if err != nil {
		t.Fatalf("a legacy relay must still be able to connect: %v (HTTP %d)", err, status)
	}
	_ = c.Close()

	// ...it cannot be DELETED without being revoked first (its token has no JTI to blacklist)...
	var listed struct {
		Relays []map[string]any `json:"relays"`
	}
	_ = json.Unmarshal(body, &listed)
	rowID := ""
	for _, r := range listed.Relays {
		if r["relay_id"] == "legacy-pull" {
			rowID, _ = r["id"].(string)
		}
	}
	if rowID == "" {
		t.Fatalf("the legacy relay row id is unknown: %s", body)
	}
	if code, b := adminCall(t, admin, "DELETE", "/api/admin/relays/"+rowID, nil); code != http.StatusConflict {
		t.Errorf("DELETE of a legacy relay without revocation = %d %s, want 409 relay_not_revoked", code, b)
	}
	// ...it IS revoked by the flag, and is then refused at the upgrade
	code, b := adminCall(t, admin, "POST", "/api/admin/relays/"+rowID+"/revoke", nil)
	if code != http.StatusOK || !contains(string(b), `"legacy_token":true`) {
		t.Errorf("revoke of a legacy relay = %d %s, want 200 with legacy_token:true", code, b)
	}
	if _, status, err := dialRelayWS(wsAddr, relayToken(t, "legacy-pull")); err == nil || status != http.StatusUnauthorized {
		t.Errorf("a revoked legacy relay must be refused in 401, got status %d err %v", status, err)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
