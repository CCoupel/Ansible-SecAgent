package storage

import (
	"bytes"
	"log"
	"strings"
	"testing"
)

func TestUpsertRelayNode_RefusesMalformedRelayID(t *testing.T) {
	s, err := NewStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	for _, id := range []string{"", "a b", "a\nb", "..", strings.Repeat("a", 64)} {
		if err := s.UpsertRelayNode(RelayNode{ID: "x", RelayID: id, Mode: "pull", Status: "pending"}); err == nil {
			t.Errorf("%q accepted", id)
		}
	}
	if err := s.UpsertRelayNode(RelayNode{ID: "ok", RelayID: "dmz1", Mode: "pull", Status: "pending"}); err != nil {
		t.Errorf("valid id refused: %v", err)
	}
}

// Rows written before the validation are ignored (with a warning, the id quoted) by the consumers
// that route / publish / inventory, but stay listable so that an admin can delete them.
func TestListValidRelayNodes_IgnoresLegacyMalformedRows(t *testing.T) {
	s, err := NewStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	if err := s.UpsertRelayNode(RelayNode{ID: "good", RelayID: "dmz1", Mode: "pull", Status: "pending"}); err != nil {
		t.Fatal(err)
	}
	// a legacy row inserted behind the guard
	if _, err := s.db.Exec(`INSERT INTO relay_nodes (id, relay_id, url, description, token_hash, mode, is_proxy, created_at, status)
		VALUES ('bad', E'a\nb', '', '', '', 'pull', 0, 0, 'pending')`); err != nil {
		if _, err2 := s.db.Exec("INSERT INTO relay_nodes (id, relay_id, url, description, token_hash, mode, is_proxy, created_at, status) VALUES ('bad', 'a'||char(10)||'b', '', '', '', 'pull', 0, 0, 'pending')"); err2 != nil {
			t.Fatal(err2)
		}
	}
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(prev)

	valid, err := s.ListValidRelayNodes()
	if err != nil || len(valid) != 1 || valid[0].RelayID != "dmz1" {
		t.Fatalf("valid = %+v %v", valid, err)
	}
	if !strings.Contains(buf.String(), `relay_id="a\nb"`) || strings.Contains(buf.String(), "a\nb") {
		t.Errorf("the warning must quote the id: %q", buf.String())
	}
	if all, _ := s.ListRelayNodes(); len(all) != 2 {
		t.Errorf("ListRelayNodes must still show the legacy row (to delete it): %d", len(all))
	}
}
