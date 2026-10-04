package storage

import (
	"fmt"
	"testing"

	"github.com/google/uuid"
)

// newRelayTestStore returns a fresh in-memory store for relay tests.
func newRelayTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := NewStore(":memory:")
	if err != nil {
		t.Fatalf("newRelayTestStore: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// ── RelayNode CRUD ────────────────────────────────────────────────────────────

func TestUpsertAndGetRelayNode(t *testing.T) {
	s := newRelayTestStore(t)

	node := RelayNode{
		ID:          uuid.New().String(),
		RelayID:     "dmz1",
		Mode:        "pull",
		Description: "Zone DMZ1",
		Status:      "pending",
		CreatedAt:   1000000,
	}

	if err := s.UpsertRelayNode(node); err != nil {
		t.Fatalf("UpsertRelayNode: %v", err)
	}

	got, err := s.GetRelayNode("dmz1")
	if err != nil {
		t.Fatalf("GetRelayNode: %v", err)
	}
	if got == nil {
		t.Fatal("expected relay node, got nil")
	}
	if got.RelayID != "dmz1" {
		t.Errorf("relay_id: want dmz1, got %s", got.RelayID)
	}
	if got.Mode != "pull" {
		t.Errorf("mode: want pull, got %s", got.Mode)
	}
	if got.Description != "Zone DMZ1" {
		t.Errorf("description: want Zone DMZ1, got %s", got.Description)
	}
}

func TestGetRelayNode_NotFound(t *testing.T) {
	s := newRelayTestStore(t)

	got, err := s.GetRelayNode("nonexistent")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil, got %+v", got)
	}
}

func TestUpsertRelayNode_UpdatesOnConflict(t *testing.T) {
	s := newRelayTestStore(t)

	id := uuid.New().String()
	node := RelayNode{ID: id, RelayID: "relay1", Mode: "pull", Status: "pending", CreatedAt: 1000}
	if err := s.UpsertRelayNode(node); err != nil {
		t.Fatalf("first upsert: %v", err)
	}

	// Update with same relay_id → should change mode and status
	node2 := RelayNode{ID: id, RelayID: "relay1", Mode: "push", URL: "https://relay1:7770", Status: "connected", CreatedAt: 1000}
	if err := s.UpsertRelayNode(node2); err != nil {
		t.Fatalf("second upsert: %v", err)
	}

	got, _ := s.GetRelayNode("relay1")
	if got.Mode != "push" {
		t.Errorf("expected mode=push after upsert, got %s", got.Mode)
	}
	if got.URL != "https://relay1:7770" {
		t.Errorf("expected url updated, got %s", got.URL)
	}
}

func TestUpsertRelayNode_IsProxy(t *testing.T) {
	s := newRelayTestStore(t)

	node := RelayNode{
		ID:        uuid.New().String(),
		RelayID:   "proxy-b",
		Mode:      "pull",
		IsProxy:   true,
		Status:    "pending",
		CreatedAt: 1000,
	}
	if err := s.UpsertRelayNode(node); err != nil {
		t.Fatalf("UpsertRelayNode: %v", err)
	}

	got, _ := s.GetRelayNode("proxy-b")
	if !got.IsProxy {
		t.Error("expected IsProxy=true")
	}
}

func TestListRelayNodes(t *testing.T) {
	s := newRelayTestStore(t)

	for _, rid := range []string{"dmz2", "dmz1", "dmz3"} {
		node := RelayNode{
			ID:        uuid.New().String(),
			RelayID:   rid,
			Mode:      "pull",
			Status:    "pending",
			CreatedAt: 1000,
		}
		if err := s.UpsertRelayNode(node); err != nil {
			t.Fatalf("UpsertRelayNode %s: %v", rid, err)
		}
	}

	nodes, err := s.ListRelayNodes()
	if err != nil {
		t.Fatalf("ListRelayNodes: %v", err)
	}
	if len(nodes) != 3 {
		t.Errorf("expected 3 nodes, got %d", len(nodes))
	}
	// Ordered by relay_id
	if nodes[0].RelayID != "dmz1" {
		t.Errorf("expected first=dmz1, got %s", nodes[0].RelayID)
	}
}

func TestDeleteRelayNode(t *testing.T) {
	s := newRelayTestStore(t)

	id := uuid.New().String()
	node := RelayNode{ID: id, RelayID: "to-delete", Mode: "pull", Status: "pending", CreatedAt: 1000}
	if err := s.UpsertRelayNode(node); err != nil {
		t.Fatalf("UpsertRelayNode: %v", err)
	}

	if err := s.DeleteRelayNode(id); err != nil {
		t.Fatalf("DeleteRelayNode: %v", err)
	}

	got, err := s.GetRelayNode("to-delete")
	if err != nil {
		t.Fatalf("GetRelayNode: %v", err)
	}
	if got != nil {
		t.Error("expected nil after delete")
	}
}

func TestUpdateRelayStatus(t *testing.T) {
	s := newRelayTestStore(t)

	node := RelayNode{
		ID:        uuid.New().String(),
		RelayID:   "relay-status",
		Mode:      "pull",
		Status:    "pending",
		CreatedAt: 1000,
	}
	if err := s.UpsertRelayNode(node); err != nil {
		t.Fatalf("UpsertRelayNode: %v", err)
	}

	if err := s.UpdateRelayStatus("relay-status", "connected", 2000000); err != nil {
		t.Fatalf("UpdateRelayStatus: %v", err)
	}

	got, _ := s.GetRelayNode("relay-status")
	if got.Status != "connected" {
		t.Errorf("expected status=connected, got %s", got.Status)
	}
	if got.LastSeen == nil || *got.LastSeen != 2000000 {
		t.Errorf("expected last_seen=2000000, got %v", got.LastSeen)
	}
}

// ── relay_routing ─────────────────────────────────────────────────────────────

func TestUpsertAndGetRelayRouting(t *testing.T) {
	s := newRelayTestStore(t)

	// relay_routing FK references relay_nodes; insert a node first
	node := RelayNode{ID: uuid.New().String(), RelayID: "dmz1", Mode: "pull", Status: "pending", CreatedAt: 1000}
	_ = s.UpsertRelayNode(node)

	if err := s.UpsertRelayRouting("host-a", "dmz1"); err != nil {
		t.Fatalf("UpsertRelayRouting: %v", err)
	}

	relayID, err := s.GetRelayForHostname("host-a")
	if err != nil {
		t.Fatalf("GetRelayForHostname: %v", err)
	}
	if relayID != "dmz1" {
		t.Errorf("expected dmz1, got %s", relayID)
	}
}

func TestGetRelayForHostname_NotFound(t *testing.T) {
	s := newRelayTestStore(t)

	id, err := s.GetRelayForHostname("unknown-host")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id != "" {
		t.Errorf("expected empty, got %s", id)
	}
}

func TestUpsertRelayRouting_UpdatesOnConflict(t *testing.T) {
	s := newRelayTestStore(t)

	// Two relay nodes
	for _, rid := range []string{"old-relay", "new-relay"} {
		n := RelayNode{ID: uuid.New().String(), RelayID: rid, Mode: "pull", Status: "pending", CreatedAt: 1000}
		_ = s.UpsertRelayNode(n)
	}

	_ = s.UpsertRelayRouting("host-b", "old-relay")
	// Reassign to new-relay
	_ = s.UpsertRelayRouting("host-b", "new-relay")

	relayID, _ := s.GetRelayForHostname("host-b")
	if relayID != "new-relay" {
		t.Errorf("expected new-relay after update, got %s", relayID)
	}
}

func TestBulkUpsertRelayRouting(t *testing.T) {
	s := newRelayTestStore(t)

	// Insert relay node
	node := RelayNode{ID: uuid.New().String(), RelayID: "bulk-relay", Mode: "pull", Status: "pending", CreatedAt: 1000}
	_ = s.UpsertRelayNode(node)

	// Build 120 hostnames (> 100 to verify no chunk issue)
	hostnames := make([]string, 120)
	for i := range hostnames {
		hostnames[i] = fmt.Sprintf("host-%03d", i)
	}

	if err := s.BulkUpsertRelayRouting("bulk-relay", hostnames); err != nil {
		t.Fatalf("BulkUpsertRelayRouting: %v", err)
	}

	// Verify all hostnames are mapped
	for i, h := range hostnames {
		relayID, err := s.GetRelayForHostname(h)
		if err != nil {
			t.Fatalf("GetRelayForHostname %s: %v", h, err)
		}
		if relayID != "bulk-relay" {
			t.Errorf("host-%03d: expected bulk-relay, got %s", i, relayID)
		}
	}
}

func TestBulkUpsertRelayRouting_ReplacesExisting(t *testing.T) {
	s := newRelayTestStore(t)

	node := RelayNode{ID: uuid.New().String(), RelayID: "replace-relay", Mode: "pull", Status: "pending", CreatedAt: 1000}
	_ = s.UpsertRelayNode(node)

	// First bulk
	_ = s.BulkUpsertRelayRouting("replace-relay", []string{"host-X", "host-Y", "host-Z"})

	// Second bulk — replaces the previous set
	_ = s.BulkUpsertRelayRouting("replace-relay", []string{"host-A", "host-B"})

	list, err := s.ListRelayRouting("replace-relay")
	if err != nil {
		t.Fatalf("ListRelayRouting: %v", err)
	}
	if len(list) != 2 {
		t.Errorf("expected 2 hostnames after replacement, got %d: %v", len(list), list)
	}

	// Old hostnames must not be mapped anymore
	relayID, _ := s.GetRelayForHostname("host-X")
	if relayID != "" {
		t.Errorf("expected host-X to be gone, still mapped to %s", relayID)
	}
}

func TestDeleteRelayRoutingByRelay(t *testing.T) {
	s := newRelayTestStore(t)

	node := RelayNode{ID: uuid.New().String(), RelayID: "del-relay", Mode: "pull", Status: "pending", CreatedAt: 1000}
	_ = s.UpsertRelayNode(node)
	_ = s.BulkUpsertRelayRouting("del-relay", []string{"host-1", "host-2", "host-3"})

	if err := s.DeleteRelayRoutingByRelay("del-relay"); err != nil {
		t.Fatalf("DeleteRelayRoutingByRelay: %v", err)
	}

	list, _ := s.ListRelayRouting("del-relay")
	if len(list) != 0 {
		t.Errorf("expected 0 entries after delete, got %d", len(list))
	}
}

func TestListRelayRouting(t *testing.T) {
	s := newRelayTestStore(t)

	node := RelayNode{ID: uuid.New().String(), RelayID: "list-relay", Mode: "pull", Status: "pending", CreatedAt: 1000}
	_ = s.UpsertRelayNode(node)
	_ = s.BulkUpsertRelayRouting("list-relay", []string{"host-c", "host-a", "host-b"})

	list, err := s.ListRelayRouting("list-relay")
	if err != nil {
		t.Fatalf("ListRelayRouting: %v", err)
	}
	if len(list) != 3 {
		t.Errorf("expected 3, got %d", len(list))
	}
	// Ordered by hostname
	if list[0] != "host-a" {
		t.Errorf("expected host-a first, got %s", list[0])
	}
}

func TestGetRelayNodeByID(t *testing.T) {
	s := newRelayTestStore(t)

	id := uuid.New().String()
	node := RelayNode{ID: id, RelayID: "by-id-relay", Mode: "pull", Status: "pending", CreatedAt: 1000}
	_ = s.UpsertRelayNode(node)

	got, err := s.GetRelayNodeByID(id)
	if err != nil {
		t.Fatalf("GetRelayNodeByID: %v", err)
	}
	if got == nil {
		t.Fatal("expected node, got nil")
	}
	if got.ID != id {
		t.Errorf("expected id=%s, got %s", id, got.ID)
	}
}
