package storage

import (
	"testing"
	"time"
)

func seedNodes(t *testing.T, s *Store, ids ...string) {
	t.Helper()
	for _, id := range ids {
		if err := s.UpsertRelayNode(RelayNode{ID: "uuid-" + id, RelayID: id, Mode: "pull", Status: "connected", CreatedAt: time.Now().Unix()}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestRouting_UpsertRouteLastWinsReturnsPrevious(t *testing.T) {
	s := newRelayTestStore(t)
	seedNodes(t, s, "dmz1", "dmz2", "zone-a")

	prev, err := s.UpsertRelayRoute("host-A", "dmz1", []string{"dmz1"})
	if err != nil || prev != nil {
		t.Fatalf("first upsert: prev=%v err=%v", prev, err)
	}
	// same next hop again: previous returned, row refreshed, still one row (PK = hostname)
	prev, err = s.UpsertRelayRoute("host-A", "dmz1", []string{"dmz1"})
	if err != nil || prev == nil || prev.NextHop() != "dmz1" {
		t.Fatalf("same hop: prev=%+v err=%v", prev, err)
	}
	// different relay: last wins
	prev, err = s.UpsertRelayRoute("host-A", "zone-a", []string{"dmz2", "zone-a"})
	if err != nil || prev == nil || prev.RelayID != "dmz1" {
		t.Fatalf("move: prev=%+v err=%v", prev, err)
	}
	got, _ := s.GetRelayRoute("host-A")
	if got.RelayID != "zone-a" || got.NextHop() != "dmz2" || len(got.RelayChain) != 2 || got.HopType != "relay" {
		t.Errorf("route = %+v", got)
	}
	if hop, _ := s.GetNextHopForHostname("host-A"); hop != "dmz2" {
		t.Errorf("next hop = %q, want dmz2", hop)
	}
	if hop, err := s.GetNextHopForHostname("ghost"); hop != "" || err != nil {
		t.Errorf("unrouted host: %q %v", hop, err)
	}
}

func TestRouting_BulkUpsertIsLastWinsAndSetsDirectChain(t *testing.T) {
	s := newRelayTestStore(t)
	seedNodes(t, s, "dmz1", "dmz2")
	if err := s.BulkUpsertRelayRouting("dmz1", []string{"h1", "h2"}); err != nil {
		t.Fatal(err)
	}
	// dmz2 claims h2 (already routed via dmz1): must re-point, not fail on the primary key
	if err := s.BulkUpsertRelayRouting("dmz2", []string{"h2", "h3"}); err != nil {
		t.Fatalf("Bulk with a host routed elsewhere: %v", err)
	}
	r, _ := s.GetRelayRoute("h2")
	if r.RelayID != "dmz2" || r.NextHop() != "dmz2" {
		t.Errorf("h2 = %+v", r)
	}
	if hosts, _ := s.ListRelayRouting("dmz1"); len(hosts) != 1 || hosts[0] != "h1" {
		t.Errorf("dmz1 hosts = %v", hosts)
	}
}

func TestRouting_SetRelayRouteChains(t *testing.T) {
	s := newRelayTestStore(t)
	seedNodes(t, s, "dmz1", "zone-a")
	if err := s.BulkUpsertRelayRouting("zone-a", []string{"host-B"}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetRelayRouteChains([]RouteChain{
		{Hostname: "host-B", RelayID: "zone-a", Chain: []string{"dmz1", "zone-a"}},
		{Hostname: "host-B", RelayID: "someone-else", Chain: []string{"x"}}, // stale relay: ignored
	}); err != nil {
		t.Fatal(err)
	}
	r, _ := s.GetRelayRoute("host-B")
	if r.NextHop() != "dmz1" || r.RelayID != "zone-a" {
		t.Errorf("route = %+v", r)
	}
}

func TestRouting_RelayDeletionCascadesRoutes(t *testing.T) {
	s := newRelayTestStore(t)
	seedNodes(t, s, "dmz1")
	if _, err := s.UpsertRelayRoute("h", "dmz1", []string{"dmz1"}); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteRelayRoutingByRelay("dmz1"); err != nil {
		t.Fatal(err)
	}
	if r, _ := s.GetRelayRoute("h"); r != nil {
		t.Errorf("route survived: %+v", r)
	}
}
