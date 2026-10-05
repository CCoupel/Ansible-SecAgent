package storage

import (
	"bytes"
	"fmt"
	"log"
	"strings"
	"testing"
	"time"

	"secagent-server/cmd/secagent-server/internal/state"
)

func TestUpsertRelayNode_RefusesMalformedRelayID(t *testing.T) {
	s, err := OpenTemp()
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
	s, err := OpenTemp()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	if err := s.UpsertRelayNode(RelayNode{ID: "good", RelayID: "dmz1", Mode: "pull", Status: "pending"}); err != nil {
		t.Fatal(err)
	}
	// a legacy row inserted behind the guard (straight through the engine)
	if err := s.Engine().Mutate(func(tx *state.Tx) error {
		return tx.PutRelayNode(state.RelayNode{ID: "bad", RelayID: "a\nb", Mode: "pull", CreatedAt: time.Unix(0, 0)})
	}); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(prev)

	valid, err := s.ListValidRelayNodes()
	if err != nil || len(valid) != 1 || valid[0].RelayID != "dmz1" {
		t.Fatalf("valid = %+v %v", valid, err)
	}
	if !strings.Contains(buf.String(), `"a\nb"`) || strings.Contains(buf.String(), "a\nb") {
		t.Errorf("the warning must quote the id: %q", buf.String())
	}
	// a legacy row is read on every inventory / snapshot: ONE warning per id and process
	if _, err := s.ListValidRelayNodes(); err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(buf.String(), "ignored"); n != 1 {
		t.Errorf("%d warnings for the same id, want 1: %q", n, buf.String())
	}
	if all, _ := s.ListRelayNodes(); len(all) != 2 {
		t.Errorf("ListRelayNodes must still show the legacy row (to delete it): %d", len(all))
	}
}

// relay_routing rows written before the validation (or by a hostile peer on an older version) are
// never served: the hostname, the declaring relay and every chain element must be well formed.
func TestRelayRouting_MalformedRowsAreNeverServed(t *testing.T) {
	resetIgnored()
	s, err := OpenTemp()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	if err := s.UpsertRelayNode(RelayNode{ID: "good", RelayID: "dmz1", Mode: "pull", Status: "pending"}); err != nil {
		t.Fatal(err)
	}
	ins := func(host, relay string, chain []string) {
		t.Helper()
		s.mu.Lock()
		s.routes[host] = RelayRoute{Hostname: host, RelayID: relay, HopType: "relay", RelayChain: chain}
		s.mu.Unlock()
	}
	ins("ok-host", "dmz1", []string{"dmz1"})
	ins("bad-relay-host", "bad\none", []string{"bad\none"})
	ins("bad-chain-host", "dmz1", []string{"dmz1", "x\n[SECURITY WARNING] forged"})
	ins("bad\nhost", "dmz1", []string{"dmz1"})

	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(prev)

	routes, err := s.ListRelayRoutes()
	if err != nil || len(routes) != 1 || routes[0].Hostname != "ok-host" {
		t.Errorf("ListRelayRoutes = %+v %v, want only ok-host", routes, err)
	}
	for _, h := range []string{"bad-relay-host", "bad-chain-host", "bad\nhost"} {
		if r, _ := s.GetRelayRoute(h); r != nil {
			t.Errorf("GetRelayRoute(%q) served a malformed route: %+v", h, r)
		}
		if hop, _ := s.GetNextHopForHostname(h); hop != "" {
			t.Errorf("next hop of %q = %q", h, hop)
		}
	}
	if id, _ := s.GetRelayForHostname("bad-relay-host"); id != "" {
		t.Errorf("GetRelayForHostname served %q", id)
	}
	if hosts, _ := s.ListRelayRouting("dmz1"); len(hosts) != 2 { // ok-host and bad-chain-host (relay_id fine); the bad hostname is dropped
		t.Errorf("ListRelayRouting(dmz1) = %v", hosts)
	}
	if strings.Contains(buf.String(), "\n[SECURITY WARNING] forged") {
		t.Errorf("hostile value forged a log line: %q", buf.String())
	}
}

func resetIgnored() {
	ignoredMu.Lock()
	ignoredWarned = make(map[string]struct{})
	ignoredOverflow = 0
	ignoredMu.Unlock()
}

// The memory of reported identifiers is bounded: beyond maxIgnoredWarned distinct ids there is ONE
// aggregated warning, the rest is only counted; filtering is not affected.
func TestWarnIgnoredOnce_IsBounded(t *testing.T) {
	resetIgnored()
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(prev)
	for i := 0; i < maxIgnoredWarned+1000; i++ {
		warnIgnoredOnce("relay route", fmt.Sprintf("bad\n%d", i))
	}
	ignoredMu.Lock()
	n := len(ignoredWarned)
	ignoredMu.Unlock()
	if n != maxIgnoredWarned {
		t.Errorf("memory holds %d ids, want exactly %d", n, maxIgnoredWarned)
	}
	if lines := strings.Count(buf.String(), "\n"); lines != maxIgnoredWarned+1 {
		t.Errorf("%d log lines, want %d (one per id + one aggregate)", lines, maxIgnoredWarned+1)
	}
	if IgnoredOverflow() != 1000 {
		t.Errorf("overflow = %d, want 1000", IgnoredOverflow())
	}
	// a known id stays silent, and an unknown one beyond the bound adds neither entry nor line
	before := buf.Len()
	warnIgnoredOnce("relay route", "bad\n0")
	warnIgnoredOnce("relay route", "brand-new-bad\n")
	if buf.Len() != before {
		t.Error("no further line expected past the bound")
	}
	resetIgnored()
}
