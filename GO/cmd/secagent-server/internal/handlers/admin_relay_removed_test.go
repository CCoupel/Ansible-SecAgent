// SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"secagent-server/cmd/secagent-server/internal/hooks"
)

var (
	upMu     sync.Mutex
	upEvents []hooks.Event
)

// capturedRemovedChain returns the relay_chain of the relay.removed handed to the upstream forwarder.
func capturedRemovedChain() []string {
	upMu.Lock()
	defer upMu.Unlock()
	for _, e := range upEvents {
		if e.Name == "relay.removed" {
			return e.RelayChain
		}
	}
	return nil
}

func relayEventsRig(t *testing.T) string {
	t.Helper()
	upMu.Lock()
	upEvents = nil
	upMu.Unlock()
	out := filepath.Join(t.TempDir(), "events.log")
	d := hooks.NewDispatcher(nil, 100)
	d.SetConfig(&hooks.HooksConfig{Hooks: []hooks.HookDef{
		{Event: "relay.removed", Actions: []hooks.ActionDef{{Type: "file", Path: out, Append: "REMOVED {{relay_id}} mode={{mode}} cause={{cause}} hosts={{hosts_routed}} first={{first_seen_at}}\n"}}},
	}})
	d.SetUpstreamEvent(func(ev hooks.Event) { upMu.Lock(); upEvents = append(upEvents, ev); upMu.Unlock() })
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	d.Start(ctx)
	prev := hooks.GlobalDispatcher
	hooks.GlobalDispatcher = d
	t.Cleanup(func() { hooks.GlobalDispatcher = prev })
	return out
}

func declareRelay(t *testing.T, id string) RelayCreateResponse {
	t.Helper()
	rr := doAdminRelayRequest(t, AdminCreateRelay, "POST", "/api/admin/relays", map[string]interface{}{"relay_id": id, "mode": "pull"})
	var created RelayCreateResponse
	mustUnmarshal(t, rr.Body.Bytes(), &created)
	if err := adminStore.SetRelayTokenInfo(id, "jti-"+id, time.Now().Add(time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}
	return created
}

// #266: DELETE of a relay emits ONE relay.removed (cause deleted, informative hosts_routed, first_seen_at when
// known); a revocation emits none.
func TestAdminDeleteRelay_EmitsOneRelayRemoved(t *testing.T) {
	s := useFreshStores(t)
	s.SetFirstSeenFlush(time.Hour)
	out := relayEventsRig(t)
	created := declareRelay(t, "rm-relay")
	s.MarkRelayFirstSeen("rm-relay")
	if err := s.BulkUpsertRelayRouting("rm-relay", []string{"h1", "h2", "h3"}); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("DELETE", "/api/admin/relays/"+created.ID, nil)
	req.Header.Set("Authorization", "Bearer "+server.AdminToken)
	req.SetPathValue("id", created.ID)
	rr := httptest.NewRecorder()
	AdminDeleteRelay(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", rr.Code, rr.Body.String())
	}
	if got := capturedRemovedChain(); len(got) != 1 || got[0] != "rm-relay" {
		t.Errorf("relay.removed relay_chain = %v, want [rm-relay] (the parent requires the chain to start with the relay it describes)", got)
	}
	var lines []string
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		b, _ := os.ReadFile(out)
		lines = strings.Split(strings.TrimSpace(string(b)), "\n")
		if len(lines) >= 1 && lines[0] != "" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	time.Sleep(150 * time.Millisecond)
	b, _ := os.ReadFile(out)
	lines = strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) != 1 || !strings.HasPrefix(lines[0], "REMOVED rm-relay mode=pull cause=deleted hosts=3 first=20") {
		t.Errorf("lines = %q, want exactly one relay.removed with hosts=3 and first_seen_at", lines)
	}
}

func TestAdminRevokeRelay_EmitsNoRemoved(t *testing.T) {
	useFreshStores(t)
	out := relayEventsRig(t)
	created := declareRelay(t, "rv-relay")
	req := httptest.NewRequest("POST", "/api/admin/relays/"+created.ID+"/revoke", nil)
	req.Header.Set("Authorization", "Bearer "+server.AdminToken)
	req.SetPathValue("id", created.ID)
	rr := httptest.NewRecorder()
	AdminRevokeRelay(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("revoke: %d %s", rr.Code, rr.Body.String())
	}
	time.Sleep(300 * time.Millisecond)
	if b, _ := os.ReadFile(out); len(b) != 0 {
		t.Errorf("a revocation emitted %q, want nothing", b)
	}
}

func TestAdminListRelays_ExposesFirstSeenAt(t *testing.T) {
	s := useFreshStores(t)
	s.SetFirstSeenFlush(time.Hour)
	declareRelay(t, "fs-relay")
	list := func() map[string]any {
		rr := doAdminRelayRequest(t, AdminListRelays, "GET", "/api/admin/relays", nil)
		var resp struct {
			Relays []map[string]any `json:"relays"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		for _, r := range resp.Relays {
			if r["relay_id"] == "fs-relay" {
				return r
			}
		}
		t.Fatal("relay not listed")
		return nil
	}
	if _, ok := list()["first_seen_at"]; ok {
		t.Error("first_seen_at must be absent before the first snapshot")
	}
	s.MarkRelayFirstSeen("fs-relay")
	s.FlushFirstSeen()
	if v, _ := list()["first_seen_at"].(string); !strings.HasPrefix(v, "20") {
		t.Errorf("first_seen_at = %v", list()["first_seen_at"])
	}
}
