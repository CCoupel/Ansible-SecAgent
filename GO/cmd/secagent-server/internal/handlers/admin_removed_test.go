// SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"secagent-server/cmd/secagent-server/internal/hooks"
)

// #266: DELETE of a minion emits host.removed (cause deleted, enrolled_at, first_seen_at when known) THEN the
// deprecated host.deleted; a revocation emits neither.
func TestAdminDeleteMinion_EmitsHostRemovedThenHostDeleted(t *testing.T) {
	s := useFreshStores(t)
	s.SetFirstSeenFlush(time.Hour)
	ctx := context.Background()
	if _, err := s.RegisterAgent(ctx, "gone-host", "pem", "jti-g"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RegisterAgent(ctx, "never-connected", "pem", "jti-n"); err != nil {
		t.Fatal(err)
	}
	s.MarkFirstSeen("gone-host")

	out := filepath.Join(t.TempDir(), "events.log")
	d := hooks.NewDispatcher(nil, 100)
	d.SetConfig(&hooks.HooksConfig{Hooks: []hooks.HookDef{
		{Event: "host.removed", Actions: []hooks.ActionDef{{Type: "file", Path: out, Append: "REMOVED {{hostname}} cause={{cause}} first={{first_seen_at}} enrolled={{enrolled_at}}\n"}}},
		{Event: "host.deleted", Actions: []hooks.ActionDef{{Type: "file", Path: out, Append: "DELETED {{hostname}}\n"}}},
	}})
	ctxd, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	d.Start(ctxd)
	prev := hooks.GlobalDispatcher
	hooks.GlobalDispatcher = d
	t.Cleanup(func() { hooks.GlobalDispatcher = prev })

	del := func(host string) {
		req := adminReq("DELETE", "/api/admin/minions/"+host, nil)
		req.SetPathValue("hostname", host)
		w := httptest.NewRecorder()
		AdminDeleteMinion(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("delete %s: %d %s", host, w.Code, w.Body.String())
		}
	}
	del("gone-host")
	del("never-connected")
	var lines []string
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		b, _ := os.ReadFile(out)
		lines = strings.Split(strings.TrimSpace(string(b)), "\n")
		if len(lines) >= 4 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if len(lines) != 4 {
		t.Fatalf("lines = %q, want 2 REMOVED + 2 DELETED", lines)
	}
	// FIFO per hostname: removed before deleted
	if !strings.HasPrefix(lines[0], "REMOVED gone-host cause=deleted first=20") || !strings.Contains(lines[0], "enrolled=20") {
		t.Errorf("first line = %q", lines[0])
	}
	if lines[1] != "DELETED gone-host" {
		t.Errorf("second line = %q, want the deprecated host.deleted right after host.removed", lines[1])
	}
	for _, l := range lines {
		if strings.HasPrefix(l, "REMOVED never-connected") && !strings.Contains(l, "first= ") {
			t.Errorf("a never connected host has no first_seen_at: %q", l)
		}
	}
}

func TestAdminRevokeMinion_EmitsNoRemoved(t *testing.T) {
	s := useFreshStores(t)
	if _, err := s.RegisterAgent(context.Background(), "rev-host", "pem", "jti-r"); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "events.log")
	d := hooks.NewDispatcher(nil, 100)
	d.SetConfig(&hooks.HooksConfig{Hooks: []hooks.HookDef{
		{Event: "host.removed", Actions: []hooks.ActionDef{{Type: "file", Path: out, Append: "REMOVED\n"}}},
		{Event: "host.deleted", Actions: []hooks.ActionDef{{Type: "file", Path: out, Append: "DELETED\n"}}},
	}})
	ctxd, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	d.Start(ctxd)
	prev := hooks.GlobalDispatcher
	hooks.GlobalDispatcher = d
	t.Cleanup(func() { hooks.GlobalDispatcher = prev })
	req := adminReq("POST", "/api/admin/minions/rev-host/revoke", nil)
	req.SetPathValue("hostname", "rev-host")
	w := httptest.NewRecorder()
	AdminRevokeMinion(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("revoke: %d %s", w.Code, w.Body.String())
	}
	time.Sleep(300 * time.Millisecond)
	if b, _ := os.ReadFile(out); len(b) != 0 {
		t.Errorf("a revocation emitted %q, want nothing", b)
	}
}
