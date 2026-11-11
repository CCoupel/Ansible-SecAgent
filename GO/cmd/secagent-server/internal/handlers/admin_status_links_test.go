// SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"secagent-server/cmd/secagent-server/internal/hooks"
)

func TestAdminStatus_IncludesLinksWhenProvided(t *testing.T) {
	useFreshStores(t)
	SetLinkStatusFunc(func() interface{} {
		return map[string]any{"upstream": map[string]any{"mode": "pull", "state": "refused_permanent"}, "degraded": true}
	})
	t.Cleanup(func() { SetLinkStatusFunc(nil) })
	w := httptest.NewRecorder()
	AdminStatus(w, adminReq("GET", "/api/admin/status", nil))
	var m map[string]any
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &m) != nil {
		t.Fatalf("status %d %s", w.Code, w.Body.String())
	}
	links, ok := m["links"].(map[string]any)
	if !ok || links["degraded"] != true || links["upstream"].(map[string]any)["state"] != "refused_permanent" {
		t.Errorf("links = %v", m["links"])
	}
}

func TestAdminStatus_NoLinksWhenNotWired(t *testing.T) {
	useFreshStores(t)
	SetLinkStatusFunc(nil)
	w := httptest.NewRecorder()
	AdminStatus(w, adminReq("GET", "/api/admin/status", nil))
	var m map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &m)
	if _, ok := m["links"]; ok {
		t.Errorf("unexpected links: %v", m["links"])
	}
	if m["db"] == nil || m["ws_connections"] == nil {
		t.Errorf("existing fields must stay: %v", m)
	}
}

// #183: the hooks queue counters are visible in the status, a loss is never silent.
func TestAdminStatus_IncludesHooksQueueCounters(t *testing.T) {
	useFreshStores(t)
	prev := hooks.GlobalDispatcher
	d := hooks.NewDispatcher(nil, 0) // unbuffered, not started: every event is rejected and counted
	hooks.GlobalDispatcher = d
	t.Cleanup(func() { hooks.GlobalDispatcher = prev })
	d.Dispatch("host.up", "h1", "connected", "")
	d.Dispatch("host.up", "h2", "connected", "")
	w := httptest.NewRecorder()
	AdminStatus(w, adminReq("GET", "/api/admin/status", nil))
	var m map[string]any
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &m) != nil {
		t.Fatalf("status %d %s", w.Code, w.Body.String())
	}
	if m["hooks_dropped_events"] != float64(2) || m["hooks_dropped_actions"] != float64(0) ||
		m["hooks_queue_depth"] != float64(0) || m["hooks_inflight"] != float64(0) || m["hooks_queue_capacity"] == nil {
		t.Errorf("hooks counters = %v", m)
	}
}

// #246: the upstream queue counters are always present (0 / 0 / 0 until wired), then follow the queue.
func TestAdminStatus_UpstreamQueueCounters(t *testing.T) {
	useFreshStores(t)
	SetUpstreamQueueStatusFunc(nil)
	get := func() map[string]any {
		w := httptest.NewRecorder()
		AdminStatus(w, adminReq("GET", "/api/admin/status", nil))
		var m map[string]any
		if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &m) != nil {
			t.Fatalf("status %d %s", w.Code, w.Body.String())
		}
		return m
	}
	m := get()
	for _, k := range []string{"upstream_dropped_events", "upstream_queue_depth", "upstream_queue_capacity"} {
		if v, ok := m[k]; !ok || v != float64(0) {
			t.Errorf("%s = %v (present=%v), want 0", k, v, ok)
		}
	}
	SetUpstreamQueueStatusFunc(func() (int64, int, int) { return 44, 12, 10000 })
	t.Cleanup(func() { SetUpstreamQueueStatusFunc(nil) })
	m = get()
	if m["upstream_dropped_events"] != float64(44) || m["upstream_queue_depth"] != float64(12) || m["upstream_queue_capacity"] != float64(10000) {
		t.Errorf("counters = %v / %v / %v", m["upstream_dropped_events"], m["upstream_queue_depth"], m["upstream_queue_capacity"])
	}
}
