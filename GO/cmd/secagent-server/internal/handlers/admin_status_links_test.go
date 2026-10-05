package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
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
