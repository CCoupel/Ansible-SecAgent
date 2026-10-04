package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"secagent-server/cmd/secagent-server/internal/repeater"
)

func healthBody(t *testing.T) (int, map[string]any) {
	t.Helper()
	w := httptest.NewRecorder()
	handleHealth(w, httptest.NewRequest("GET", "/health", nil))
	var m map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		t.Fatalf("health body: %v (%s)", err, w.Body.String())
	}
	return w.Code, m
}

func withLinks(t *testing.T, fn func() repeater.LinksStatus) {
	t.Helper()
	prev := linksProvider
	linksProvider = fn
	t.Cleanup(func() { linksProvider = prev })
}

func TestHealth_UnchangedWithoutLinks(t *testing.T) {
	withLinks(t, nil)
	code, m := healthBody(t)
	if code != http.StatusOK || m["status"] != "ok" || m["timestamp"] == nil {
		t.Errorf("health = %d %v", code, m)
	}
	if _, ok := m["links"]; ok {
		t.Error("a node without links must not report any")
	}
	// an empty summary (root without push children) is omitted too
	withLinks(t, func() repeater.LinksStatus { return repeater.NewLinksStatus(nil, nil) })
	if _, m := healthBody(t); m["links"] != nil {
		t.Errorf("empty links must be omitted: %v", m)
	}
}

// A permanently refused link is visible in /health but the probe stays 200: a node cut off
// from its parent still serves its agents and descendants and must not be restarted.
func TestHealth_PermanentRefusalVisibleButStill200(t *testing.T) {
	since := time.Now().UTC()
	withLinks(t, func() repeater.LinksStatus {
		return repeater.NewLinksStatus(
			&repeater.UpstreamStatus{Mode: "pull", Peer: "central", LinkStatus: repeater.LinkStatus{
				State: repeater.LinkRefusedPermanent, Reason: "peer closed with code 4010 (token revoked)", Since: since}},
			[]repeater.NamedStatus{
				{RelayID: "dmz2", LinkStatus: repeater.LinkStatus{State: repeater.LinkConnected, Since: since}},
				{RelayID: "dmz3", LinkStatus: repeater.LinkStatus{State: repeater.LinkRetrying, Reason: "connect failed", Since: since}},
			})
	})
	code, m := healthBody(t)
	if code != http.StatusOK || m["status"] != "ok" {
		t.Fatalf("liveness must stay 200/ok: %d %v", code, m)
	}
	if m["degraded"] != true {
		t.Errorf("degraded = %v, want true", m["degraded"])
	}
	links := m["links"].(map[string]any)
	up := links["upstream"].(map[string]any)
	if up["state"] != "refused_permanent" || up["mode"] != "pull" || up["peer"] != "central" ||
		!strings.Contains(up["reason"].(string), "4010") || up["since"] == nil {
		t.Errorf("upstream = %v", up)
	}
	push := links["push_children"].([]any)
	if len(push) != 2 || push[0].(map[string]any)["relay_id"] != "dmz2" || push[1].(map[string]any)["state"] != "retrying" {
		t.Errorf("push children = %v", push)
	}
}

func TestHealth_RetryingIsNotDegraded(t *testing.T) {
	withLinks(t, func() repeater.LinksStatus {
		return repeater.NewLinksStatus(&repeater.UpstreamStatus{Mode: "pull", LinkStatus: repeater.LinkStatus{State: repeater.LinkRetrying, Reason: "connect failed"}}, nil)
	})
	_, m := healthBody(t)
	if m["degraded"] != false {
		t.Errorf("a correctable/transient state is not degraded: %v", m["degraded"])
	}
}
