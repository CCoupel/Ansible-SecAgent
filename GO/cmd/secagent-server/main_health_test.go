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

// /health is public: a permanently refused link is flagged ("degraded") but the probe stays 200
// and NOTHING about the topology is exposed (no relay id, no state, no reason, no links block).
func TestHealth_PermanentRefusalFlagsDegradedAndStill200(t *testing.T) {
	since := time.Now().UTC()
	withLinks(t, func() repeater.LinksStatus {
		return repeater.NewLinksStatus(
			&repeater.UpstreamStatus{Mode: "pull", Peer: "central-secret-peer", LinkStatus: repeater.LinkStatus{
				State: repeater.LinkRefusedPermanent, Reason: "peer closed with code 4010 (token revoked)", Since: since}},
			[]repeater.NamedStatus{
				{RelayID: "dmz2-secret-child", LinkStatus: repeater.LinkStatus{State: repeater.LinkConnected, Since: since}},
				{RelayID: "dmz3-secret-child", LinkStatus: repeater.LinkStatus{State: repeater.LinkRetrying, Reason: "connect failed", Since: since}},
			})
	})
	w := httptest.NewRecorder()
	handleHealth(w, httptest.NewRequest("GET", "/health", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("liveness must stay 200, got %d", w.Code)
	}
	var m map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	if m["status"] != "ok" || m["degraded"] != true {
		t.Errorf("health = %v, want status ok and degraded true", m)
	}
	if _, ok := m["links"]; ok {
		t.Error("/health must not carry the links block")
	}
	body := strings.ToLower(w.Body.String())
	for _, leak := range []string{"central-secret-peer", "dmz2-secret-child", "dmz3-secret-child", "relay_id", "peer", "reason",
		"refused_permanent", "retrying", "connected", "4010", "token revoked", "upstream", "push_children", "since"} {
		if strings.Contains(body, leak) {
			t.Errorf("/health leaks %q: %s", leak, w.Body.String())
		}
	}
	// only these keys are allowed
	for k := range m {
		if k != "status" && k != "timestamp" && k != "degraded" {
			t.Errorf("unexpected key %q in /health", k)
		}
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
