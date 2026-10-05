package handlers

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"secagent-server/cmd/secagent-server/internal/storage"
)

// #160: last_used_at / last_used_ip of a plugin token are approximate (persisted with the next
// write only): the API says so wherever it reports them.
func TestPluginTokenSummary_LastUsedIsFlaggedApproximate(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)
	ctx := context.Background()
	if err := s.CreatePluginToken(ctx, storage.PluginToken{ID: "p1", TokenHash: "h1", CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	tok, _ := s.GetPluginTokenByID(ctx, "p1")
	if sum := pluginTokenToSummary(*tok); sum.LastUsedApproximate || sum.LastUsedAt != "" {
		t.Errorf("never used: %+v", sum)
	}
	if err := s.TouchPluginToken(ctx, "p1", "192.0.2.9"); err != nil {
		t.Fatal(err)
	}
	tok, _ = s.GetPluginTokenByID(ctx, "p1")
	if sum := pluginTokenToSummary(*tok); !sum.LastUsedApproximate || sum.LastUsedAt == "" || sum.LastUsedIP != "192.0.2.9" {
		t.Errorf("used: %+v", sum)
	}
	// and through the admin list endpoint
	w := httptest.NewRecorder()
	AdminListTokens(w, adminReq("GET", "/api/admin/tokens?role=plugin", nil))
	if !strings.Contains(w.Body.String(), `"last_used_approximate":true`) {
		t.Errorf("the list must carry the approximate flag: %s", w.Body.String())
	}
}
