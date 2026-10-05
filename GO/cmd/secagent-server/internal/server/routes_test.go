package server

import (
	"sort"
	"strings"
	"testing"
)

// The exposed surface is part of the security contract: any added, removed, moved or renamed route
// must be a deliberate change of THESE lists (a handler silently moved to the public router, a
// modified path or method fails here).
var (
	wantAPIRoutes = []string{
		"GET /health",
		"POST /api/register",
		"POST /api/exec/{hostname}",
		"POST /api/upload/{hostname}",
		"POST /api/fetch/{hostname}",
		"GET /api/inventory",
		"POST /api/token/refresh",
		"POST /api/admin/authorize",
		"/ws/agent",
		"/ws/relay",
	}
	wantWSRoutes    = []string{"/ws/agent", "/ws/relay"}
	wantAdminRoutes = []string{
		"POST /api/admin/authorize",
		"GET /api/admin/minions",
		"GET /api/admin/minions/{hostname}",
		"POST /api/admin/minions/{hostname}/suspend",
		"POST /api/admin/minions/{hostname}/resume",
		"POST /api/admin/minions/{hostname}/set-state",
		"GET /api/admin/minions/{hostname}/vars",
		"POST /api/admin/minions/{hostname}/vars",
		"DELETE /api/admin/minions/{hostname}/vars/{key}",
		"POST /api/admin/revoke/{hostname}",
		"POST /api/admin/keys/rotate",
		"GET /api/admin/security/keys/status",
		"GET /api/admin/security/tokens",
		"GET /api/admin/security/blacklist",
		"POST /api/admin/security/blacklist/purge",
		"GET /api/inventory",
		"POST /api/admin/tokens",
		"GET /api/admin/tokens",
		"POST /api/admin/tokens/{id}/revoke",
		"DELETE /api/admin/tokens/{id}",
		"POST /api/admin/tokens/purge",
		"GET /api/admin/status",
		"GET /api/admin/stats",
		"DELETE /api/admin/minions/{hostname}",
		"GET /api/admin/hooks/log",
		"POST /api/admin/relays",
		"GET /api/admin/relays",
		"GET /api/admin/relays/status",
		"DELETE /api/admin/relays/{id}",
		"POST /api/admin/relays/{id}/revoke",
	}
)

func sortedCopy(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

func equalSets(t *testing.T, name string, got, want []string) {
	t.Helper()
	g, w := sortedCopy(got), sortedCopy(want)
	if len(g) != len(w) {
		t.Errorf("%s routes differ:\n got  %v\n want %v", name, g, w)
		return
	}
	for i := range g {
		if g[i] != w[i] {
			t.Errorf("%s routes differ at %d:\n got  %v\n want %v", name, i, g, w)
			return
		}
	}
}

func TestRoutes_ExposedSurfaceIsExactlyTheDeclaredOne(t *testing.T) {
	n, err := Build(Config{TLSDisable: true, JWTSecret: "s", AdminToken: "a", StateDir: testStateDir(t), InsecureTestState: true, WriteGuard: allowWrites})
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	api, admin, wsRoutes := n.Routes()
	equalSets(t, "public API", api, wantAPIRoutes)
	equalSets(t, "admin", admin, wantAdminRoutes)
	equalSets(t, "WebSocket", wsRoutes, wantWSRoutes)
}

// #176: /api/async_status was removed (its in-memory cache was unbounded and racy, and async jobs
// are polled through exec → async_status.py on the minion). It must never come back unnoticed.
func TestRoutes_NoAsyncStatusEndpoint(t *testing.T) {
	n, err := Build(Config{TLSDisable: true, JWTSecret: "s", AdminToken: "a", StateDir: testStateDir(t), InsecureTestState: true, WriteGuard: allowWrites})
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	api, admin, wsRoutes := n.Routes()
	for _, r := range append(append(append([]string{}, api...), admin...), wsRoutes...) {
		if strings.Contains(r, "async_status") {
			t.Errorf("route %q must not exist (#176)", r)
		}
	}
}
