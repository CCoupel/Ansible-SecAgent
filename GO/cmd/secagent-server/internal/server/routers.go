package server

import (
	"log"
	"net/http"
	"time"

	"secagent-server/cmd/secagent-server/internal/handlers"
	"secagent-server/cmd/secagent-server/internal/ws"
)

// buildRouters creates the three routers and HTTP servers. Admin handlers live ONLY on the admin
// router (port 7771); the public router carries just the API, the agent/relay WebSocket and the
// register/authorize endpoints.
func (n *Node) buildRouters() {
	// Create routers; every registration is also recorded so tests can check the public/admin split.
	apiRouter := http.NewServeMux()
	adminRouter := http.NewServeMux()
	wsRouter := http.NewServeMux()
	n.apiRoutes, n.adminRoutes, n.wsRoutes = nil, nil, nil
	apiH := func(pattern string, h http.HandlerFunc) {
		apiRouter.HandleFunc(pattern, h)
		n.apiRoutes = append(n.apiRoutes, pattern)
	}
	adminH := func(pattern string, h http.HandlerFunc) {
		adminRouter.HandleFunc(pattern, h)
		n.adminRoutes = append(n.adminRoutes, pattern)
	}
	wsH := func(pattern string, h http.HandlerFunc) {
		wsRouter.HandleFunc(pattern, h)
		n.wsRoutes = append(n.wsRoutes, pattern)
	}

	// === PORT 7770: API ENDPOINTS + WebSocket + Admin (backward compat) ===
	apiH("GET /health", n.handleHealth)
	apiH("POST /api/register", handlers.RegisterAgent)
	apiH("POST /api/exec/{hostname}", handlers.ExecCommand)
	apiH("POST /api/upload/{hostname}", handlers.UploadFile)
	apiH("POST /api/fetch/{hostname}", handlers.FetchFile)
	apiH("GET /api/inventory", handlers.GetInventory)
	apiH("GET /api/async_status/{task_id}", handlers.AsyncStatus)
	apiH("POST /api/token/refresh", handlers.TokenRefresh)
	apiH("POST /api/admin/authorize", handlers.AdminAuthorize) // Also on 7770 for compat
	apiH("/ws/agent", ws.AgentHandler)                         // Also serve WS on main port

	// === PORT 7771: ADMIN ENDPOINTS ===
	adminH("POST /api/admin/authorize", handlers.AdminAuthorize)

	// Minions CRUD
	adminH("GET /api/admin/minions", handlers.AdminListMinions)
	adminH("GET /api/admin/minions/{hostname}", handlers.AdminGetMinion)
	adminH("POST /api/admin/minions/{hostname}/suspend", handlers.AdminSuspendMinion)
	adminH("POST /api/admin/minions/{hostname}/resume", handlers.AdminResumeMinion)
	adminH("POST /api/admin/minions/{hostname}/set-state", handlers.AdminSetMinionState)
	adminH("GET /api/admin/minions/{hostname}/vars", handlers.AdminGetMinionVars)
	adminH("POST /api/admin/minions/{hostname}/vars", handlers.AdminSetMinionVars)
	adminH("DELETE /api/admin/minions/{hostname}/vars/{key}", handlers.AdminDeleteMinionVar)

	// Revoke (blacklist JTI + close WS 4001)
	adminH("POST /api/admin/revoke/{hostname}", handlers.AdminRevokeMinion)

	// Key rotation
	adminH("POST /api/admin/keys/rotate", handlers.AdminRotateKeys)

	// Security status endpoints
	adminH("GET /api/admin/security/keys/status", handlers.AdminSecurityKeysStatus)
	adminH("GET /api/admin/security/tokens", handlers.AdminSecurityTokens)
	adminH("GET /api/admin/security/blacklist", handlers.AdminSecurityBlacklist)
	adminH("POST /api/admin/security/blacklist/purge", handlers.AdminSecurityBlacklistPurge)

	// Inventory (admin CLI access via port 7771 — same data as /api/inventory on 7770)
	adminH("GET /api/inventory", handlers.AdminGetInventory)

	// Enrollment + plugin tokens (Phase 10)
	adminH("POST /api/admin/tokens", handlers.AdminCreateToken)
	adminH("GET /api/admin/tokens", handlers.AdminListTokens)
	adminH("POST /api/admin/tokens/{id}/revoke", handlers.AdminRevokeToken)
	adminH("DELETE /api/admin/tokens/{id}", handlers.AdminDeleteToken)
	adminH("POST /api/admin/tokens/purge", handlers.AdminPurgeTokens)

	// Server status / stats
	adminH("GET /api/admin/status", handlers.AdminStatus)
	adminH("GET /api/admin/stats", handlers.AdminStats)

	// Agent deletion (distinct from revoke — removes the DB row)
	adminH("DELETE /api/admin/minions/{hostname}", handlers.AdminDeleteMinion)

	// Hooks execution log (Phase 11 revised)
	adminH("GET /api/admin/hooks/log", handlers.AdminHooksLog)

	// Relay nodes management (Phase 12 — proxy/gateway mode)
	adminH("POST /api/admin/relays", handlers.AdminCreateRelay)
	adminH("GET /api/admin/relays", handlers.AdminListRelays)
	adminH("GET /api/admin/relays/status", handlers.AdminRelaysStatus)
	adminH("DELETE /api/admin/relays/{id}", handlers.AdminDeleteRelay)
	adminH("POST /api/admin/relays/{id}/revoke", handlers.AdminRevokeRelay)

	// === PORT 7772: WEBSOCKET ===
	wsH("/ws/agent", ws.AgentHandler)
	// /ws/relay: always active — relays connect to this server via pull mode
	wsH("/ws/relay", ws.RelayHandler)
	apiH("/ws/relay", ws.RelayHandler) // also on 7770 for compat
	log.Println("[RELAY] /ws/relay endpoint enabled")

	n.apiHandler, n.adminHandler, n.wsHandler = apiRouter, adminRouter, wsRouter

	// Create HTTP servers
	n.apiSrv = &http.Server{
		Handler:      apiRouter,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	n.adminSrv = &http.Server{
		Handler:      adminRouter,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	n.wsSrv = &http.Server{
		Handler:      wsRouter,
		ReadTimeout:  60 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
}
