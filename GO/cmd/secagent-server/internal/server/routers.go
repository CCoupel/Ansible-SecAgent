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
	// Create routers
	apiRouter := http.NewServeMux()
	adminRouter := http.NewServeMux()
	wsRouter := http.NewServeMux()

	// === PORT 7770: API ENDPOINTS + WebSocket + Admin (backward compat) ===
	apiRouter.HandleFunc("GET /health", n.handleHealth)
	apiRouter.HandleFunc("POST /api/register", handlers.RegisterAgent)
	apiRouter.HandleFunc("POST /api/exec/{hostname}", handlers.ExecCommand)
	apiRouter.HandleFunc("POST /api/upload/{hostname}", handlers.UploadFile)
	apiRouter.HandleFunc("POST /api/fetch/{hostname}", handlers.FetchFile)
	apiRouter.HandleFunc("GET /api/inventory", handlers.GetInventory)
	apiRouter.HandleFunc("GET /api/async_status/{task_id}", handlers.AsyncStatus)
	apiRouter.HandleFunc("POST /api/token/refresh", handlers.TokenRefresh)
	apiRouter.HandleFunc("POST /api/admin/authorize", handlers.AdminAuthorize) // Also on 7770 for compat
	apiRouter.HandleFunc("/ws/agent", ws.AgentHandler)                         // Also serve WS on main port

	// === PORT 7771: ADMIN ENDPOINTS ===
	adminRouter.HandleFunc("POST /api/admin/authorize", handlers.AdminAuthorize)

	// Minions CRUD
	adminRouter.HandleFunc("GET /api/admin/minions", handlers.AdminListMinions)
	adminRouter.HandleFunc("GET /api/admin/minions/{hostname}", handlers.AdminGetMinion)
	adminRouter.HandleFunc("POST /api/admin/minions/{hostname}/suspend", handlers.AdminSuspendMinion)
	adminRouter.HandleFunc("POST /api/admin/minions/{hostname}/resume", handlers.AdminResumeMinion)
	adminRouter.HandleFunc("POST /api/admin/minions/{hostname}/set-state", handlers.AdminSetMinionState)
	adminRouter.HandleFunc("GET /api/admin/minions/{hostname}/vars", handlers.AdminGetMinionVars)
	adminRouter.HandleFunc("POST /api/admin/minions/{hostname}/vars", handlers.AdminSetMinionVars)
	adminRouter.HandleFunc("DELETE /api/admin/minions/{hostname}/vars/{key}", handlers.AdminDeleteMinionVar)

	// Revoke (blacklist JTI + close WS 4001)
	adminRouter.HandleFunc("POST /api/admin/revoke/{hostname}", handlers.AdminRevokeMinion)

	// Key rotation
	adminRouter.HandleFunc("POST /api/admin/keys/rotate", handlers.AdminRotateKeys)

	// Security status endpoints
	adminRouter.HandleFunc("GET /api/admin/security/keys/status", handlers.AdminSecurityKeysStatus)
	adminRouter.HandleFunc("GET /api/admin/security/tokens", handlers.AdminSecurityTokens)
	adminRouter.HandleFunc("GET /api/admin/security/blacklist", handlers.AdminSecurityBlacklist)
	adminRouter.HandleFunc("POST /api/admin/security/blacklist/purge", handlers.AdminSecurityBlacklistPurge)

	// Inventory (admin CLI access via port 7771 — same data as /api/inventory on 7770)
	adminRouter.HandleFunc("GET /api/inventory", handlers.AdminGetInventory)

	// Enrollment + plugin tokens (Phase 10)
	adminRouter.HandleFunc("POST /api/admin/tokens", handlers.AdminCreateToken)
	adminRouter.HandleFunc("GET /api/admin/tokens", handlers.AdminListTokens)
	adminRouter.HandleFunc("POST /api/admin/tokens/{id}/revoke", handlers.AdminRevokeToken)
	adminRouter.HandleFunc("DELETE /api/admin/tokens/{id}", handlers.AdminDeleteToken)
	adminRouter.HandleFunc("POST /api/admin/tokens/purge", handlers.AdminPurgeTokens)

	// Server status / stats
	adminRouter.HandleFunc("GET /api/admin/status", handlers.AdminStatus)
	adminRouter.HandleFunc("GET /api/admin/stats", handlers.AdminStats)

	// Agent deletion (distinct from revoke — removes the DB row)
	adminRouter.HandleFunc("DELETE /api/admin/minions/{hostname}", handlers.AdminDeleteMinion)

	// Hooks execution log (Phase 11 revised)
	adminRouter.HandleFunc("GET /api/admin/hooks/log", handlers.AdminHooksLog)

	// Relay nodes management (Phase 12 — proxy/gateway mode)
	adminRouter.HandleFunc("POST /api/admin/relays", handlers.AdminCreateRelay)
	adminRouter.HandleFunc("GET /api/admin/relays", handlers.AdminListRelays)
	adminRouter.HandleFunc("GET /api/admin/relays/status", handlers.AdminRelaysStatus)
	adminRouter.HandleFunc("DELETE /api/admin/relays/{id}", handlers.AdminDeleteRelay)
	adminRouter.HandleFunc("POST /api/admin/relays/{id}/revoke", handlers.AdminRevokeRelay)

	// === PORT 7772: WEBSOCKET ===
	wsRouter.HandleFunc("/ws/agent", ws.AgentHandler)
	// /ws/relay: always active — relays connect to this server via pull mode
	wsRouter.HandleFunc("/ws/relay", ws.RelayHandler)
	apiRouter.HandleFunc("/ws/relay", ws.RelayHandler) // also on 7770 for compat
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
