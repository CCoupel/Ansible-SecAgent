package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"secagent-server/cmd/secagent-server/internal/broker"
	"secagent-server/cmd/secagent-server/internal/cli"
	"secagent-server/cmd/secagent-server/internal/config"
	"secagent-server/cmd/secagent-server/internal/handlers"
	"secagent-server/cmd/secagent-server/internal/hooks"
	"secagent-server/cmd/secagent-server/internal/proxy"
	"secagent-server/cmd/secagent-server/internal/repeater"
	"secagent-server/cmd/secagent-server/internal/storage"
	"secagent-server/cmd/secagent-server/internal/ws"
)

var store *storage.Store

// isCLIMode returns true when the binary is invoked as a CLI tool.
// CLI mode is active when the first argument is a known subcommand (not a server flag).
// Server flags start with "-" or are absent.
func isCLIMode() bool {
	if len(os.Args) < 2 {
		return false
	}
	first := os.Args[1]
	// Server mode flags start with "-" (e.g. -d, --config)
	if len(first) > 0 && first[0] == '-' {
		return false
	}
	// Known CLI top-level commands
	switch first {
	case "minions", "security", "inventory", "server", "tokens", "hooks", "relays", "help", "completion":
		return true
	}
	return false
}

func main() {
	// Dual-mode: CLI or server
	if isCLIMode() {
		cli.Execute()
		return
	}

	// Load configuration from environment
	jwtSecret := os.Getenv("JWT_SECRET_KEY")
	adminToken := os.Getenv("ADMIN_TOKEN")
	natsURL := os.Getenv("NATS_URL")
	if natsURL == "" {
		natsURL = "nats://localhost:4222"
	}
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		dbURL = "sqlite:///./relay.db"
	}
	logLevel := os.Getenv("LOG_LEVEL")
	if logLevel == "" {
		logLevel = "INFO"
	}

	// PROXY_MODE and PROXY_RELAYS env vars are silently ignored (removed in v3.0 #123).
	// Relay topology is always active: relays connect via /ws/relay (pull mode).
	// Push-mode relay entries in the DB are preserved for future use (#140).

	// Validate required environment variables
	if jwtSecret == "" {
		log.Fatal("JWT_SECRET_KEY environment variable is required")
	}
	if adminToken == "" {
		log.Fatal("ADMIN_TOKEN environment variable is required")
	}

	// Child relay configuration (#124): validated at startup, token never logged.
	repeaterCfg, cfgErr := config.LoadRepeaterConfig()
	if cfgErr != nil {
		log.Fatalf("Invalid repeater configuration: %v", cfgErr)
	}

	log.Printf("[INIT] Ansible-SecAgent GO Server v1.0")
	log.Printf("[INIT] NATS_URL: %s", natsURL)
	log.Printf("[INIT] DATABASE_URL: %s", dbURL)
	log.Printf("[INIT] LOG_LEVEL: %s", logLevel)
	if repeaterCfg != nil {
		log.Printf("[INIT] Repeater child mode: REPEATER_ID=%s upstream=%s", repeaterCfg.ID, repeaterCfg.UpstreamURL)
	}

	// Initialize storage (SQLite)
	log.Println("[INIT] Initializing SQLite database...")
	var err error
	store, err = storage.NewStore(dbURL)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer func() {
		if cerr := store.Close(); cerr != nil {
			log.Printf("store.Close: %v", cerr)
		}
	}()
	log.Println("[OK] Database initialized")

	// Inject store into admin handlers
	handlers.SetAdminStore(store)

	// Inject store into register/token handlers
	handlers.SetRegisterStore(store)

	// Always initialize ProxyRouter — relay WS topology is a core feature (v3.0+).
	// Push-mode relay entries are preserved in the DB but are inert until #140.
	proxyRouter := proxy.NewProxyRouter(store)
	handlers.SetProxyRouter(proxyRouter)

	// Log push-mode relay nodes from DB so operators know they are inert.
	if nodes, listErr := store.ListRelayNodes(); listErr == nil {
		for _, n := range nodes {
			if n.Mode == "push" {
				log.Printf("[RELAY] relay_id=%s mode=push → inert (REST polling removed in v3.0, see #140)", n.RelayID)
			}
		}
	}
	log.Println("[OK] ProxyRouter initialized (pull-mode WS topology)")

	// Load/generate RSA keypair and JWT secrets from DB (idempotent)
	log.Println("[INIT] Loading server keys from DB...")
	if err := handlers.InitServerState(context.Background(), store); err != nil {
		log.Fatalf("Failed to initialize server state: %v", err)
	}
	log.Println("[OK] Server keys loaded")

	// Inject JWT secrets getter into WS handler for dual-key validation
	ws.SetJWTSecretsFunc(handlers.GetServerJWTSecrets)

	// Inject rekey function into WS handler (used when agent connects with previous key)
	ws.SetRekeyFunc(handlers.RekeyAgent)

	// Initialize NATS client (optional — server starts without NATS in degraded mode)
	log.Println("[INIT] Connecting to NATS JetStream...")
	natsClient, err := broker.NewClient(natsURL)
	if err != nil {
		log.Printf("[WARN] NATS unavailable, running in degraded mode: %v", err)
		natsClient = nil
	} else {
		defer func() {
			if cerr := natsClient.Close(); cerr != nil {
				log.Printf("natsClient.Close: %v", cerr)
			}
		}()
		log.Println("[OK] NATS connected")
	}
	_ = natsClient

	// Wire NATS health check into admin status handler
	handlers.NATSHealthCheck = func() bool {
		return natsClient != nil && natsClient.IsConnected()
	}

	// Initialize hooks dispatcher (async event delivery)
	dispatchCtx, dispatchCancel := context.WithCancel(context.Background())
	defer dispatchCancel()
	dispatcher := hooks.NewDispatcher(store, 1000)
	dispatcher.Start(dispatchCtx)
	hooks.GlobalDispatcher = dispatcher

	// Load initial hooks config (absent file is not an error)
	hooksConfigPath := hooks.ConfigPath()
	if initialCfg, err := hooks.LoadConfig(hooksConfigPath); err != nil {
		log.Printf("[WARN] hooks config parse error (%s): %v — hooks disabled", hooksConfigPath, err)
	} else if initialCfg == nil {
		log.Printf("[INFO] hooks config not found at %s — 0 hooks active", hooksConfigPath)
	} else {
		dispatcher.SetConfig(initialCfg)
	}

	// Wire DispatchFunc into ws package (avoids import cycle ws→hooks)
	ws.DispatchFunc = func(event, hostname, status, enrolledAt string) {
		dispatcher.Dispatch(event, hostname, status, enrolledAt)
	}
	log.Println("[OK] Hooks dispatcher started")

	// Wire relay routing/status update functions into ws package (avoids import cycle ws→storage)
	ws.RelayRoutingBulkUpsertFunc = func(relayID string, hostnames []string) error {
		return store.BulkUpsertRelayRouting(relayID, hostnames)
	}
	ws.RelayStatusUpdateFunc = func(relayID, status string, lastSeen int64) error {
		return store.UpdateRelayStatus(relayID, status, lastSeen)
	}
	ws.RelayIsProxyUpdateFunc = func(relayID string, isProxy bool) error {
		return store.SetRelayIsProxy(relayID, isProxy)
	}

	// Tree topology (#125): identity, ancestors and node registration used by /ws/relay.
	var rc *repeater.Client
	ws.SetRelayLocalIDFunc(func() string {
		if repeaterCfg != nil {
			return repeaterCfg.ID
		}
		return os.Getenv(config.EnvRepeaterID)
	})
	ws.SetRelayAncestorsFunc(func() []string {
		if rc == nil {
			return nil
		}
		return rc.Ancestors()
	})
	ws.SetRelayNodeRegisterFunc(func(relayID string) error { return registerPullRelay(store, relayID) })

	// Child relay (#125): one goroutine keeps the WSS link to the unique parent.
	if repeaterCfg != nil {
		events := make(chan repeater.Event, 256)
		ws.SetRelayEventUpstreamFunc(func(m ws.RelayMessage) {
			ev := repeater.Event{Event: m.Event, Hostname: m.Hostname, RelayID: m.RelayID, Status: m.Status,
				RelayChain: m.RelayChain, GroupVars: m.GroupVars, Timestamp: m.Timestamp}
			select {
			case events <- ev:
			default:
				log.Printf("[REPEATER] upstream event queue full, event %s dropped", m.Event)
			}
		})
		rc = repeater.New(*repeaterCfg, repeater.Options{
			DirectAgents: directAgents,
			Snapshot:     func() repeater.Snapshot { return buildSnapshot(repeaterCfg.ID, store) },
			Events:       events,
		})
		if err := rc.Start(dispatchCtx); err != nil {
			log.Fatalf("Failed to start repeater client: %v", err)
		}
		log.Printf("[OK] Repeater client started (parent=%s)", repeaterCfg.UpstreamURL)
	}

	// Create routers
	apiRouter := http.NewServeMux()
	adminRouter := http.NewServeMux()
	wsRouter := http.NewServeMux()

	// === PORT 7770: API ENDPOINTS + WebSocket + Admin (backward compat) ===
	apiRouter.HandleFunc("GET /health", handleHealth)
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

	// === PORT 7772: WEBSOCKET ===
	wsRouter.HandleFunc("/ws/agent", ws.AgentHandler)
	// /ws/relay: always active — relays connect to this server via pull mode
	wsRouter.HandleFunc("/ws/relay", ws.RelayHandler)
	apiRouter.HandleFunc("/ws/relay", ws.RelayHandler) // also on 7770 for compat
	log.Println("[RELAY] /ws/relay endpoint enabled")

	// Create HTTP servers
	apiServer := &http.Server{
		Addr:         ":7770",
		Handler:      apiRouter,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	adminServer := &http.Server{
		Addr:         ":7771",
		Handler:      adminRouter,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	wsServer := &http.Server{
		Addr:         ":7772",
		Handler:      wsRouter,
		ReadTimeout:  60 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Start servers in goroutines
	go func() {
		log.Printf("[LISTEN] API server starting on %s", apiServer.Addr)
		if err := apiServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("API server error: %v", err)
		}
	}()

	go func() {
		log.Printf("[LISTEN] Admin server starting on %s", adminServer.Addr)
		if err := adminServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Admin server error: %v", err)
		}
	}()

	go func() {
		log.Printf("[LISTEN] WebSocket server starting on %s", wsServer.Addr)
		if err := wsServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("WebSocket server error: %v", err)
		}
	}()

	// Verify servers are listening
	time.Sleep(100 * time.Millisecond)
	if !isListening(":7770") || !isListening(":7771") || !isListening(":7772") {
		log.Fatal("Failed to start all servers")
	}
	log.Println("[OK] All servers running")
	log.Println("[OK] Ansible-SecAgent GO Server ready")

	// SIGHUP → hot-reload hooks config
	sighupChan := make(chan os.Signal, 1)
	signal.Notify(sighupChan, syscall.SIGHUP)
	go func() {
		for range sighupChan {
			log.Println("[HOOKS] SIGHUP received — reloading hooks config")
			cfg, err := hooks.LoadConfig(hooksConfigPath)
			if err != nil {
				log.Printf("[WARN] hooks config reload error: %v — keeping previous config", err)
			} else {
				dispatcher.SetConfig(cfg)
			}
		}
	}()

	// Wait for interrupt signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGINT)
	<-sigChan

	log.Println("[SHUTDOWN] Shutting down servers...")

	// Graceful shutdown with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := apiServer.Shutdown(ctx); err != nil {
		log.Printf("API server shutdown error: %v", err)
	}
	if err := adminServer.Shutdown(ctx); err != nil {
		log.Printf("Admin server shutdown error: %v", err)
	}
	if err := wsServer.Shutdown(ctx); err != nil {
		log.Printf("WebSocket server shutdown error: %v", err)
	}

	log.Println("[OK] Shutdown complete")
}

// Health check endpoint — returns "ok" for backward compatibility with Python server
func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if _, err := fmt.Fprintf(w, `{"status":"ok","timestamp":%d}`, time.Now().Unix()); err != nil {
		log.Printf("handleHealth write: %v", err)
	}
}

// Helper to check if port is listening
func isListening(addr string) bool {
	conn, err := net.DialTimeout("tcp", "localhost"+addr, 1*time.Second)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// directAgents lists the agents connected directly to this node (1 level).
func directAgents() []repeater.AgentInfo {
	hosts := ws.GetConnectedHostnames()
	out := make([]repeater.AgentInfo, 0, len(hosts))
	for _, h := range hosts {
		out = append(out, repeater.AgentInfo{Hostname: h, Status: "connected"})
	}
	return out
}

// buildSnapshot describes the subtree of this relay for topology_snapshot:
// direct agents plus the descendant relays (and their routed agents).
// relay_chain always starts with this relay's own id (cf. ARCHITECTURE §23.2).
func buildSnapshot(selfID string, st *storage.Store) repeater.Snapshot {
	snap := repeater.Snapshot{}
	for _, h := range ws.GetConnectedHostnames() {
		snap.Agents = append(snap.Agents, repeater.TopoAgent{Hostname: h, RelayID: selfID, RelayChain: []string{selfID}})
	}
	nodes, err := st.ListRelayNodes()
	if err != nil {
		log.Printf("[REPEATER] snapshot: list relay nodes: %v", err)
		return snap
	}
	for _, n := range nodes {
		chain := []string{selfID, n.RelayID}
		snap.Relays = append(snap.Relays, repeater.TopoRelay{RelayID: n.RelayID, RelayChain: chain})
		hosts, herr := st.ListRelayRouting(n.RelayID)
		if herr != nil {
			log.Printf("[REPEATER] snapshot: routing for %s: %v", n.RelayID, herr)
			continue
		}
		for _, h := range hosts {
			snap.Agents = append(snap.Agents, repeater.TopoAgent{Hostname: h, RelayID: n.RelayID, RelayChain: chain})
		}
	}
	return snap
}

// registerPullRelay idempotently records a relay that connected to us (mode=pull).
// An existing declaration (e.g. admin-created) is kept: only its status/last_seen change.
func registerPullRelay(st *storage.Store, relayID string) error {
	existing, err := st.GetRelayNode(relayID)
	if err != nil {
		return fmt.Errorf("get relay node: %w", err)
	}
	now := time.Now().UTC().Unix()
	if existing != nil {
		return st.UpdateRelayStatus(relayID, "connected", now)
	}
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return fmt.Errorf("generate id: %w", err)
	}
	return st.UpsertRelayNode(storage.RelayNode{
		ID: hex.EncodeToString(b), RelayID: relayID, Mode: "pull", Status: "connected", LastSeen: &now,
	})
}
