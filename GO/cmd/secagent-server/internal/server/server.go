package server

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"secagent-server/cmd/secagent-server/internal/actionlog"
	"secagent-server/cmd/secagent-server/internal/config"
	"secagent-server/cmd/secagent-server/internal/forward"
	"secagent-server/cmd/secagent-server/internal/handlers"
	"secagent-server/cmd/secagent-server/internal/hooks"
	"secagent-server/cmd/secagent-server/internal/logsafe"
	"secagent-server/cmd/secagent-server/internal/proxy"
	"secagent-server/cmd/secagent-server/internal/repeater"
	"secagent-server/cmd/secagent-server/internal/state"
	"secagent-server/cmd/secagent-server/internal/storage"
	"secagent-server/cmd/secagent-server/internal/ws"
)

// shutdownTimeout bounds the graceful shutdown of the HTTP servers.
const shutdownTimeout = 30 * time.Second

// Node is one built secagent-server: every component is wired, nothing listens yet.
// The hooks of the ws and handlers packages are package-level variables, so one process runs
// ONE Node (tests start one process per node).
type Node struct {
	cfg Config

	store       *storage.Store
	dispatcher  *hooks.Dispatcher
	journal     *actionlog.Journal
	hooksPath   string
	dispatchCtx context.Context
	cancel      context.CancelFunc

	uplink  *repeater.Uplink
	rc      *repeater.Client // set when REPEATER_UPSTREAM_* configures a pull parent
	dialers *repeater.DialerManager

	// healthLinks feeds /health "degraded" (set from linksStatus; replaceable in tests)
	healthLinks func() repeater.LinksStatus

	apiHandler, adminHandler, wsHandler http.Handler
	apiRoutes, adminRoutes, wsRoutes    []string
	apiSrv, adminSrv, wsSrv             *http.Server
	certs                               *certStore // nil: plain HTTP (TLS_DISABLE=true)

	closeOnce sync.Once
	ready     chan struct{}
	apiAddr   string // effective addresses once listening
	adminAddr string
	wsAddr    string
	addrMu    sync.Mutex
}

// Build wires every component in the production order (store, JWT secrets, hooks, revocation and
// blacklist checks BEFORE any listener exists) and returns the Node. It does not listen.
// On error everything already opened is released.
func Build(cfg Config) (node *Node, err error) {
	logsafe.Install() // one log call = one line, whatever a peer or a legacy row put in a value
	n := &Node{cfg: cfg, ready: make(chan struct{})}
	defer func() {
		if err != nil {
			n.Close()
		}
	}()

	// TLS first (#175): a missing, partial or invalid certificate pair refuses the start before
	// anything else is opened (unless the explicit test-only TLS_DISABLE=true).
	if err := n.prepareTLS(); err != nil {
		return nil, err
	}

	repeaterCfg := cfg.Repeater
	log.Printf("[INIT] Ansible-SecAgent GO Server v1.0")
	if os.Getenv("NATS_URL") != "" {
		// NATS was never on the dispatch path (WebSocket direct): ignoring the variable has no
		// functional effect, so this is a warning, not an error (unlike DATABASE_URL, #160).
		log.Printf("[WARN] NATS_URL is obsolete and ignored (NATS removed in v3.0.3)")
	}
	log.Printf("[INIT] DATABASE_URL: %s", cfg.DatabaseURL)
	log.Printf("[INIT] LOG_LEVEL: %s", cfg.LogLevel)
	if repeaterCfg != nil {
		log.Printf("[INIT] Repeater child mode: REPEATER_ID=%s upstream=%s", repeaterCfg.ID, repeaterCfg.UpstreamURL)
	}

	// X-Forwarded-For is trusted only behind these proxies (#177); invalid CIDR = no start.
	proxies, perr := handlers.ParseTrustedProxyCIDRs(cfg.TrustedProxyCIDRs)
	if perr != nil {
		return nil, perr
	}
	handlers.SetTrustedProxies(proxies)

	// Bootstrap secrets from the Config (init() read the same values from the environment).
	handlers.ConfigureServer(cfg.JWTSecret, cfg.AdminToken)

	// Initialize storage (SQLite)
	log.Println("[INIT] Initializing SQLite database...")
	store, err := storage.NewStore(cfg.DatabaseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize database: %w", err)
	}
	n.store = store
	log.Println("[OK] Database initialized")

	// Inject store into admin handlers
	handlers.SetAdminStore(store)

	// Inject store into register/token handlers
	handlers.SetRegisterStore(store)

	// Always initialize ProxyRouter — relay WS topology is a core feature (v3.0+).
	proxyRouter := proxy.NewProxyRouter(store)
	handlers.SetProxyRouter(proxyRouter)

	log.Println("[OK] ProxyRouter initialized (pull-mode WS topology)")

	// Load/generate RSA keypair and JWT secrets from DB (idempotent)
	log.Println("[INIT] Loading server keys from DB...")
	if err := handlers.InitServerState(context.Background(), store); err != nil {
		return nil, fmt.Errorf("failed to initialize server state: %w", err)
	}
	log.Println("[OK] Server keys loaded")

	// Inject JWT secrets getter into WS handler for dual-key validation
	ws.SetJWTSecretsFunc(handlers.GetServerJWTSecrets)

	// Revocation / token-replacement check of /ws/agent (#169, fail closed without it).
	ws.SetAgentJTICheckFunc(agentJTICheck(store))

	// Inject rekey function into WS handler (used when agent connects with previous key)
	ws.SetRekeyFunc(handlers.RekeyAgent)

	// Initialize hooks dispatcher (async event delivery)
	n.dispatchCtx, n.cancel = context.WithCancel(context.Background())
	dispatchCtx := n.dispatchCtx
	journal, jerr := actionlog.Open(actionlog.Options{Path: actionlog.PathFromEnv(state.DirFromEnv())})
	if jerr != nil {
		return nil, fmt.Errorf("failed to prepare the action journal: %w", jerr)
	}
	n.journal = journal
	handlers.SetActionJournal(journal)
	dispatcher := hooks.NewDispatcher(journal, hooks.QueueSizeFromEnv())
	dispatcher.Start(dispatchCtx)
	hooks.GlobalDispatcher = dispatcher
	n.dispatcher = dispatcher

	// Load initial hooks config (absent file is not an error)
	hooksConfigPath := hooks.ConfigPath()
	n.hooksPath = hooksConfigPath
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

	// Tree topology (#125/#140): identity, ancestors, registration and revocation used by /ws/relay.
	ws.SetRelayLocalIDFunc(func() string {
		if repeaterCfg != nil {
			return repeaterCfg.ID
		}
		return os.Getenv(config.EnvRepeaterID)
	})
	ws.SetRelayAncestorsFunc(func() []string {
		if n.uplink == nil {
			return nil
		}
		return n.uplink.Ancestors()
	})
	ws.SetRelayJTIBlacklistFunc(func(jti string) (bool, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return store.IsJTIBlacklisted(ctx, jti)
	})
	ws.SetRelayRevokedFunc(handlers.RelayRevokedCheck)
	ws.SetRelayHostRouteFunc(store.GetRelayForHostname)
	ws.SetRelayNodeRegisterFunc(func(relayID string) error { return registerPullRelay(store, relayID) })
	// Ansible group vars of the relays (#139): stored per relay, served in the inventory.
	ws.SetRelayGroupVarsFunc(func(relayID, groupVarsJSON string) error {
		_, err := store.SetRelayGroupVars(relayID, groupVarsJSON)
		return err
	})
	handlers.SetLocalGroupVars(cfg.GroupVars)

	// Upstream publisher shared by the two ways of having a parent: we dial it (pull, #125) or it
	// dials us (push, #140). A node has a single parent: with REPEATER_UPSTREAM_* configured,
	// links opened by a parent are refused.
	selfID, _ := ws.RelayIdentity()
	upEvents := make(chan repeater.Event, 256)
	// A child link changed the subtree below us (snapshot accepted, link closed): our parent gets a
	// full topology_snapshot again. Non-blocking, coalesced by the uplink.
	topoChanged := make(chan struct{}, 1)
	ws.SetRelayTopologyChangedFunc(func() {
		select {
		case topoChanged <- struct{}{}:
		default:
		}
	})
	// Tasks sent down by our parent: resolve the next hop (live agent first, then relay_routing).
	forwarder := &forward.Forwarder{NextHop: store.GetNextHopForHostname, Suspended: handlers.AgentSuspended}
	upOpts := repeater.Options{
		GroupVars:       cfg.GroupVars,
		DirectAgents:    directAgents,
		Snapshot:        func() repeater.Snapshot { return buildSnapshot(selfID, store) },
		Events:          upEvents,
		TopologyChanged: topoChanged,
		OnTask:          forwarder.Handle,
	}
	dialerOpts := repeater.DialerOptions{
		Identity:  ws.RelayIdentity,
		WouldLoop: ws.RelayWouldLoop,
		Serve:     ws.ServeDialedRelay,
	}
	if cfg.Tune != nil { // test seam: durations only, applied before anything is created
		cfg.Tune(&upOpts, &dialerOpts)
	}
	if repeaterCfg != nil {
		n.rc = repeater.New(*repeaterCfg, upOpts)
		n.uplink = n.rc.Uplink()
		if err := n.rc.Start(dispatchCtx); err != nil {
			return nil, fmt.Errorf("failed to start repeater client: %w", err)
		}
		log.Printf("[OK] Repeater client started (parent=%s)", repeaterCfg.UpstreamURL)
	} else {
		n.uplink = repeater.NewUplink(selfID, upOpts)
		ws.SetRelayParentLinkFunc(n.uplink.ServeAccepted)
	}
	ws.SetRelayEventUpstreamFunc(func(m ws.RelayMessage) {
		// Root without a parent link: nothing to forward to.
		if repeaterCfg == nil && !n.uplink.Active() {
			return
		}
		queueUpstream(upEvents, repeater.Event{Event: m.Event, Hostname: m.Hostname, RelayID: m.RelayID, Status: m.Status,
			RelayChain: m.RelayChain, GroupVars: m.GroupVars, Timestamp: m.Timestamp, OldRelay: m.OldRelay, NewRelay: m.NewRelay,
			EnrolledAt: m.EnrolledAt})
	})

	// Event propagation (#126). Local events of this node (agent connect / disconnect, enrollment)
	// go up to the parent; the uplink appends this node's id to relay_chain. A link that is not
	// established drops them: the snapshot sent at the next connection re-synchronizes the parent.
	dispatcher.SetUpstream(func(event, hostname, status, enrolledAt string) {
		if !n.uplink.Active() {
			return
		}
		queueUpstream(upEvents, repeater.Event{Event: event, Hostname: hostname, Status: status,
			EnrolledAt: enrolledAt, Timestamp: time.Now().UTC().Format(time.RFC3339)})
	})
	// Events received from a child run THIS node's hooks with the received relay_chain.
	ws.SetRelayEventLocalFunc(func(event, hostname, status, enrolledAt string, relayChain []string) {
		dispatcher.DispatchChain(event, hostname, status, enrolledAt, relayChain)
	})

	// Hierarchical routing (#127): chains of snapshot routes, event-driven routes, host.conflict.
	ws.SetRelayRouteUpsertFunc(func(hostname, relayID string, chain []string) error {
		_, err := store.UpsertRelayRoute(hostname, relayID, chain)
		return err
	})
	ws.SetRelayChainFunc(func(relayID string, chain []string) error {
		_, err := store.SetRelayChain(relayID, chain)
		return err
	})
	ws.SetRelayRouteChainsFunc(func(entries []ws.RouteChainEntry) error {
		rc := make([]storage.RouteChain, 0, len(entries))
		for _, e := range entries {
			rc = append(rc, storage.RouteChain{Hostname: e.Hostname, RelayID: e.RelayID, Chain: e.Chain})
		}
		return store.SetRelayRouteChains(rc)
	})
	ws.SetRelayConflictFunc(func(c ws.HostConflict, fromBelow bool) {
		// Hooks fire at every level; a conflict detected HERE is also reported upstream
		// (one detected below already travels as its own event_forward).
		if hooks.GlobalDispatcher != nil {
			hooks.GlobalDispatcher.Dispatch("host.conflict", c.Hostname, c.OldRelay+"->"+c.NewRelay, "")
		}
		if !fromBelow && (repeaterCfg != nil || n.uplink.Active()) {
			queueUpstream(upEvents, repeater.Event{Event: "host.conflict", Hostname: c.Hostname,
				RelayID: c.NewRelay, OldRelay: c.OldRelay, NewRelay: c.NewRelay})
		}
	})

	// Push mode (#140): the parent dials its push children (relay_nodes.mode=push).
	n.dialers = repeater.NewDialerManager(dispatchCtx, dialerOpts)
	handlers.SetRelayPushHooks(
		func(relayID, url, token string) error {
			return n.dialers.Start(repeater.DialTarget{RelayID: relayID, URL: url, Token: token})
		},
		n.dialers.Stop,
	)
	startPushDialers(store, n.dialers)

	// Link status (#154): /health "degraded" and the admin status "links".
	n.healthLinks = n.linksStatus
	handlers.SetLinkStatusFunc(func() interface{} { return n.linksStatus() })

	n.buildRouters()
	return n, nil
}

// linksStatus summarizes the parent / push-child links (#154).
func (n *Node) linksStatus() repeater.LinksStatus {
	var up *repeater.UpstreamStatus
	switch {
	case n.rc != nil:
		up = &repeater.UpstreamStatus{Mode: "pull", Peer: n.rc.ParentID(), LinkStatus: n.rc.Status()}
	case n.uplink != nil && n.uplink.Active():
		up = &repeater.UpstreamStatus{Mode: "push", LinkStatus: repeater.LinkStatus{State: repeater.LinkConnected}}
	}
	return repeater.NewLinksStatus(up, n.dialers.Statuses())
}

// ReloadHooks re-reads the hooks configuration (SIGHUP). A broken file keeps the previous config.
func (n *Node) ReloadHooks() {
	log.Println("[HOOKS] SIGHUP received — reloading hooks config")
	cfg, err := hooks.LoadConfig(n.hooksPath)
	if err != nil {
		log.Printf("[WARN] hooks config reload error: %v — keeping previous config", err)
		return
	}
	n.dispatcher.SetConfig(cfg)
}

// Close releases everything Build opened (dialers and repeater client, hooks dispatcher,
// store). It is idempotent and also called by Run on exit.
func (n *Node) Close() {
	n.closeOnce.Do(func() {
		if n.cancel != nil {
			n.cancel()
		}
		if n.journal != nil {
			if err := n.journal.Close(); err != nil {
				log.Printf("action journal close: %v", err)
			}
		}
		if n.store != nil {
			if err := n.store.Close(); err != nil {
				log.Printf("store.Close: %v", err)
			}
		}
	})
}

// APIHandler, AdminHandler and WSHandler expose the routers (tests: no socket needed).
func (n *Node) APIHandler() http.Handler   { return n.apiHandler }
func (n *Node) AdminHandler() http.Handler { return n.adminHandler }
func (n *Node) WSHandler() http.Handler    { return n.wsHandler }

// Routes returns the registered patterns of each router ("METHOD /path" or "/path").
func (n *Node) Routes() (api, admin, wsRoutes []string) {
	return append([]string(nil), n.apiRoutes...), append([]string(nil), n.adminRoutes...), append([]string(nil), n.wsRoutes...)
}

// Ready is closed once all listeners are up.
func (n *Node) Ready() <-chan struct{} { return n.ready }

// Addrs returns the effective listen addresses (valid after Ready).
func (n *Node) Addrs() (api, admin, wsAddr string) {
	n.addrMu.Lock()
	defer n.addrMu.Unlock()
	return n.apiAddr, n.adminAddr, n.wsAddr
}

// Run listens on the three addresses, serves until ctx is cancelled (or a server fails), then
// shuts down gracefully and releases the node. It returns nil on a requested shutdown.
func (n *Node) Run(ctx context.Context) error {
	defer n.Close()

	type srvSpec struct {
		name  string
		srv   *http.Server
		ln    net.Listener
		addr  string
		label string // address shown in the log: the configured one, or the injected listener's
		tls   bool
	}
	specs := []*srvSpec{
		{name: "API server", srv: n.apiSrv, ln: n.cfg.APIListener, addr: n.cfg.apiAddr()},
		{name: "Admin server", srv: n.adminSrv, ln: n.cfg.AdminListener, addr: n.cfg.adminAddr()},
		{name: "WebSocket server", srv: n.wsSrv, ln: n.cfg.WSListener, addr: n.cfg.wsAddr()},
	}
	for i, s := range specs {
		s.tls = n.applyTLS(s.srv, i == 1)
	}
	// Bind first: a port conflict fails here, before anything is served.
	for _, s := range specs {
		s.label = s.addr
		if s.ln != nil {
			s.label = s.ln.Addr().String()
		}
		if s.ln == nil {
			ln, err := net.Listen("tcp", s.addr)
			if err != nil {
				for _, o := range specs {
					if o.ln != nil {
						_ = o.ln.Close()
					}
				}
				return fmt.Errorf("failed to start all servers: %s on %s: %w", s.name, s.addr, err)
			}
			s.ln = ln
		}
		s.srv.Addr = s.ln.Addr().String()
	}

	// Hot reload of the certificate pair: polling of the files' content, and SIGHUP.
	stopTLSWatch := make(chan struct{})
	defer close(stopTLSWatch)
	if n.certs != nil {
		go n.certs.watch(n.cfg.TLSReloadInterval, stopTLSWatch)
		hup := make(chan os.Signal, 1)
		signal.Notify(hup, syscall.SIGHUP)
		defer signal.Stop(hup)
		go func() {
			for {
				select {
				case <-hup:
					log.Printf("[INIT] SIGHUP received: reloading the TLS certificate")
					n.certs.reload(true)
				case <-stopTLSWatch:
					return
				}
			}
		}()
	}

	errCh := make(chan error, len(specs))
	for _, s := range specs {
		go func() {
			var err error
			if s.tls {
				log.Printf("[LISTEN] %s starting on %s (TLS)", s.name, s.label)
				err = s.srv.ServeTLS(s.ln, "", "") // certificate from TLSConfig.GetCertificate
			} else {
				log.Printf("[LISTEN] %s starting on %s", s.name, s.label)
				err = s.srv.Serve(s.ln)
			}
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				errCh <- fmt.Errorf("%s error: %w", s.name, err)
			}
		}()
	}
	n.addrMu.Lock()
	n.apiAddr, n.adminAddr, n.wsAddr = specs[0].ln.Addr().String(), specs[1].ln.Addr().String(), specs[2].ln.Addr().String()
	n.addrMu.Unlock()

	// Verify servers are listening (effective addresses)
	time.Sleep(100 * time.Millisecond)
	for _, s := range specs {
		if !isListening(s.ln.Addr()) {
			n.shutdownServers()
			return errors.New("failed to start all servers")
		}
	}
	log.Println("[OK] All servers running")
	log.Println("[OK] Ansible-SecAgent GO Server ready")
	close(n.ready)

	var runErr error
	select {
	case <-ctx.Done():
	case runErr = <-errCh:
	}

	log.Println("[SHUTDOWN] Shutting down servers...")
	n.shutdownServers()
	if runErr == nil && n.dispatcher != nil { // clean stop: flush the hooks queue (bounded), then count what is left
		if left := n.dispatcher.Drain(hooks.DefaultDrainTimeout); left > 0 {
			log.Printf("[SHUTDOWN] hooks: %d event(s) still pending after %s — they are lost", left, hooks.DefaultDrainTimeout)
		}
	}
	log.Println("[OK] Shutdown complete")
	return runErr
}

func (n *Node) shutdownServers() {
	// Graceful shutdown with timeout
	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	for _, s := range []struct {
		name string
		srv  *http.Server
	}{{"API", n.apiSrv}, {"Admin", n.adminSrv}, {"WebSocket", n.wsSrv}} {
		if err := s.srv.Shutdown(ctx); err != nil {
			log.Printf("%s server shutdown error: %v", s.name, err)
		}
	}
}
