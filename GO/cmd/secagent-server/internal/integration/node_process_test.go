package integration

// Child side of the harness: one secagent-server NODE per OS process.
//
// The ws / handlers packages keep their state (relay registry, local identity, hooks) in
// package-level variables, so a tree of nodes cannot live in a single process. The harness
// therefore re-executes this test binary once per node (TestNodeProcess); each child assembles
// a node exactly like main.go does (see assembleNode — kept in sync by TestNodeWiringMatchesMain)
// and serves it over TLS on an ephemeral port.
//
// Deliberate, documented deviations from main.go (test plumbing only, no production logic):
//   - one TLS listener (httptest cert) with API + admin + ws routes instead of 7770/7771/7772;
//   - TLS verification disabled for node-to-node links (self-signed test certificate);
//   - short backoff / agent_list interval from the environment so the suite runs in seconds;
//   - no NATS, no InitServerState (RSA-4096 generation is irrelevant to the relay tree);
//   - /__test/close-relay to cut a link with a given close code.

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"
	"time"

	"secagent-server/cmd/secagent-server/internal/config"
	"secagent-server/cmd/secagent-server/internal/forward"
	"secagent-server/cmd/secagent-server/internal/handlers"
	"secagent-server/cmd/secagent-server/internal/hooks"
	"secagent-server/cmd/secagent-server/internal/proxy"
	"secagent-server/cmd/secagent-server/internal/repeater"
	"secagent-server/cmd/secagent-server/internal/storage"
	"secagent-server/cmd/secagent-server/internal/ws"
)

const (
	envNodeProcess      = "NODE_PROCESS"
	envAgentListEvery   = "NODE_AGENT_LIST_INTERVAL"
	envMinBackoff       = "NODE_MIN_BACKOFF"
	envMaxBackoff       = "NODE_MAX_BACKOFF"
	nodeReadyMarkerLine = "NODE_READY "
)

func envDuration(name string, def time.Duration) time.Duration {
	if v, err := time.ParseDuration(os.Getenv(name)); err == nil && v > 0 {
		return v
	}
	return def
}

// TestNodeProcess runs ONE node until its stdin is closed (the parent test process exits).
func TestNodeProcess(t *testing.T) {
	if os.Getenv(envNodeProcess) != "1" {
		t.Skip("child process of the integration harness only")
	}
	handler, shutdown := assembleNode(t)
	srv := httptest.NewUnstartedServer(handler)
	srv.StartTLS()
	fmt.Println(nodeReadyMarkerLine + srv.URL) // the parent reads the address here
	_ = os.Stdout.Sync()
	buf := make([]byte, 1)
	for {
		if _, err := os.Stdin.Read(buf); err != nil {
			break
		}
	}
	shutdown()
	srv.Close()
}

// assembleNode mirrors the node wiring of main.go.
func assembleNode(t *testing.T) (http.Handler, func()) {
	t.Helper()
	insecure := &tls.Config{InsecureSkipVerify: true} //nolint:gosec // self-signed test certificate

	repeaterCfg, err := config.LoadRepeaterConfig()
	if err != nil {
		log.Fatalf("Invalid repeater configuration: %v", err)
	}
	store, err := storage.NewStore(os.Getenv("DATABASE_URL"))
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	handlers.SetAdminStore(store)
	handlers.SetRegisterStore(store)
	proxyRouter := proxy.NewProxyRouter(store)
	handlers.SetProxyRouter(proxyRouter)
	ws.SetJWTSecretsFunc(handlers.GetServerJWTSecrets)
	ws.SetRekeyFunc(handlers.RekeyAgent)

	dispatchCtx, dispatchCancel := context.WithCancel(context.Background())
	dispatcher := hooks.NewDispatcher(store, 1000)
	dispatcher.Start(dispatchCtx)
	hooks.GlobalDispatcher = dispatcher
	ws.DispatchFunc = func(event, hostname, status, enrolledAt string) {
		dispatcher.Dispatch(event, hostname, status, enrolledAt)
	}

	ws.RelayRoutingBulkUpsertFunc = func(relayID string, hostnames []string) error {
		return store.BulkUpsertRelayRouting(relayID, hostnames)
	}
	ws.RelayStatusUpdateFunc = func(relayID, status string, lastSeen int64) error {
		return store.UpdateRelayStatus(relayID, status, lastSeen)
	}
	ws.RelayIsProxyUpdateFunc = func(relayID string, isProxy bool) error {
		return store.SetRelayIsProxy(relayID, isProxy)
	}

	var uplink *repeater.Uplink
	var rc *repeater.Client
	ws.SetRelayLocalIDFunc(func() string {
		if repeaterCfg != nil {
			return repeaterCfg.ID
		}
		return os.Getenv(config.EnvRepeaterID)
	})
	ws.SetRelayAncestorsFunc(func() []string {
		if uplink == nil {
			return nil
		}
		return uplink.Ancestors()
	})
	ws.SetRelayJTIBlacklistFunc(func(jti string) (bool, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return store.IsJTIBlacklisted(ctx, jti)
	})
	ws.SetRelayRevokedFunc(handlers.RelayRevokedCheck)
	ws.SetRelayHostRouteFunc(store.GetRelayForHostname)
	ws.SetRelayNodeRegisterFunc(func(relayID string) error { return registerPullRelay(store, relayID) })

	selfID, _ := ws.RelayIdentity()
	upEvents := make(chan repeater.Event, 256)
	forwarder := &forward.Forwarder{NextHop: store.GetNextHopForHostname}
	upOpts := repeater.Options{
		DirectAgents: directAgents,
		Snapshot:     func() repeater.Snapshot { return buildSnapshot(selfID, store) },
		Events:       upEvents,
		OnTask:       forwarder.Handle,
		// test plumbing (see header)
		TLSConfig:         insecure,
		MinBackoff:        envDuration(envMinBackoff, 50*time.Millisecond),
		MaxBackoff:        envDuration(envMaxBackoff, 400*time.Millisecond),
		AgentListInterval: envDuration(envAgentListEvery, 100*time.Millisecond),
	}
	if repeaterCfg != nil {
		rc = repeater.New(*repeaterCfg, upOpts)
		uplink = rc.Uplink()
		if err := rc.Start(dispatchCtx); err != nil {
			log.Fatalf("Failed to start repeater client: %v", err)
		}
		log.Printf("[OK] Repeater client started (parent=%s)", repeaterCfg.UpstreamURL)
	} else {
		uplink = repeater.NewUplink(selfID, upOpts)
		ws.SetRelayParentLinkFunc(uplink.ServeAccepted)
	}
	ws.SetRelayEventUpstreamFunc(func(m ws.RelayMessage) {
		if repeaterCfg == nil && !uplink.Active() {
			return
		}
		queueUpstream(upEvents, repeater.Event{Event: m.Event, Hostname: m.Hostname, RelayID: m.RelayID, Status: m.Status,
			RelayChain: m.RelayChain, GroupVars: m.GroupVars, Timestamp: m.Timestamp, OldRelay: m.OldRelay, NewRelay: m.NewRelay})
	})

	ws.SetRelayRouteUpsertFunc(func(hostname, relayID string, chain []string) error {
		_, err := store.UpsertRelayRoute(hostname, relayID, chain)
		return err
	})
	ws.SetRelayRouteChainsFunc(func(entries []ws.RouteChainEntry) error {
		rcs := make([]storage.RouteChain, 0, len(entries))
		for _, e := range entries {
			rcs = append(rcs, storage.RouteChain{Hostname: e.Hostname, RelayID: e.RelayID, Chain: e.Chain})
		}
		return store.SetRelayRouteChains(rcs)
	})
	ws.SetRelayConflictFunc(func(c ws.HostConflict, fromBelow bool) {
		if hooks.GlobalDispatcher != nil {
			hooks.GlobalDispatcher.Dispatch("host.conflict", c.Hostname, c.OldRelay+"->"+c.NewRelay, "")
		}
		if !fromBelow && (repeaterCfg != nil || uplink.Active()) {
			queueUpstream(upEvents, repeater.Event{Event: "host.conflict", Hostname: c.Hostname,
				RelayID: c.NewRelay, OldRelay: c.OldRelay, NewRelay: c.NewRelay})
		}
	})

	dialers := repeater.NewDialerManager(dispatchCtx, repeater.DialerOptions{
		Identity:         ws.RelayIdentity,
		WouldLoop:        ws.RelayWouldLoop,
		Serve:            ws.ServeDialedRelay,
		TLSConfig:        insecure,
		MinBackoff:       envDuration(envMinBackoff, 50*time.Millisecond),
		MaxBackoff:       envDuration(envMaxBackoff, 400*time.Millisecond),
		HandshakeTimeout: 0,
	})
	handlers.SetRelayPushHooks(
		func(relayID, url, token string) error {
			return dialers.Start(repeater.DialTarget{RelayID: relayID, URL: url, Token: token})
		},
		dialers.Stop,
	)
	startPushDialers(store, dialers)

	linksProvider := func() repeater.LinksStatus {
		var up *repeater.UpstreamStatus
		switch {
		case rc != nil:
			up = &repeater.UpstreamStatus{Mode: "pull", Peer: rc.ParentID(), LinkStatus: rc.Status()}
		case uplink != nil && uplink.Active():
			up = &repeater.UpstreamStatus{Mode: "push", LinkStatus: repeater.LinkStatus{State: repeater.LinkConnected}}
		}
		return repeater.NewLinksStatus(up, dialers.Statuses())
	}
	handlers.SetLinkStatusFunc(func() interface{} { return linksProvider() })

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		body := map[string]interface{}{"status": "ok", "timestamp": time.Now().Unix()}
		if l := linksProvider(); !l.Empty() {
			body["degraded"] = l.Degraded // public: only the flag, never ids / states / reasons (#154)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(body)
	})
	mux.HandleFunc("POST /api/exec/{hostname}", handlers.ExecCommand)
	mux.HandleFunc("POST /api/upload/{hostname}", handlers.UploadFile)
	mux.HandleFunc("POST /api/fetch/{hostname}", handlers.FetchFile)
	mux.HandleFunc("GET /api/inventory", handlers.GetInventory)
	mux.HandleFunc("POST /api/admin/tokens", handlers.AdminCreateToken)
	mux.HandleFunc("GET /api/admin/tokens", handlers.AdminListTokens)
	mux.HandleFunc("POST /api/admin/tokens/{id}/revoke", handlers.AdminRevokeToken)
	mux.HandleFunc("POST /api/admin/relays", handlers.AdminCreateRelay)
	mux.HandleFunc("GET /api/admin/relays", handlers.AdminListRelays)
	mux.HandleFunc("DELETE /api/admin/relays/{id}", handlers.AdminDeleteRelay)
	mux.HandleFunc("POST /api/admin/relays/{id}/revoke", handlers.AdminRevokeRelay)
	mux.HandleFunc("GET /api/admin/status", handlers.AdminStatus)
	mux.HandleFunc("/ws/agent", ws.AgentHandler)
	mux.HandleFunc("/ws/relay", ws.RelayHandler)
	mux.HandleFunc("POST /__test/close-relay", func(w http.ResponseWriter, r *http.Request) {
		code, _ := strconv.Atoi(r.URL.Query().Get("code"))
		ok := ws.CloseRelay(r.URL.Query().Get("id"), code, "test-induced")
		_ = json.NewEncoder(w).Encode(map[string]bool{"closed": ok})
	})

	return mux, func() { dispatchCancel(); _ = store.Close() }
}

// ── copies of the helpers of main.go (package main cannot be imported) ──────

func directAgents() []repeater.AgentInfo {
	hosts := ws.GetConnectedHostnames()
	out := make([]repeater.AgentInfo, 0, len(hosts))
	for _, h := range hosts {
		out = append(out, repeater.AgentInfo{Hostname: h, Status: "connected"})
	}
	return out
}

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

func startPushDialers(st *storage.Store, mgr *repeater.DialerManager) {
	nodes, err := st.ListRelayNodes()
	if err != nil {
		log.Printf("[RELAY] cannot list relay nodes for push dial-out: %v", err)
		return
	}
	for _, n := range nodes {
		if n.Mode != "push" {
			continue
		}
		token, terr := handlers.OpenPushToken(n.TokenHash)
		if terr != nil {
			log.Printf("[WARN] push relay %s skipped: %v", n.RelayID, terr)
			continue
		}
		if serr := mgr.Start(repeater.DialTarget{RelayID: n.RelayID, URL: n.URL, Token: token}); serr != nil {
			log.Printf("[WARN] push relay %s skipped: %v", n.RelayID, serr)
		}
	}
}

func queueUpstream(ch chan<- repeater.Event, ev repeater.Event) {
	select {
	case ch <- ev:
	default:
		log.Printf("[REPEATER] upstream event queue full, event %s dropped", ev.Event)
	}
}
