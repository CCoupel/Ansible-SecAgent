// Phase 12 — relay_handler.go
// WebSocket handler for /ws/relay — mode pull.
//
// Relays connect here with a JWT (role=relay) and announce their agents.
// The proxy then dispatches tasks to the relay via this connection.
//
// Close codes (relay-specific):
//
//	4010 — relay token revoked
//	4011 — relay token expired
//	4000 — normal close
package ws

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// Relay-specific WebSocket close codes.
const (
	WSRelayCloseRevoked = 4010
	WSRelayCloseExpired = 4011
	WSRelayCloseNormal  = 4000
)

// ── Types ─────────────────────────────────────────────────────────────────────

// RelayConnection represents an active WebSocket connection from a downstream relay.
type RelayConnection struct {
	RelayID string
	IsProxy bool
	Conn    interface{ WriteJSON(interface{}) error } // *websocket.Conn in production
	mu      sync.Mutex

	// Tree state (#125) — only touched by the connection's read-loop goroutine.
	descendants  map[string]struct{} // relays declared in the validated topology_snapshot
	helloDone    bool                // relay_hello accepted: required before topology_snapshot / event_forward
	snapshotDone bool
	reject       *relayRejection // set by a handler to make the read loop close the link
	evWindow     time.Time       // event_forward rate limit window start
	evCount      int
}

// relayRejection asks the read loop to close the link with a WS close code.
type relayRejection struct {
	code   int
	reason string
}

// maxRelayChainLen bounds relay_chain length (tree depth) in snapshots and events.
const maxRelayChainLen = 32

// maxEventsPerSecond bounds event_forward from a single relay (flood protection).
const maxEventsPerSecond = 200

// RelayMessage is the wire format for messages over /ws/relay.
// All fields are optional; only the ones relevant to a given type are populated.
type RelayMessage struct {
	Type string `json:"type"`

	// relay_hello / relay_ack
	RelayID  string `json:"relay_id,omitempty"`
	Version  string `json:"version,omitempty"`
	IsProxy  bool   `json:"is_proxy,omitempty"`
	NodeType string `json:"node_type,omitempty"` // "relay" | "proxy" — alternative to is_proxy
	// Ancestors: relay_hello = ancestors of the sender (push mode); relay_ack = ancestors of
	// the child as known by the parent ({parent} ∪ ancestors(parent), parent first).
	Ancestors []string `json:"ancestors,omitempty"`

	// topology_snapshot: descendant relays (agents reuse the Agents field)
	Relays []RelayTopoEntry `json:"relays,omitempty"`

	// event_forward
	Event      string         `json:"event,omitempty"`
	RelayChain []string       `json:"relay_chain,omitempty"`
	GroupVars  map[string]any `json:"group_vars,omitempty"`

	// agent_list / agent_list_ack
	Agents []RelayAgentInfo `json:"agents,omitempty"`
	Count  int              `json:"count,omitempty"` // agent_list_ack

	// task_forward (proxy → relay)
	TaskID       string `json:"task_id,omitempty"`
	Hostname     string `json:"hostname,omitempty"`
	Cmd          string `json:"cmd,omitempty"`
	Stdin        string `json:"stdin,omitempty"`
	Timeout      int    `json:"timeout,omitempty"`
	Become       bool   `json:"become,omitempty"`
	BecomeMethod string `json:"become_method,omitempty"`

	// file_upload / file_fetch (proxy → relay)
	Dest string `json:"dest,omitempty"`
	Src  string `json:"src,omitempty"`
	Data string `json:"data,omitempty"` // base64
	Mode string `json:"mode,omitempty"` // file permissions

	// task_result (relay → proxy)
	RC        int    `json:"rc,omitempty"`
	Stdout    string `json:"stdout,omitempty"`
	Stderr    string `json:"stderr,omitempty"`
	Truncated bool   `json:"truncated,omitempty"`

	// generic
	Status    string `json:"status,omitempty"`
	Error     string `json:"error,omitempty"`
	Timestamp string `json:"timestamp,omitempty"`
}

// RelayAgentInfo describes an agent registered on a downstream relay.
type RelayAgentInfo struct {
	Hostname string `json:"hostname"`
	Status   string `json:"status,omitempty"`
	LastSeen string `json:"last_seen,omitempty"`
	// topology_snapshot only
	RelayID    string   `json:"relay_id,omitempty"`
	RelayChain []string `json:"relay_chain,omitempty"`
}

// RelayTopoEntry is a descendant relay declared in a topology_snapshot.
type RelayTopoEntry struct {
	RelayID    string   `json:"relay_id"`
	RelayChain []string `json:"relay_chain"`
}

// RelayTaskResult holds the outcome of a task dispatched to a relay.
type RelayTaskResult struct {
	TaskID    string
	RC        int
	Stdout    string
	Stderr    string
	Truncated bool
	Data      string // base64, for fetch results
	Error     string // set on relay disconnect or exec failure
}

// ── Global state ─────────────────────────────────────────────────────────────

var (
	// relay_id → active WS connection (pull mode)
	relayConnections = make(map[string]*RelayConnection)
	relayConnsMu     sync.RWMutex

	// task_id → channel receiving task result (for task_forward flow)
	relayPendingTasks = make(map[string]chan RelayTaskResult)
	relayTasksMu      sync.RWMutex
)

// ── Injected functions (avoid ws→storage import cycle) ───────────────────────

// RelayRoutingBulkUpsertFunc is called when a relay sends its agent list.
// Injected from main.go: func(relayID string, hostnames []string) error
var RelayRoutingBulkUpsertFunc func(relayID string, hostnames []string) error

// RelayStatusUpdateFunc updates the DB status for a relay.
// Injected from main.go: func(relayID, status string, lastSeen int64) error
var RelayStatusUpdateFunc func(relayID, status string, lastSeen int64) error

// RelayIsProxyUpdateFunc persists the is_proxy flag for a relay node.
// Injected from main.go: func(relayID string, isProxy bool) error
// Called when a relay identifies itself as a proxy in relay_hello (node_type="proxy" or is_proxy=true).
var RelayIsProxyUpdateFunc func(relayID string, isProxy bool) error

// Tree-topology hooks (#125). They are guarded by a mutex because handler goroutines
// read them while tests/main may (re)assign them; use the Set* functions.
var (
	treeHooksMu         sync.RWMutex
	relayLocalIDFn      func() string
	relayAncestorsFn    func() []string
	relayNodeRegisterFn func(relayID string) error
	relayEventUpstream  func(ev RelayMessage)
	relayJTIBlacklistFn func(jti string) (bool, error)
	relayHostRouteFn    func(hostname string) (string, error)
)

// SetRelayLocalIDFunc sets the provider of this node's own relay id (REPEATER_ID; "" if unset).
func SetRelayLocalIDFunc(fn func() string) {
	treeHooksMu.Lock()
	relayLocalIDFn = fn
	treeHooksMu.Unlock()
}

// SetRelayAncestorsFunc sets the provider of this node's ancestors, parent first, root last
// (learned from its own upstream handshake; empty for the root).
func SetRelayAncestorsFunc(fn func() []string) {
	treeHooksMu.Lock()
	relayAncestorsFn = fn
	treeHooksMu.Unlock()
}

// SetRelayNodeRegisterFunc sets the idempotent relay_nodes registration (mode=pull,
// status=connected) that must not overwrite an existing declaration.
func SetRelayNodeRegisterFunc(fn func(relayID string) error) {
	treeHooksMu.Lock()
	relayNodeRegisterFn = fn
	treeHooksMu.Unlock()
}

// SetRelayEventUpstreamFunc sets the forwarder of validated event_forward messages to this
// node's own parent (nil on the root). The upstream client appends this node's id.
func SetRelayEventUpstreamFunc(fn func(ev RelayMessage)) {
	treeHooksMu.Lock()
	relayEventUpstream = fn
	treeHooksMu.Unlock()
}

// SetRelayJTIBlacklistFunc sets the revocation check used at /ws/relay upgrade.
// fn returns true when the JTI is blacklisted; an error is treated as a refusal (fail closed).
func SetRelayJTIBlacklistFunc(fn func(jti string) (bool, error)) {
	treeHooksMu.Lock()
	relayJTIBlacklistFn = fn
	treeHooksMu.Unlock()
}

// SetRelayHostRouteFunc sets the lookup "which relay currently routes this hostname"
// (empty string when unrouted). Used to refuse topology_snapshots that would hijack routes.
func SetRelayHostRouteFunc(fn func(hostname string) (string, error)) {
	treeHooksMu.Lock()
	relayHostRouteFn = fn
	treeHooksMu.Unlock()
}

func lookupHostRoute(hostname string) (string, error) {
	treeHooksMu.RLock()
	fn := relayHostRouteFn
	treeHooksMu.RUnlock()
	if fn == nil {
		return "", nil
	}
	return fn(hostname)
}

// descendantOwner records which direct peer declared each descendant relay, so that
// another peer cannot re-declare (and overwrite the routing of) the same relay.
var (
	descOwnerMu     sync.Mutex
	descendantOwner = make(map[string]string) // descendant relay_id → declaring direct peer
)

// claimDescendants atomically checks that none of the relays is connected directly or
// declared by another peer, then records peer as owner. Returns the offending relay on conflict.
func claimDescendants(peer string, relays map[string]struct{}) (conflict string, ok bool) {
	descOwnerMu.Lock()
	defer descOwnerMu.Unlock()
	for id := range relays {
		if owner, taken := descendantOwner[id]; taken && owner != peer {
			return id, false
		}
		if IsRelayConnected(id) {
			return id, false
		}
	}
	for id := range relays {
		descendantOwner[id] = peer
	}
	return "", true
}

func releaseDescendants(peer string, relays map[string]struct{}) {
	descOwnerMu.Lock()
	defer descOwnerMu.Unlock()
	for id := range relays {
		if descendantOwner[id] == peer {
			delete(descendantOwner, id)
		}
	}
}

// checkHostConflicts refuses hostnames already routed through a different peer or
// connected locally. Hosts routed to this peer itself or to its declared relays are fine.
func checkHostConflicts(conn *RelayConnection, relays map[string]struct{}, byRelay map[string][]string) error {
	for _, hosts := range byRelay {
		for _, h := range hosts {
			if _, err := GetConnection(h); err == nil {
				return fmt.Errorf("hostname %q is connected locally", h)
			}
			route, err := lookupHostRoute(h)
			if err != nil {
				return fmt.Errorf("route lookup failed: %w", err)
			}
			if route == "" || route == conn.RelayID {
				continue
			}
			if _, mine := relays[route]; mine {
				continue
			}
			return fmt.Errorf("hostname %q already routed via relay %q", h, route)
		}
	}
	return nil
}

// checkRelayJTI refuses revoked tokens. Without a configured check the token is accepted
// (tests); main.go always wires it.
func checkRelayJTI(jti string) error {
	treeHooksMu.RLock()
	fn := relayJTIBlacklistFn
	treeHooksMu.RUnlock()
	if fn == nil {
		return nil
	}
	revoked, err := fn(jti)
	if err != nil {
		return fmt.Errorf("blacklist_check_failed: %w", err)
	}
	if revoked {
		return fmt.Errorf("token_revoked")
	}
	return nil
}

func registerRelayNode(relayID string) error {
	treeHooksMu.RLock()
	fn := relayNodeRegisterFn
	treeHooksMu.RUnlock()
	if fn == nil {
		return nil
	}
	return fn(relayID)
}

func forwardEventUpstream(ev RelayMessage) {
	treeHooksMu.RLock()
	fn := relayEventUpstream
	treeHooksMu.RUnlock()
	if fn != nil {
		fn(ev)
	}
}

// ── Limits ───────────────────────────────────────────────────────────────────

func envInt(name string, def int) int {
	if v, err := strconv.Atoi(os.Getenv(name)); err == nil && v > 0 {
		return v
	}
	return def
}

func maxSnapshotRelays() int { return envInt("MAX_SNAPSHOT_RELAYS", 1000) }
func maxSnapshotHosts() int  { return envInt("MAX_SNAPSHOT_HOSTS", 10000) }
func maxRelayMessageSize() int64 {
	return int64(envInt("MAX_WS_MESSAGE_SIZE_RELAY", 10*1024*1024))
}

const defaultLocalRelayID = "secagent-server"

func localRelayID() string {
	treeHooksMu.RLock()
	fn := relayLocalIDFn
	treeHooksMu.RUnlock()
	if fn != nil {
		if id := fn(); id != "" {
			return id
		}
	}
	return defaultLocalRelayID
}

func localAncestors() []string {
	treeHooksMu.RLock()
	fn := relayAncestorsFn
	treeHooksMu.RUnlock()
	if fn != nil {
		return fn()
	}
	return nil
}

// loopedWith reports whether linking childID under this node would create a loop:
// childID ∈ {this node} ∪ ancestors(this node).
func loopedWith(childID string) bool {
	if childID == localRelayID() {
		return true
	}
	for _, a := range localAncestors() {
		if a == childID {
			return true
		}
	}
	return false
}

func reject(conn *RelayConnection, reason string) {
	log.Printf("[RELAY] link refused: relay_id=%s reason=%s", conn.RelayID, reason)
	conn.reject = &relayRejection{code: WSRelayCloseRevoked, reason: reason}
}

// ── Public accessors ─────────────────────────────────────────────────────────

// GetRelayConnection returns the active RelayConnection for relayID.
// Returns an error if the relay is not connected.
func GetRelayConnection(relayID string) (*RelayConnection, error) {
	relayConnsMu.RLock()
	defer relayConnsMu.RUnlock()
	conn, ok := relayConnections[relayID]
	if !ok {
		return nil, fmt.Errorf("relay_offline: %s", relayID)
	}
	return conn, nil
}

// GetConnectedRelayCount returns the number of relays currently connected.
func GetConnectedRelayCount() int {
	relayConnsMu.RLock()
	defer relayConnsMu.RUnlock()
	return len(relayConnections)
}

// GetConnectedRelayIDs returns the IDs of all currently connected relays.
func GetConnectedRelayIDs() []string {
	relayConnsMu.RLock()
	defer relayConnsMu.RUnlock()
	ids := make([]string, 0, len(relayConnections))
	for id := range relayConnections {
		ids = append(ids, id)
	}
	return ids
}

// IsRelayConnected reports whether a relay is currently connected.
func IsRelayConnected(relayID string) bool {
	relayConnsMu.RLock()
	defer relayConnsMu.RUnlock()
	_, ok := relayConnections[relayID]
	return ok
}

// RegisterRelayTaskFuture registers a result channel for a task dispatched to a relay.
func RegisterRelayTaskFuture(taskID string) chan RelayTaskResult {
	ch := make(chan RelayTaskResult, 1)
	relayTasksMu.Lock()
	relayPendingTasks[taskID] = ch
	relayTasksMu.Unlock()
	return ch
}

// UnregisterRelayTaskFuture removes a pending relay task future.
func UnregisterRelayTaskFuture(taskID string) {
	relayTasksMu.Lock()
	delete(relayPendingTasks, taskID)
	relayTasksMu.Unlock()
}

// DispatchToRelay sends a task_forward message to a connected relay and returns
// a channel that will receive the result. The caller must wait on the channel.
func DispatchToRelay(relayID string, msg RelayMessage) (chan RelayTaskResult, error) {
	conn, err := GetRelayConnection(relayID)
	if err != nil {
		return nil, err
	}

	ch := RegisterRelayTaskFuture(msg.TaskID)

	conn.mu.Lock()
	writeErr := conn.Conn.WriteJSON(msg)
	conn.mu.Unlock()

	if writeErr != nil {
		UnregisterRelayTaskFuture(msg.TaskID)
		return nil, fmt.Errorf("DispatchToRelay write: %w", writeErr)
	}
	return ch, nil
}

// ── Internal ─────────────────────────────────────────────────────────────────

// registerRelayConnection registers a relay connection, replacing any stale one.
func registerRelayConnection(conn *RelayConnection) {
	relayConnsMu.Lock()
	if old, exists := relayConnections[conn.RelayID]; exists {
		log.Printf("Replacing stale relay WS: relay_id=%s", conn.RelayID)
		_ = old // old.Conn.Close() called from its own goroutine
	}
	relayConnections[conn.RelayID] = conn
	relayConnsMu.Unlock()

	if RelayStatusUpdateFunc != nil {
		if err := RelayStatusUpdateFunc(conn.RelayID, "connected", time.Now().Unix()); err != nil {
			log.Printf("registerRelayConnection: status update error: relay_id=%s err=%v", conn.RelayID, err)
		}
	}
	log.Printf("Relay connected: relay_id=%s is_proxy=%v", conn.RelayID, conn.IsProxy)
}

// unregisterRelayConnection removes a relay connection and resolves pending tasks.
func unregisterRelayConnection(relayID string) {
	relayConnsMu.Lock()
	delete(relayConnections, relayID)
	relayConnsMu.Unlock()

	// Update DB status
	if RelayStatusUpdateFunc != nil {
		if err := RelayStatusUpdateFunc(relayID, "disconnected", time.Now().Unix()); err != nil {
			log.Printf("unregisterRelayConnection: status update error: relay_id=%s err=%v", relayID, err)
		}
	}

	// Clear routing for this relay (empty hostnames list = delete all entries for relayID)
	if RelayRoutingBulkUpsertFunc != nil {
		if err := RelayRoutingBulkUpsertFunc(relayID, nil); err != nil {
			log.Printf("unregisterRelayConnection: routing clear error: relay_id=%s err=%v", relayID, err)
		}
	}

	// Resolve all pending task futures with disconnect error
	relayTasksMu.Lock()
	var taskIDs []string
	for id := range relayPendingTasks {
		taskIDs = append(taskIDs, id)
	}
	relayTasksMu.Unlock()

	for _, tid := range taskIDs {
		relayTasksMu.Lock()
		ch, ok := relayPendingTasks[tid]
		if ok {
			delete(relayPendingTasks, tid)
		}
		relayTasksMu.Unlock()
		if ok {
			select {
			case ch <- RelayTaskResult{TaskID: tid, Error: "relay_disconnected"}:
			default:
			}
		}
	}

	log.Printf("Relay disconnected: relay_id=%s", relayID)
}

// extractRelayFromRequest validates the JWT and extracts the relay_id.
// Requires role == "relay" in the JWT claims.
func extractRelayFromRequest(r *http.Request) (relayID string, isProxy bool, err error) {
	authHeader := r.Header.Get("Authorization")

	// Fail closed: without a JWT verifier, no relay is ever authenticated.
	if JWTSecretsFunc == nil {
		log.Printf("[SECURITY WARNING] relay connection refused: JWTSecretsFunc is not configured (fail closed)")
		return "", false, fmt.Errorf("jwt_not_configured")
	}
	if !strings.HasPrefix(authHeader, "Bearer ") {
		log.Printf("[SECURITY WARNING] relay connection refused: missing bearer token")
		return "", false, fmt.Errorf("missing_relay_credentials")
	}
	claims, _, valErr := ExtractJWTClaims(authHeader)
	if valErr != nil {
		log.Printf("[SECURITY WARNING] relay connection refused: invalid JWT: %v", valErr)
		return "", false, fmt.Errorf("jwt_invalid: %w", valErr)
	}
	role, _ := claims["role"].(string)
	if role != "relay" {
		log.Printf("[SECURITY WARNING] relay connection refused: wrong JWT role %q", role)
		return "", false, fmt.Errorf("jwt_wrong_role: got %q, want relay", role)
	}
	sub, _ := claims["sub"].(string)
	if sub == "" {
		log.Printf("[SECURITY WARNING] relay connection refused: JWT without sub")
		return "", false, fmt.Errorf("jwt_missing_sub")
	}
	// Revocation: a revoked token must not reconnect (SECURITY.md §7).
	jti, _ := claims["jti"].(string)
	if jti == "" {
		log.Printf("[SECURITY WARNING] relay connection refused: JWT without jti (relay_id=%s)", sub)
		return "", false, fmt.Errorf("jwt_missing_jti")
	}
	if err := checkRelayJTI(jti); err != nil {
		log.Printf("[SECURITY WARNING] relay connection refused: relay_id=%s jti=%s: %v", sub, jti, err)
		return "", false, err
	}
	// is_proxy hint from query param (relay sets this when it is itself a proxy)
	ip := r.URL.Query().Get("is_proxy") == "true"
	return sub, ip, nil
}

// handleRelayMessage dispatches an incoming relay message to the appropriate handler.
func handleRelayMessage(conn *RelayConnection, msg RelayMessage) {
	switch msg.Type {

	case "relay_hello":
		// The announced identity must be the authenticated one.
		if msg.RelayID != conn.RelayID {
			reject(conn, "relay_hello relay_id does not match jwt.sub")
			return
		}
		// Structural loop check (also enforced at upgrade time).
		if loopedWith(conn.RelayID) {
			reject(conn, "loop detected: relay is the parent or one of its ancestors")
			return
		}
		// node_type="proxy" or is_proxy=true both mark this node as a proxy
		isProxyNode := msg.IsProxy || msg.NodeType == "proxy"
		conn.IsProxy = isProxyNode
		// Persist the is_proxy flag to DB so inventory aggregation and routing
		// can distinguish proxy nodes from simple relay nodes
		if isProxyNode && RelayIsProxyUpdateFunc != nil {
			if err := RelayIsProxyUpdateFunc(conn.RelayID, true); err != nil {
				log.Printf("relay_hello: SetRelayIsProxy error: relay_id=%s err=%v", conn.RelayID, err)
			}
		}
		// Auto-registration in relay_nodes (idempotent).
		if err := registerRelayNode(conn.RelayID); err != nil {
			log.Printf("relay_hello: auto-register error: relay_id=%s err=%v", conn.RelayID, err)
		}
		conn.helloDone = true
		// relay_ack carries the PARENT's identity (this node), so the child can pin it.
		ancestors := append([]string{localRelayID()}, localAncestors()...)
		ack := RelayMessage{
			Type:      "relay_ack",
			RelayID:   localRelayID(),
			Ancestors: ancestors,
			Status:    "ok",
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		}
		conn.mu.Lock()
		if err := conn.Conn.WriteJSON(ack); err != nil {
			log.Printf("relay_hello ack write error: relay_id=%s err=%v", conn.RelayID, err)
		}
		conn.mu.Unlock()
		log.Printf("relay_hello ack: relay_id=%s version=%s is_proxy=%v node_type=%q",
			conn.RelayID, msg.Version, conn.IsProxy, msg.NodeType)

	case "topology_snapshot":
		handleTopologySnapshot(conn, msg)

	case "event_forward":
		handleEventForward(conn, msg)

	case "agent_list":
		// Relay announces its connected agents → update relay_routing
		hostnames := make([]string, 0, len(msg.Agents))
		for _, a := range msg.Agents {
			if a.Hostname != "" {
				hostnames = append(hostnames, a.Hostname)
			}
		}
		if RelayRoutingBulkUpsertFunc != nil {
			if err := RelayRoutingBulkUpsertFunc(conn.RelayID, hostnames); err != nil {
				log.Printf("agent_list routing update error: relay_id=%s err=%v", conn.RelayID, err)
			}
		}
		ack := RelayMessage{
			Type:    "agent_list_ack",
			RelayID: conn.RelayID,
			Count:   len(hostnames),
			Status:  "ok",
		}
		conn.mu.Lock()
		if err := conn.Conn.WriteJSON(ack); err != nil {
			log.Printf("agent_list ack write error: relay_id=%s err=%v", conn.RelayID, err)
		}
		conn.mu.Unlock()
		log.Printf("agent_list: relay_id=%s count=%d", conn.RelayID, len(hostnames))

	case "task_result":
		// Relay returns the result of a dispatched task
		relayTasksMu.Lock()
		ch, ok := relayPendingTasks[msg.TaskID]
		if ok {
			delete(relayPendingTasks, msg.TaskID)
		}
		relayTasksMu.Unlock()

		if ok {
			res := RelayTaskResult{
				TaskID:    msg.TaskID,
				RC:        msg.RC,
				Stdout:    msg.Stdout,
				Stderr:    msg.Stderr,
				Truncated: msg.Truncated,
				Data:      msg.Data,
				Error:     msg.Error,
			}
			select {
			case ch <- res:
				log.Printf("task_result resolved: task_id=%s rc=%d relay_id=%s", msg.TaskID, msg.RC, conn.RelayID)
			default:
				log.Printf("task_result channel full: task_id=%s relay_id=%s", msg.TaskID, conn.RelayID)
			}
		} else {
			log.Printf("task_result with no pending future: task_id=%s relay_id=%s", msg.TaskID, conn.RelayID)
		}

	case "heartbeat":
		ack := RelayMessage{
			Type:      "heartbeat_ack",
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		}
		conn.mu.Lock()
		if err := conn.Conn.WriteJSON(ack); err != nil {
			log.Printf("heartbeat_ack write error: relay_id=%s err=%v", conn.RelayID, err)
		}
		conn.mu.Unlock()

	default:
		log.Printf("unknown relay message type: type=%s relay_id=%s", msg.Type, conn.RelayID)
	}
}

// ── RelayHandler ─────────────────────────────────────────────────────────────

// RelayHandler manages WebSocket connections from downstream relays (/ws/relay).
//
// Flow:
//  1. Validate JWT → must have role=relay
//  2. Extract relay_id from "sub" claim
//  3. Upgrade HTTP → WebSocket
//  4. Register relay connection and update DB status
//  5. Message loop (relay_hello, agent_list, task_result, heartbeat)
//  6. On disconnect: cleanup routing, resolve pending task futures
func RelayHandler(w http.ResponseWriter, r *http.Request) {
	relayID, isProxy, err := extractRelayFromRequest(r)
	if err != nil {
		log.Printf("Relay WS auth rejected: %v", err)
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	conn, upgradeErr := upgrader.Upgrade(w, r, nil)
	if upgradeErr != nil {
		log.Printf("Relay WebSocket upgrade failed: relay_id=%s err=%v", relayID, upgradeErr)
		return
	}

	relayConn := &RelayConnection{
		RelayID: relayID,
		IsProxy: isProxy,
		Conn:    conn,
	}

	// Structural loop refusal, independent of what the peer sends afterwards.
	if loopedWith(relayID) {
		reject(relayConn, "loop detected: relay is the parent or one of its ancestors")
		closeWithRejection(conn, relayConn.reject)
		_ = conn.Close()
		return
	}
	conn.SetReadLimit(maxRelayMessageSize())

	registerRelayConnection(relayConn)

	defer func() {
		// Descendants declared by this relay are unreachable once it is gone.
		if RelayRoutingBulkUpsertFunc != nil {
			for id := range relayConn.descendants {
				if err := RelayRoutingBulkUpsertFunc(id, nil); err != nil {
					log.Printf("Relay WS cleanup: routing clear relay=%s err=%v", id, err)
				}
			}
		}
		releaseDescendants(relayID, relayConn.descendants)
		unregisterRelayConnection(relayID)
		_ = conn.Close()
	}()

	// Set read deadline for heartbeat monitoring
	if err := conn.SetReadDeadline(time.Now().Add(120 * time.Second)); err != nil {
		log.Printf("Relay WS SetReadDeadline: relay_id=%s err=%v", relayID, err)
	}
	conn.SetPongHandler(func(string) error {
		return conn.SetReadDeadline(time.Now().Add(120 * time.Second))
	})

	for {
		var msg RelayMessage
		if err := conn.ReadJSON(&msg); err != nil {
			if isNormalClose(err) {
				log.Printf("Relay WS closed: relay_id=%s", relayID)
			} else {
				log.Printf("Relay WS read error: relay_id=%s err=%v", relayID, err)
			}
			break
		}
		// Reset deadline on any message
		if err := conn.SetReadDeadline(time.Now().Add(120 * time.Second)); err != nil {
			log.Printf("Relay WS SetReadDeadline loop: relay_id=%s err=%v", relayID, err)
		}
		handleRelayMessage(relayConn, msg)
		if relayConn.reject != nil {
			closeWithRejection(conn, relayConn.reject)
			break
		}
	}
}

// isNormalClose returns true for expected WS close errors.
func isNormalClose(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "websocket: close") ||
		strings.Contains(s, "EOF") ||
		strings.Contains(s, "use of closed network connection")
}

// resetRelayState clears all relay global state (used in tests).
func resetRelayState() {
	descOwnerMu.Lock()
	for k := range descendantOwner {
		delete(descendantOwner, k)
	}
	descOwnerMu.Unlock()

	relayConnsMu.Lock()
	for k := range relayConnections {
		delete(relayConnections, k)
	}
	relayConnsMu.Unlock()

	relayTasksMu.Lock()
	for k := range relayPendingTasks {
		delete(relayPendingTasks, k)
	}
	relayTasksMu.Unlock()
}

// validateSnapshot checks a topology_snapshot sent by the child conn.RelayID and
// returns the descendant relay ids and the hostname → relay_id map.
func validateSnapshot(conn *RelayConnection, msg RelayMessage) (map[string]struct{}, map[string][]string, error) {
	if len(msg.Relays) > maxSnapshotRelays() {
		return nil, nil, fmt.Errorf("too many relays (%d > %d)", len(msg.Relays), maxSnapshotRelays())
	}
	if len(msg.Agents) > maxSnapshotHosts() {
		return nil, nil, fmt.Errorf("too many hosts (%d > %d)", len(msg.Agents), maxSnapshotHosts())
	}
	self := localRelayID()
	forbidden := map[string]struct{}{self: {}}
	for _, a := range localAncestors() {
		forbidden[a] = struct{}{}
	}

	// chainOK: starts with the child, ends with owner, no repetition, no ancestor/self.
	chainOK := func(chain []string, owner string) error {
		if len(chain) > maxRelayChainLen {
			return fmt.Errorf("relay_chain too long (%d > %d)", len(chain), maxRelayChainLen)
		}
		if len(chain) == 0 || chain[0] != conn.RelayID || chain[len(chain)-1] != owner {
			return fmt.Errorf("invalid relay_chain %v for %q", chain, owner)
		}
		seen := make(map[string]struct{}, len(chain))
		for _, id := range chain {
			if _, bad := forbidden[id]; bad {
				return fmt.Errorf("relay_chain %v contains %q (loop)", chain, id)
			}
			if _, dup := seen[id]; dup {
				return fmt.Errorf("relay_chain %v has a cycle on %q", chain, id)
			}
			seen[id] = struct{}{}
		}
		return nil
	}

	relays := make(map[string]struct{}, len(msg.Relays))
	for _, r := range msg.Relays {
		if r.RelayID == "" || r.RelayID == conn.RelayID {
			return nil, nil, fmt.Errorf("invalid descendant relay_id %q", r.RelayID)
		}
		if _, dup := relays[r.RelayID]; dup {
			return nil, nil, fmt.Errorf("duplicate relay_id %q", r.RelayID)
		}
		if err := chainOK(r.RelayChain, r.RelayID); err != nil {
			return nil, nil, err
		}
		relays[r.RelayID] = struct{}{}
	}

	byRelay := make(map[string][]string)
	seenHosts := make(map[string]struct{}, len(msg.Agents))
	for _, a := range msg.Agents {
		if a.Hostname == "" {
			return nil, nil, fmt.Errorf("agent without hostname")
		}
		if _, dup := seenHosts[a.Hostname]; dup {
			return nil, nil, fmt.Errorf("duplicate hostname %q", a.Hostname)
		}
		seenHosts[a.Hostname] = struct{}{}
		if a.RelayID != conn.RelayID {
			if _, known := relays[a.RelayID]; !known {
				return nil, nil, fmt.Errorf("agent %q references undeclared relay %q", a.Hostname, a.RelayID)
			}
		}
		if err := chainOK(a.RelayChain, a.RelayID); err != nil {
			return nil, nil, err
		}
		byRelay[a.RelayID] = append(byRelay[a.RelayID], a.Hostname)
	}
	return relays, byRelay, nil
}

func handleTopologySnapshot(conn *RelayConnection, msg RelayMessage) {
	if !conn.helloDone {
		log.Printf("[SECURITY WARNING] topology_snapshot before relay_hello: relay_id=%s", conn.RelayID)
		reject(conn, "topology_snapshot before relay_hello")
		return
	}
	if conn.snapshotDone {
		reject(conn, "topology_snapshot already received")
		return
	}
	relays, byRelay, err := validateSnapshot(conn, msg)
	if err != nil {
		reject(conn, "invalid topology_snapshot: "+err.Error())
		return
	}
	// Route-hijack protection (HAUT-3): refuse before any write.
	if id, ok := claimDescendants(conn.RelayID, relays); !ok {
		log.Printf("[SECURITY WARNING] topology_snapshot refused: relay_id=%s declares relay %q already owned elsewhere", conn.RelayID, id)
		reject(conn, "topology_snapshot conflicts with an existing relay")
		return
	}
	if cerr := checkHostConflicts(conn, relays, byRelay); cerr != nil {
		releaseDescendants(conn.RelayID, relays)
		log.Printf("[SECURITY WARNING] topology_snapshot refused: relay_id=%s: %v", conn.RelayID, cerr)
		reject(conn, "topology_snapshot conflicts with existing routing")
		return
	}
	// Declare descendants and publish routing: hostname → declaring relay.
	for id := range relays {
		if rerr := registerRelayNode(id); rerr != nil {
			log.Printf("topology_snapshot: register relay %s: %v", id, rerr)
		}
	}
	if RelayRoutingBulkUpsertFunc != nil {
		for id, hosts := range byRelay {
			if uerr := RelayRoutingBulkUpsertFunc(id, hosts); uerr != nil {
				log.Printf("topology_snapshot: routing update relay=%s: %v", id, uerr)
			}
		}
	}
	conn.descendants = relays
	conn.snapshotDone = true
	ack := RelayMessage{Type: "topology_ack", RelayID: localRelayID(), Status: "ok", Count: len(msg.Agents),
		Timestamp: time.Now().UTC().Format(time.RFC3339)}
	conn.mu.Lock()
	if werr := conn.Conn.WriteJSON(ack); werr != nil {
		log.Printf("topology_ack write error: relay_id=%s err=%v", conn.RelayID, werr)
	}
	conn.mu.Unlock()
	log.Printf("topology_snapshot: relay_id=%s relays=%d agents=%d", conn.RelayID, len(msg.Relays), len(msg.Agents))
}

// handleEventForward validates an ascending event (HAUT-1) and propagates it upstream.
func handleEventForward(conn *RelayConnection, msg RelayMessage) {
	if !conn.helloDone {
		log.Printf("[SECURITY WARNING] event_forward before relay_hello: relay_id=%s (dropped)", conn.RelayID)
		return
	}
	now := time.Now()
	if now.Sub(conn.evWindow) >= time.Second {
		conn.evWindow, conn.evCount = now, 0
	}
	conn.evCount++
	if conn.evCount > maxEventsPerSecond {
		log.Printf("[RELAY] event_forward rate limit exceeded: relay_id=%s (dropped)", conn.RelayID)
		return
	}
	chain := msg.RelayChain
	if len(chain) > maxRelayChainLen {
		log.Printf("[SECURITY WARNING] event_forward rejected: relay_id=%s relay_chain too long (%d)", conn.RelayID, len(chain))
		return
	}
	if len(chain) == 0 || chain[len(chain)-1] != conn.RelayID {
		log.Printf("[RELAY] event_forward rejected: relay_id=%s relay_chain=%v (last element must be the authenticated peer)", conn.RelayID, chain)
		return
	}
	self := localRelayID()
	for i, id := range chain {
		if id == self {
			log.Printf("[RELAY] event_forward rejected: relay_id=%s relay_chain contains local id (loop)", conn.RelayID)
			return
		}
		if i < len(chain)-1 {
			if _, ok := conn.descendants[id]; !ok {
				log.Printf("[RELAY] event_forward rejected: relay_id=%s unknown descendant %q in relay_chain", conn.RelayID, id)
				return
			}
		}
	}
	forwardEventUpstream(msg)
}

// closeWithRejection sends the WS close frame for a rejected link.
func closeWithRejection(conn *websocket.Conn, rej *relayRejection) {
	_ = conn.WriteControl(websocket.CloseMessage,
		websocket.FormatCloseMessage(rej.code, rej.reason), time.Now().Add(time.Second))
}
