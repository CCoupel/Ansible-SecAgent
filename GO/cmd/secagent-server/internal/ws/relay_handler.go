// Phase 12 — relay_handler.go
// WebSocket handler for /ws/relay — mode pull.
//
// Relays connect here with a JWT (role=relay) and announce their agents.
// The proxy then dispatches tasks to the relay via this connection.
//
// Close codes (relay-specific, #148):
//
//	4010 — PERMANENT refusal (revoked / unauthorized identity, loop): the peer must NOT reconnect
//	4011 — relay token expired (refresh the token, then reconnect)
//	4012 — CORRECTABLE refusal (invalid snapshot, protocol error, conflict, busy slot): reconnect with backoff
//	4000 — normal close
package ws

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/gorilla/websocket"

	"secagent-server/cmd/secagent-server/internal/config"
)

// Relay-specific WebSocket close codes.
const (
	WSRelayCloseRevoked = 4010 // permanent refusal: revoked/unauthorized identity, loop — never reconnect
	WSRelayCloseExpired = 4011
	WSRelayCloseRetry   = 4012 // correctable refusal: the peer may reconnect with backoff
	WSRelayCloseNormal  = 4000
)

// ── Types ─────────────────────────────────────────────────────────────────────

// RelayConnection represents an active WebSocket connection from a downstream relay.
type RelayConnection struct {
	RelayID string
	IsProxy bool
	Conn    interface{ WriteJSON(interface{}) error } // *websocket.Conn in production
	wsConn  *websocket.Conn                           // same connection, for CloseRelay (nil in unit tests)
	mu      sync.Mutex

	// Tree state (#125) — only touched by the connection's read-loop goroutine.
	descendants  map[string]struct{} // relays declared in the validated topology_snapshot
	helloDone    bool                // relay_hello accepted: required before topology_snapshot / event_forward
	snapshotDone bool
	snapWindow   time.Time // replacement-snapshot rate limit window start
	snapCount    int
	reject       *relayRejection // set by a handler to make the read loop close the link
	evWindow     time.Time       // event_forward rate limit window start
	evCount      int
	reported     map[string]string // hostname → "old->new" already reported as host.conflict (no event storm)
}

// relayRejection asks the read loop to close the link with a WS close code.
type relayRejection struct {
	code   int
	reason string
}

// maxRelayChainLen bounds relay_chain length (tree depth) in snapshots and events.
const maxRelayChainLen = 32

// Replacement topology_snapshot rate limit, per link: each snapshot rewrites routing in the DB, so
// a child cannot saturate it by repeating snapshots. A well-behaved child coalesces its changes
// (min gap 2 s => <= 30/min). Over the limit the link is closed with the correctable code 4012:
// the child reconnects with backoff and its first snapshot restores a consistent state.
// Variables (not constants) so that tests can tighten them.
var (
	snapshotReplaceLimit  = 40
	snapshotReplaceWindow = time.Minute
)

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
	EnrolledAt string         `json:"enrolled_at,omitempty"` // host.new only
	RelayChain []string       `json:"relay_chain,omitempty"`
	GroupVars  map[string]any `json:"group_vars,omitempty"`
	// host.conflict: previous and new owner of a hostname route
	OldRelay string `json:"old_relay,omitempty"`
	NewRelay string `json:"new_relay,omitempty"`

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
	RelayID    string         `json:"relay_id"`
	RelayChain []string       `json:"relay_chain"`
	GroupVars  map[string]any `json:"group_vars,omitempty"` // that relay's Ansible group vars (#139)
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
	relayTopoChangedFn  func()
	relayChainFn        func(relayID string, chain []string) error
	relayJTIBlacklistFn func(jti string) (bool, error)
	relayRevokedFn      func(relayID string) (bool, error)
	relayHostRouteFn    func(hostname string) (string, error)
	relayRouteUpsertFn  func(hostname, relayID string, chain []string) error
	relayRouteChainsFn  func(entries []RouteChainEntry) error
	relayConflictFn     func(c HostConflict, fromBelow bool)
	relayEventLocalFn   func(event, hostname, status, enrolledAt string, relayChain []string)
	relayGroupVarsFn    func(relayID, groupVarsJSON string) error
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

// SetRelayTopologyChangedFunc sets the callback fired when the set of relays below this node (or
// their hosts) changed: a child link accepted a topology_snapshot (first or replacement) or ended.
// The node then re-sends a full topology_snapshot to its own parent ("snapshot = truth of the
// subtree"). The callback must not block.
func SetRelayTopologyChangedFunc(fn func()) {
	treeHooksMu.Lock()
	relayTopoChangedFn = fn
	treeHooksMu.Unlock()
}

// SetRelayChainFunc sets the persistence of the top-down path to each relay below this node
// (["r2","r3"]: r3 learned through our direct child r2). It feeds the topology_snapshot this node
// sends to ITS parent, which must carry the real chains (not the flattened [self, relay]).
// A nil chain clears the stored path (the relay is then considered a direct child).
func SetRelayChainFunc(fn func(relayID string, chain []string) error) {
	treeHooksMu.Lock()
	relayChainFn = fn
	treeHooksMu.Unlock()
}

func storeRelayChain(relayID string, chain []string) {
	treeHooksMu.RLock()
	fn := relayChainFn
	treeHooksMu.RUnlock()
	if fn == nil {
		return
	}
	if err := fn(relayID, chain); err != nil {
		log.Printf("relay chain: store relay=%q: %v", relayID, err)
	}
}

func notifyTopologyChanged() {
	treeHooksMu.RLock()
	fn := relayTopoChangedFn
	treeHooksMu.RUnlock()
	if fn != nil {
		fn()
	}
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

// RouteChainEntry is a host route learned from a topology_snapshot: the declaring relay and
// the top-down chain from this node's direct child (the peer) down to that relay.
type RouteChainEntry struct {
	Hostname string
	RelayID  string
	Chain    []string
}

// HostConflict describes a host whose route changed to a different owner (SECURITY.md §9):
// last arrival wins, the event lets operators alert on suspicious route moves.
type HostConflict struct {
	Hostname   string
	OldRelay   string // previous owner: relay_id, or LocalOwner when the agent is connected here
	NewRelay   string // relay that now declares the host
	RelayChain []string
}

// LocalOwner is HostConflict.OldRelay when the host is a directly connected agent.
const LocalOwner = "local"

// SetRelayRouteUpsertFunc sets the single-host route upsert (event_forward host.up/host.new).
func SetRelayRouteUpsertFunc(fn func(hostname, relayID string, chain []string) error) {
	treeHooksMu.Lock()
	relayRouteUpsertFn = fn
	treeHooksMu.Unlock()
}

// SetRelayRouteChainsFunc sets the recorder of full top-down chains for snapshot routes.
func SetRelayRouteChainsFunc(fn func(entries []RouteChainEntry) error) {
	treeHooksMu.Lock()
	relayRouteChainsFn = fn
	treeHooksMu.Unlock()
}

// SetRelayGroupVarsFunc sets the persistence of a relay's validated, canonical JSON group vars
// ("" clears them). Group vars reach this node in relay_hello, topology_snapshot and relay.updated.
func SetRelayGroupVarsFunc(fn func(relayID, groupVarsJSON string) error) {
	treeHooksMu.Lock()
	relayGroupVarsFn = fn
	treeHooksMu.Unlock()
}

// storeGroupVars validates and stores the group vars of relayID, then tells the parent (relay.updated,
// origin first: chain ends with the authenticated peer, our own id is appended by the uplink).
// An invalid payload is refused as a whole and reported.
func storeGroupVars(conn *RelayConnection, relayID string, chainToPeer []string, vars map[string]any) error {
	canonical, err := config.EncodeGroupVars(vars)
	if err != nil {
		log.Printf("[SECURITY WARNING] group_vars refused: relay_id=%s declared by %s: %v", conn.RelayID, relayID, err)
		return err
	}
	treeHooksMu.RLock()
	fn := relayGroupVarsFn
	treeHooksMu.RUnlock()
	if fn != nil {
		if serr := fn(relayID, canonical); serr != nil {
			log.Printf("group_vars: store relay=%q: %v", relayID, serr)
		}
	}
	forwardEventUpstream(RelayMessage{Type: "event_forward", Event: "relay.updated", RelayID: relayID,
		GroupVars: vars, RelayChain: chainToPeer})
	return nil
}

// SetRelayEventLocalFunc sets the local dispatch of an event received from a child (hooks run
// here with the received relay_chain, origin first). It is called for validated host.up / host.down /
// host.new only, and never forwards: the handler forwards the event upstream itself.
func SetRelayEventLocalFunc(fn func(event, hostname, status, enrolledAt string, relayChain []string)) {
	treeHooksMu.Lock()
	relayEventLocalFn = fn
	treeHooksMu.Unlock()
}

func dispatchEventLocal(m RelayMessage) {
	treeHooksMu.RLock()
	fn := relayEventLocalFn
	treeHooksMu.RUnlock()
	if fn != nil {
		fn(m.Event, m.Hostname, m.Status, m.EnrolledAt, append([]string(nil), m.RelayChain...))
	}
}

// SetRelayConflictFunc sets the host.conflict sink. fromBelow is true when the conflict was
// reported by a descendant (already counted there): hooks should fire, no upstream re-emission.
func SetRelayConflictFunc(fn func(c HostConflict, fromBelow bool)) {
	treeHooksMu.Lock()
	relayConflictFn = fn
	treeHooksMu.Unlock()
}

// reportConflictOnce emits host.conflict only when the (old, new) owner pair differs from what
// this connection already reported for the host: a relay repeating its agent_list every 30 s
// must not cause an event storm.
func reportConflictOnce(conn *RelayConnection, c HostConflict) {
	key := c.OldRelay + "->" + c.NewRelay
	if conn.reported == nil {
		conn.reported = make(map[string]string)
	}
	if conn.reported[c.Hostname] == key {
		return
	}
	conn.reported[c.Hostname] = key
	emitConflict(c, false)
}

func emitConflict(c HostConflict, fromBelow bool) {
	log.Printf("[WARN] host.conflict: hostname=%q old=%q new=%q chain=%q", c.Hostname, c.OldRelay, c.NewRelay, c.RelayChain)
	treeHooksMu.RLock()
	fn := relayConflictFn
	treeHooksMu.RUnlock()
	if fn != nil {
		fn(c, fromBelow)
	}
}

// detectHostConflict returns a conflict when peer's claim on hostname moves it away from
// another owner: a different relay not under peer, or a directly connected agent.
func detectHostConflict(conn *RelayConnection, hostname string, chain []string) *HostConflict {
	if _, err := GetConnection(hostname); err == nil {
		return &HostConflict{Hostname: hostname, OldRelay: LocalOwner, NewRelay: conn.RelayID, RelayChain: chain}
	}
	prev, err := lookupHostRoute(hostname)
	if err != nil || prev == "" || prev == conn.RelayID {
		return nil
	}
	if _, mine := conn.descendants[prev]; mine {
		return nil
	}
	return &HostConflict{Hostname: hostname, OldRelay: prev, NewRelay: conn.RelayID, RelayChain: chain}
}

func routeChainsHook() func(entries []RouteChainEntry) error {
	treeHooksMu.RLock()
	defer treeHooksMu.RUnlock()
	return relayRouteChainsFn
}

func routeUpsertHook() func(hostname, relayID string, chain []string) error {
	treeHooksMu.RLock()
	defer treeHooksMu.RUnlock()
	return relayRouteUpsertFn
}

// SetRelayRevokedFunc sets the "is this relay revoked?" check applied to CHILD links at upgrade
// (#153): it covers legacy relays whose token JTI is unknown. An error is a refusal (fail closed).
func SetRelayRevokedFunc(fn func(relayID string) (bool, error)) {
	treeHooksMu.Lock()
	relayRevokedFn = fn
	treeHooksMu.Unlock()
}

func checkRelayRevoked(relayID string) error {
	treeHooksMu.RLock()
	fn := relayRevokedFn
	treeHooksMu.RUnlock()
	if fn == nil {
		log.Printf("[SECURITY WARNING] relay connection refused: revocation check is not configured (fail closed)")
		return fmt.Errorf("revocation_check_not_configured")
	}
	revoked, err := fn(relayID)
	if err != nil {
		return fmt.Errorf("revocation_check_failed: %w", err)
	}
	if revoked {
		return fmt.Errorf("relay_revoked")
	}
	return nil
}

// checkRelayJTI refuses revoked tokens. Fail closed: without a configured check
// (main.go always wires it) no relay token is accepted.
func checkRelayJTI(jti string) error {
	treeHooksMu.RLock()
	fn := relayJTIBlacklistFn
	treeHooksMu.RUnlock()
	if fn == nil {
		log.Printf("[SECURITY WARNING] relay connection refused: JTI blacklist check is not configured (fail closed)")
		return fmt.Errorf("blacklist_not_configured")
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

// maxAgentListHosts bounds one agent_list (each host costs a DB lookup for conflict detection).
func maxAgentListHosts() int { return envInt("MAX_AGENT_LIST_HOSTS", 10000) }
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

// reject asks the read loop to close the link with the CORRECTABLE code 4012 (invalid snapshot,
// protocol error, conflict): the peer may fix the cause and reconnect with backoff.
func reject(conn *RelayConnection, reason string) {
	log.Printf("[RELAY] link refused (retryable): relay_id=%s reason=%q", conn.RelayID, reason)
	conn.reject = &relayRejection{code: WSRelayCloseRetry, reason: closeReason(reason)}
}

// closeReason makes a refusal reason fit a WebSocket close frame: the payload is limited to 123
// bytes (code included), longer text (it can quote peer-controlled values) makes the frame
// invalid and the peer would see an abnormal closure (1006) instead of the close code.
func closeReason(reason string) string {
	const maxReason = 100
	reason = strings.ToValidUTF8(reason, "?")
	if len(reason) <= maxReason {
		return reason
	}
	cut := maxReason
	for cut > 0 && !utf8.RuneStart(reason[cut]) {
		cut--
	}
	return reason[:cut] + "..."
}

// rejectPermanent closes the link with 4010: the refusal cannot be fixed by retrying
// (identity not authorized, loop). The client stops instead of reconnecting.
func rejectPermanent(conn *RelayConnection, reason string) {
	log.Printf("[SECURITY WARNING] link refused (permanent): relay_id=%s reason=%q", conn.RelayID, reason)
	conn.reject = &relayRejection{code: WSRelayCloseRevoked, reason: closeReason(reason)}
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

// Relay JWT roles accepted on /ws/relay.
const (
	relayRoleChild  = "relay"
	relayRoleParent = "relay-parent"
)

// relayAuth is the authenticated identity of a /ws/relay upgrade.
type relayAuth struct {
	RelayID string // jwt.sub
	IsProxy bool
	Role    string // relayRoleChild | relayRoleParent
	JTI     string // jwt.jti (revocation key)
}

// extractRelayAuth validates the JWT of a /ws/relay upgrade and returns the relay id (sub),
// the is_proxy hint and the role. Accepted roles: "relay" (a child opening a link to us) and
// "relay-parent" (our parent opening a link to us, push mode #140; token signed by this node).
// The full role model (relay-child / relay-parent split, #146) is not implemented yet.
// Fail closed: no verifier, missing/invalid/revoked token, unknown role => refused.
func extractRelayAuth(r *http.Request) (relayAuth, error) {
	authHeader := r.Header.Get("Authorization")

	// Fail closed: without a JWT verifier, no relay is ever authenticated.
	if JWTSecretsFunc == nil {
		log.Printf("[SECURITY WARNING] relay connection refused: JWTSecretsFunc is not configured (fail closed)")
		return relayAuth{}, fmt.Errorf("jwt_not_configured")
	}
	if !strings.HasPrefix(authHeader, "Bearer ") {
		log.Printf("[SECURITY WARNING] relay connection refused: missing bearer token")
		return relayAuth{}, fmt.Errorf("missing_relay_credentials")
	}
	claims, _, valErr := ExtractJWTClaims(authHeader)
	if valErr != nil {
		log.Printf("[SECURITY WARNING] relay connection refused: invalid JWT: %v", valErr)
		return relayAuth{}, fmt.Errorf("jwt_invalid: %w", valErr)
	}
	role, _ := claims["role"].(string)
	if role != relayRoleChild && role != relayRoleParent {
		log.Printf("[SECURITY WARNING] relay connection refused: wrong JWT role %q", role)
		return relayAuth{}, fmt.Errorf("jwt_wrong_role: got %q, want %s or %s", role, relayRoleChild, relayRoleParent)
	}
	sub, _ := claims["sub"].(string)
	if sub == "" {
		log.Printf("[SECURITY WARNING] relay connection refused: JWT without sub")
		return relayAuth{}, fmt.Errorf("jwt_missing_sub")
	}
	// The subject becomes the relay identity (logs, environment, hook files, Ansible groups): a
	// token whose sub is not a well-formed relay_id is refused, whoever signed it. Never echoed.
	if !relayIDShape.MatchString(sub) {
		log.Printf("[SECURITY WARNING] relay connection refused: JWT sub is not a valid relay_id (length %d)", len(sub))
		return relayAuth{}, fmt.Errorf("jwt_invalid_sub")
	}
	// Revocation: a revoked token must not reconnect (SECURITY.md §7).
	jti, _ := claims["jti"].(string)
	if jti == "" {
		log.Printf("[SECURITY WARNING] relay connection refused: JWT without jti (relay_id=%s)", sub)
		return relayAuth{}, fmt.Errorf("jwt_missing_jti")
	}
	if err := checkRelayJTI(jti); err != nil {
		log.Printf("[SECURITY WARNING] relay connection refused: relay_id=%s jti=%s: %v", sub, jti, err)
		return relayAuth{}, err
	}
	// A revoked relay (flagged in relay_nodes) is refused even if its JTI is unknown (legacy token).
	if role == relayRoleChild {
		if err := checkRelayRevoked(sub); err != nil {
			log.Printf("[SECURITY WARNING] relay connection refused: relay_id=%s: %v", sub, err)
			return relayAuth{}, err
		}
	}
	// is_proxy hint from query param (relay sets this when it is itself a proxy)
	ip := r.URL.Query().Get("is_proxy") == "true"
	return relayAuth{RelayID: sub, IsProxy: ip, Role: role, JTI: jti}, nil
}

// handleRelayMessage dispatches an incoming relay message to the appropriate handler.
func handleRelayMessage(conn *RelayConnection, msg RelayMessage) {
	switch msg.Type {

	case "relay_hello":
		// The announced identity must be the authenticated one.
		if msg.RelayID != conn.RelayID {
			rejectPermanent(conn, "relay_hello relay_id does not match jwt.sub")
			return
		}
		// Structural loop check (also enforced at upgrade time).
		if loopedWith(conn.RelayID) {
			rejectPermanent(conn, "loop detected: relay is the parent or one of its ancestors")
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
		if msg.GroupVars != nil {
			if err := storeGroupVars(conn, conn.RelayID, []string{conn.RelayID}, msg.GroupVars); err != nil {
				reject(conn, "invalid group_vars")
				return
			}
		}
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
		if n := len(msg.Agents); n > maxAgentListHosts() {
			log.Printf("[SECURITY WARNING] agent_list refused: relay_id=%s hosts=%d limit=%d", conn.RelayID, n, maxAgentListHosts())
			reject(conn, "agent_list too large")
			return
		}
		// Last arrival wins between relays, but a move away from another owner is reported
		// (host.conflict, once per owner change) and a live local agent is never re-routed.
		routable := hostnames[:0:0]
		seen := make(map[string]bool, len(hostnames))
		for _, h := range hostnames {
			c := detectHostConflict(conn, h, []string{conn.RelayID})
			seen[h] = true // still claimed: the reported-conflict memory is kept (an uncontested round must not re-arm it)
			if c == nil {
				routable = append(routable, h)
				continue
			}
			reportConflictOnce(conn, *c)
			if c.OldRelay != LocalOwner {
				routable = append(routable, h) // relay-to-relay move: last arrival wins
			}
		}
		for h := range conn.reported {
			if !seen[h] { // the claim ended: a later conflict is a new event
				delete(conn.reported, h)
			}
		}
		hostnames = routable
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
				log.Printf("task_result resolved: task_id=%q rc=%d relay_id=%s", msg.TaskID, msg.RC, conn.RelayID)
			default:
				log.Printf("task_result channel full: task_id=%q relay_id=%s", msg.TaskID, conn.RelayID)
			}
		} else {
			log.Printf("task_result with no pending future: task_id=%q relay_id=%s", msg.TaskID, conn.RelayID)
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
		log.Printf("unknown relay message type: type=%q relay_id=%s", msg.Type, conn.RelayID)
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
	auth, err := extractRelayAuth(r)
	if err != nil {
		log.Printf("Relay WS auth rejected: %v", err)
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	relayID, isProxy := auth.RelayID, auth.IsProxy
	conn, upgradeErr := upgrader.Upgrade(w, r, nil)
	if upgradeErr != nil {
		log.Printf("Relay WebSocket upgrade failed: relay_id=%s err=%v", relayID, upgradeErr)
		return
	}

	// Our PARENT opened this link (push mode, #140): we are the child side of the handshake.
	if auth.Role == relayRoleParent {
		serveParentLink(r.Context(), conn, relayID, auth.JTI)
		return
	}

	relayConn := &RelayConnection{
		RelayID: relayID,
		IsProxy: isProxy,
		Conn:    conn,
	}

	// Structural loop refusal, independent of what the peer sends afterwards.
	if loopedWith(relayID) {
		rejectPermanent(relayConn, "loop detected: relay is the parent or one of its ancestors")
		closeWithRejection(conn, relayConn.reject)
		_ = conn.Close()
		return
	}
	_ = serveRelayConn(conn, relayConn) // the error only matters to a dialer (ServeDialedRelay)
}

// serveRelayConn registers a child relay connection and runs its message loop until the
// link ends. Shared by the accepted (pull) and the dialed (push) paths.
//
// It returns the error that ended the read loop (a *websocket.CloseError when the peer closed
// the link with a code, e.g. 4010) or nil when WE closed it (rejection). ServeDialedRelay relays it
// so that the dialer can tell a permanent refusal (4010) from a lost link.
func serveRelayConn(conn *websocket.Conn, relayConn *RelayConnection) error {
	relayID := relayConn.RelayID
	relayConn.wsConn = conn
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
		for id := range relayConn.descendants {
			storeRelayChain(id, nil) // unreachable now: no path to publish
		}
		releaseDescendants(relayID, relayConn.descendants)
		unregisterRelayConnection(relayID)
		_ = conn.Close()
		notifyTopologyChanged() // the subtree below this node changed: tell our own parent
	}()

	// Set read deadline for heartbeat monitoring
	if err := conn.SetReadDeadline(time.Now().Add(120 * time.Second)); err != nil {
		log.Printf("Relay WS SetReadDeadline: relay_id=%s err=%v", relayID, err)
	}
	conn.SetPongHandler(func(string) error {
		return conn.SetReadDeadline(time.Now().Add(120 * time.Second))
	})

	var loopErr error
	for {
		var msg RelayMessage
		if err := conn.ReadJSON(&msg); err != nil {
			if isNormalClose(err) {
				log.Printf("Relay WS closed: relay_id=%s", relayID)
			} else {
				log.Printf("Relay WS read error: relay_id=%s err=%v", relayID, err)
			}
			loopErr = err
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
	return loopErr
}

// ── Push mode (#140) ─────────────────────────────────────────────────────────

// RelayIdentity returns this node's own relay id and its ancestors (parent first).
func RelayIdentity() (id string, ancestors []string) {
	return localRelayID(), localAncestors()
}

// CloseRelay force-closes the active link of relayID (child link, pull or dialed) with the given
// WebSocket close code (4010 = permanent: the peer stops, #148). The read loop then ends and
// cleans routing/state as for any disconnect. Returns false when the relay is not connected.
// Symmetric of CloseAgent.
func CloseRelay(relayID string, code int, reason string) bool {
	relayConnsMu.RLock()
	rc := relayConnections[relayID]
	relayConnsMu.RUnlock()
	if rc == nil || rc.wsConn == nil {
		return false
	}
	log.Printf("Relay force-closed: relay_id=%s code=%d reason=%s", relayID, code, reason)
	closeWithRejection(rc.wsConn, &relayRejection{code: code, reason: reason})
	_ = rc.wsConn.Close()
	return true
}

// ConfiguredRelayID returns this node's own relay id (REPEATER_ID) and whether one is configured.
// A standalone root has none (RelayIdentity then reports a placeholder).
func ConfiguredRelayID() (string, bool) {
	treeHooksMu.RLock()
	fn := relayLocalIDFn
	treeHooksMu.RUnlock()
	if fn == nil {
		return "", false
	}
	id := fn()
	return id, id != ""
}

// RelayWouldLoop reports whether linking childID under this node would create a loop
// (childID ∈ {this node} ∪ ancestors(this node)).
func RelayWouldLoop(childID string) bool { return loopedWith(childID) }

// ErrRelayAlreadyConnected is returned by ServeDialedRelay when the peer is already linked.
var ErrRelayAlreadyConnected = errors.New("relay already connected")

// ServeDialedRelay serves a child relay that WE dialed (push mode): relay_hello was sent and
// relay_ack (with the expected identity) received by the caller. The child now sends its
// topology_snapshot, then agent_list / event_forward / task_result, exactly as in pull mode.
// It blocks until the link ends and always closes conn. When the peer ended the link with a close
// frame, the returned error is its *websocket.CloseError (code 4010 = permanent refusal, #148).
func ServeDialedRelay(ctx context.Context, conn *websocket.Conn, peerID string) error {
	if IsRelayConnected(peerID) {
		_ = conn.Close()
		return ErrRelayAlreadyConnected
	}
	relayConn := &RelayConnection{RelayID: peerID, Conn: conn, helloDone: true}
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-done:
		}
	}()
	err := serveRelayConn(conn, relayConn)
	if ctx.Err() != nil {
		return ctx.Err() // we were stopped: not a peer decision
	}
	return err
}

var (
	// parentLinkFn serves an accepted parent link (bound by main to repeater.Uplink.ServeAccepted).
	parentLinkFn func(ctx context.Context, conn *websocket.Conn, ancestors []string, ack func() error) error
)

// SetRelayParentLinkFunc sets the handler of a link opened by our parent. It must send ack()
// only once the single-parent slot is secured, then serve the uplink until the link ends.
// Without it (e.g. this node has its own REPEATER_UPSTREAM_* parent) such links are refused.
func SetRelayParentLinkFunc(fn func(ctx context.Context, conn *websocket.Conn, ancestors []string, ack func() error) error) {
	treeHooksMu.Lock()
	parentLinkFn = fn
	treeHooksMu.Unlock()
}

// ── Live parent links, by JWT id (#150) ──────────────────────────────────────

var (
	parentLinksMu sync.Mutex
	parentLinks   = make(map[string]*websocket.Conn)
)

func registerParentLink(jti string, conn *websocket.Conn) {
	parentLinksMu.Lock()
	parentLinks[jti] = conn
	parentLinksMu.Unlock()
}

func unregisterParentLink(jti string, conn *websocket.Conn) {
	parentLinksMu.Lock()
	if parentLinks[jti] == conn {
		delete(parentLinks, jti)
	}
	parentLinksMu.Unlock()
}

// RevokeRelayParentLink closes the active parent link authenticated with the token jti, if any,
// with the permanent code 4010 (the token is blacklisted: the parent cannot come back with it).
// Returns true when a live link was closed.
func RevokeRelayParentLink(jti string) bool {
	parentLinksMu.Lock()
	conn := parentLinks[jti]
	delete(parentLinks, jti)
	parentLinksMu.Unlock()
	if conn == nil {
		return false
	}
	log.Printf("[SECURITY WARNING] parent link closed: token revoked")
	closeWithRejection(conn, &relayRejection{code: WSRelayCloseRevoked, reason: "token revoked"})
	_ = conn.Close()
	return true
}

// serveParentLink handles a connection authenticated with a relay-parent token: the peer is
// OUR PARENT. Handshake: relay_hello (relay_id == jwt.sub, loop check against its ancestors)
// → relay_ack with our identity → uplink (topology_snapshot sent by us, then steady state).
func serveParentLink(ctx context.Context, conn *websocket.Conn, parentID, jti string) {
	defer func() { _ = conn.Close() }()
	// Track the live link by token id so that revoking the token can cut it immediately (#150).
	registerParentLink(jti, conn)
	defer unregisterParentLink(jti, conn)
	// refuse closes with 4012 (the parent may fix the cause and retry); refusePermanent with 4010.
	refuse := func(reason string) {
		log.Printf("[SECURITY WARNING] parent link refused (retryable): parent=%s reason=%s", parentID, reason)
		closeWithRejection(conn, &relayRejection{code: WSRelayCloseRetry, reason: reason})
	}
	refusePermanent := func(reason string) {
		log.Printf("[SECURITY WARNING] parent link refused (permanent): parent=%s reason=%s", parentID, reason)
		closeWithRejection(conn, &relayRejection{code: WSRelayCloseRevoked, reason: reason})
	}

	treeHooksMu.RLock()
	link := parentLinkFn
	treeHooksMu.RUnlock()
	if link == nil {
		refusePermanent("this node does not accept a parent link")
		return
	}

	conn.SetReadLimit(maxRelayMessageSize())
	if err := conn.SetReadDeadline(time.Now().Add(15 * time.Second)); err != nil {
		return
	}
	var hello RelayMessage
	if err := conn.ReadJSON(&hello); err != nil || hello.Type != "relay_hello" {
		refuse("expected relay_hello")
		return
	}
	if hello.RelayID != parentID {
		refusePermanent("relay_hello relay_id does not match jwt.sub")
		return
	}
	if len(hello.Ancestors) > maxRelayChainLen {
		refuse("relay_hello ancestors too long")
		return
	}
	// Loop: we must not be the parent nor one of its ancestors.
	self := localRelayID()
	loop := self == parentID
	for _, a := range hello.Ancestors {
		if a == self {
			loop = true
		}
	}
	if loop {
		refusePermanent("loop detected: this node is the parent or one of its ancestors")
		return
	}

	ancestors := append([]string{parentID}, hello.Ancestors...)
	acked := false
	ack := func() error {
		acked = true
		return conn.WriteJSON(RelayMessage{Type: "relay_ack", RelayID: self, Status: "ok",
			Timestamp: time.Now().UTC().Format(time.RFC3339)})
	}
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		return
	}
	err := link(ctx, conn, ancestors, ack)
	if !acked {
		// The single-parent slot was not available (or the hook failed): refused, no handshake done.
		log.Printf("[SECURITY WARNING] parent link refused: parent=%s err=%v", parentID, err)
		// busy single-parent slot: another link may end soon, so the parent may retry
		closeWithRejection(conn, &relayRejection{code: WSRelayCloseRetry, reason: "parent link refused"})
		return
	}
	log.Printf("parent link closed: parent=%s err=%v", parentID, err)
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
		for _, id := range chain {
			if !relayIDShape.MatchString(id) {
				return fmt.Errorf("invalid relay id %q in relay_chain", id)
			}
		}
		if len(chain) == 0 || chain[0] != conn.RelayID || chain[len(chain)-1] != owner {
			return fmt.Errorf("invalid relay_chain %q for %q", chain, owner)
		}
		seen := make(map[string]struct{}, len(chain))
		for _, id := range chain {
			if _, bad := forbidden[id]; bad {
				return fmt.Errorf("relay_chain %q contains %q (loop)", chain, id)
			}
			if _, dup := seen[id]; dup {
				return fmt.Errorf("relay_chain %q has a cycle on %q", chain, id)
			}
			seen[id] = struct{}{}
		}
		return nil
	}

	relays := make(map[string]struct{}, len(msg.Relays))
	for _, r := range msg.Relays {
		if !relayIDShape.MatchString(r.RelayID) || r.RelayID == conn.RelayID {
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
		if !hostnameShape.MatchString(a.Hostname) {
			return nil, nil, fmt.Errorf("invalid hostname %q", a.Hostname)
		}
		if !relayIDShape.MatchString(a.RelayID) {
			return nil, nil, fmt.Errorf("agent %q has invalid relay_id %q", a.Hostname, a.RelayID)
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
	replacing := conn.snapshotDone
	if replacing {
		// A later snapshot REPLACES the subtree atomically (late-joining relays, lost links), but
		// is rate limited per link: every replacement rewrites routing.
		now := time.Now()
		if now.Sub(conn.snapWindow) >= snapshotReplaceWindow {
			conn.snapWindow, conn.snapCount = now, 0
		}
		conn.snapCount++
		if conn.snapCount > snapshotReplaceLimit {
			log.Printf("[SECURITY WARNING] topology_snapshot rate limit exceeded: relay_id=%s (> %d per %s)", conn.RelayID, snapshotReplaceLimit, snapshotReplaceWindow)
			reject(conn, "topology_snapshot rate limit exceeded")
			return
		}
	}
	relays, byRelay, err := validateSnapshot(conn, msg)
	if err != nil {
		reject(conn, "invalid topology_snapshot: "+err.Error())
		return
	}
	// Group vars (#139) are validated as a whole before anything is written.
	if err := validateSnapshotGroupVars(msg); err != nil {
		log.Printf("[SECURITY WARNING] topology_snapshot refused: relay_id=%s: %v", conn.RelayID, err)
		reject(conn, "invalid group_vars in topology_snapshot")
		return
	}
	// Route-hijack protection (HAUT-3): refuse before any write.
	if id, ok := claimDescendants(conn.RelayID, relays); !ok {
		log.Printf("[SECURITY WARNING] topology_snapshot refused: relay_id=%s declares relay %q already owned elsewhere", conn.RelayID, id)
		reject(conn, "topology_snapshot conflicts with an existing relay")
		return
	}
	// Only the relays claimed by THIS snapshot are given back on refusal: the ones already owned
	// by the previous snapshot stay owned (the link close then cleans them as usual).
	fresh := make(map[string]struct{})
	for id := range relays {
		if _, had := conn.descendants[id]; !had {
			fresh[id] = struct{}{}
		}
	}
	if cerr := checkHostConflicts(conn, relays, byRelay); cerr != nil {
		releaseDescendants(conn.RelayID, fresh)
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
	// Remember the real path to every relay below the peer (chains are validated: they start at
	// the peer and end at the relay), so our own snapshot upstream does not flatten the tree.
	storeRelayChain(conn.RelayID, []string{conn.RelayID})
	for _, r := range msg.Relays {
		storeRelayChain(r.RelayID, r.RelayChain)
	}
	if replacing {
		for id := range conn.descendants {
			if _, still := relays[id]; !still {
				storeRelayChain(id, nil)
			}
		}
	}
	if RelayRoutingBulkUpsertFunc != nil {
		// BulkUpsert REPLACES a relay's routes: every relay of the snapshot (and the peer itself) is
		// rewritten, with an empty list when it no longer has hosts; relays that left the subtree
		// are cleared.
		write := func(id string) {
			if uerr := RelayRoutingBulkUpsertFunc(id, byRelay[id]); uerr != nil {
				log.Printf("topology_snapshot: routing update relay=%s: %v", id, uerr)
			}
		}
		write(conn.RelayID)
		for id := range relays {
			write(id)
		}
		for id := range conn.descendants {
			if _, still := relays[id]; !still {
				if uerr := RelayRoutingBulkUpsertFunc(id, nil); uerr != nil {
					log.Printf("topology_snapshot: routing clear relay=%s: %v", id, uerr)
				}
			}
		}
	}
	if replacing {
		gone := make(map[string]struct{})
		for id := range conn.descendants {
			if _, still := relays[id]; !still {
				gone[id] = struct{}{}
			}
		}
		releaseDescendants(conn.RelayID, gone)
	}
	if fn := routeChainsHook(); fn != nil {
		var entries []RouteChainEntry
		for _, a := range msg.Agents {
			entries = append(entries, RouteChainEntry{Hostname: a.Hostname, RelayID: a.RelayID, Chain: a.RelayChain})
		}
		if cerr := fn(entries); cerr != nil {
			log.Printf("topology_snapshot: route chains: relay=%s err=%v", conn.RelayID, cerr)
		}
	}
	conn.descendants = relays
	conn.snapshotDone = true
	applySnapshotGroupVars(conn, msg)
	ack := RelayMessage{Type: "topology_ack", RelayID: localRelayID(), Status: "ok", Count: len(msg.Agents),
		Timestamp: time.Now().UTC().Format(time.RFC3339)}
	conn.mu.Lock()
	if werr := conn.Conn.WriteJSON(ack); werr != nil {
		log.Printf("topology_ack write error: relay_id=%s err=%v", conn.RelayID, werr)
	}
	conn.mu.Unlock()
	log.Printf("topology_snapshot: relay_id=%s relays=%d agents=%d replaced=%t", conn.RelayID, len(msg.Relays), len(msg.Agents), replacing)
	notifyTopologyChanged()
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
		log.Printf("[RELAY] event_forward rejected: relay_id=%s relay_chain=%q (last element must be the authenticated peer)", conn.RelayID, chain)
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
	if reason := eventShapeError(msg); reason != "" {
		log.Printf("[SECURITY WARNING] event_forward rejected: relay_id=%s event=%q: %s", conn.RelayID, msg.Event, reason)
		return
	}
	if !applyEventRouting(conn, msg) {
		return // not accepted (host not owned by this peer's subtree): neither dispatched nor forwarded
	}
	// Hooks of THIS node see the event with the received relay_chain (origin first); the event is
	// then forwarded to our own parent (the uplink appends our id). A received event is never
	// handed back to the sender.
	switch msg.Event {
	case "host.up", "host.down", "host.new":
		dispatchEventLocal(msg)
	}
	forwardEventUpstream(msg)
}

// validateSnapshotGroupVars checks the group vars of the sender and of every declared descendant.
func validateSnapshotGroupVars(msg RelayMessage) error {
	if msg.GroupVars != nil {
		if err := config.ValidateGroupVars(msg.GroupVars); err != nil {
			return err
		}
	}
	for _, r := range msg.Relays {
		if r.GroupVars != nil {
			if err := config.ValidateGroupVars(r.GroupVars); err != nil {
				return fmt.Errorf("relay %q: %w", r.RelayID, err)
			}
		}
	}
	return nil
}

// applySnapshotGroupVars stores the (already validated) group vars carried by a snapshot.
func applySnapshotGroupVars(conn *RelayConnection, msg RelayMessage) {
	if msg.GroupVars != nil {
		_ = storeGroupVars(conn, conn.RelayID, []string{conn.RelayID}, msg.GroupVars)
	}
	for _, r := range msg.Relays {
		if r.GroupVars == nil {
			continue
		}
		// origin first, authenticated peer last: reverse of the top-down chain
		chain := make([]string, len(r.RelayChain))
		for i, id := range r.RelayChain {
			chain[len(r.RelayChain)-1-i] = id
		}
		_ = storeGroupVars(conn, r.RelayID, chain, r.GroupVars)
	}
}

// hostnameShape / enrolledAtShape bound what a child may put in an event: the values end up in
// hook templates, environment variables and webhook bodies.
var hostnameShape = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9._-]{0,251}[A-Za-z0-9])?$`)

// eventShapeError returns why an event_forward must be refused, "" when well formed.
func eventShapeError(m RelayMessage) string {
	switch m.Event {
	case "host.up", "host.down", "host.new", "host.conflict":
	case "relay.updated":
		// a relay announces its Ansible group vars (#139): relay id + origin-first chain + vars
		if !relayIDShape.MatchString(m.RelayID) {
			return "invalid relay id"
		}
		if len(m.RelayChain) == 0 || m.RelayChain[0] != m.RelayID {
			return "relay.updated chain must start with the relay it describes"
		}
		if m.GroupVars != nil {
			if err := config.ValidateGroupVars(m.GroupVars); err != nil {
				return "invalid group_vars"
			}
		}
		return ""
	default:
		return "unsupported event kind"
	}
	if !hostnameShape.MatchString(m.Hostname) {
		return "invalid hostname"
	}
	switch m.Event {
	case "host.up", "host.down", "host.new":
		if m.Status != "connected" && m.Status != "disconnected" {
			return "invalid status"
		}
		if m.EnrolledAt != "" {
			if m.Event != "host.new" {
				return "enrolled_at only belongs to host.new"
			}
			if _, err := time.Parse(time.RFC3339, m.EnrolledAt); err != nil {
				return "invalid enrolled_at"
			}
		}
	case "host.conflict":
		for _, id := range []string{m.OldRelay, m.NewRelay} {
			if id != LocalOwner && !relayIDShape.MatchString(id) {
				return "invalid relay id in host.conflict"
			}
		}
	}
	return ""
}

var relayIDShape = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,62}$`)

// applyEventRouting keeps relay_routing in sync with descendants' events: host.up / host.new
// (re)route the host to the relay where it lives (chain[0]) via the peer; a host.conflict
// reported below is relayed to the hooks. host.down keeps the route (dispatch reports offline).
func applyEventRouting(conn *RelayConnection, msg RelayMessage) bool {
	chain := msg.RelayChain // origin first, authenticated peer last
	switch msg.Event {
	case "host.up", "host.new":
		origin := chain[0]
		topDown := make([]string, len(chain))
		for i, id := range chain {
			topDown[len(chain)-1-i] = id
		}
		// The event comes from below: a conflict here is detected against OTHER owners only.
		if c := detectHostConflict(conn, msg.Hostname, topDown); c != nil {
			reportConflictOnce(conn, *c)
			if c.OldRelay == LocalOwner {
				return false // a live local agent is never re-routed, nor announced as up from below
			}
		}
		// NB: an uncontested event does NOT reset the "already reported" memory: with two relays
		// claiming the same host, every host.up of the current owner would otherwise re-arm the
		// conflict and bring back the event storm. Only agent_list (the authoritative, periodic
		// declaration) ends a reported conflict.
		if origin != conn.RelayID {
			if err := registerRelayNode(origin); err != nil {
				log.Printf("event_forward: register relay %s: %v", origin, err)
			}
		}
		if fn := routeUpsertHook(); fn != nil {
			if err := fn(msg.Hostname, origin, topDown); err != nil {
				log.Printf("event_forward: route update host=%q: %v", msg.Hostname, err)
			}
		}
		return true
	case "host.down":
		// A child may only report the going down of a host of its own subtree: never of a host
		// connected here nor routed through another peer (no alert spam / no spoofing).
		if _, err := GetConnection(msg.Hostname); err == nil {
			log.Printf("[SECURITY WARNING] event_forward host.down refused: relay_id=%s hostname=%q is connected locally", conn.RelayID, msg.Hostname)
			return false
		}
		if prev, err := lookupHostRoute(msg.Hostname); err == nil && prev != "" && prev != conn.RelayID {
			if _, mine := conn.descendants[prev]; !mine {
				log.Printf("[SECURITY WARNING] event_forward host.down refused: relay_id=%s hostname=%q is routed through another relay", conn.RelayID, msg.Hostname)
				return false
			}
		}
		return true
	case "host.conflict":
		emitConflict(HostConflict{Hostname: msg.Hostname, OldRelay: msg.OldRelay, NewRelay: msg.NewRelay, RelayChain: chain}, true)
		return true
	case "relay.updated":
		// Only the sender or a relay it declared may have its group vars set through it.
		if msg.RelayID != conn.RelayID {
			if _, mine := conn.descendants[msg.RelayID]; !mine {
				log.Printf("[SECURITY WARNING] relay.updated refused: relay_id=%s describes %q which is not in its subtree", conn.RelayID, msg.RelayID)
				return false
			}
		}
		treeHooksMu.RLock()
		fn := relayGroupVarsFn
		treeHooksMu.RUnlock()
		canonical, err := config.EncodeGroupVars(msg.GroupVars)
		if err != nil {
			return false
		}
		if fn != nil {
			if serr := fn(msg.RelayID, canonical); serr != nil {
				log.Printf("relay.updated: store group vars relay=%q: %v", msg.RelayID, serr)
			}
		}
		return true
	}
	return false
}

// closeWithRejection sends the WS close frame for a rejected link.
func closeWithRejection(conn *websocket.Conn, rej *relayRejection) {
	_ = conn.WriteControl(websocket.CloseMessage,
		websocket.FormatCloseMessage(rej.code, rej.reason), time.Now().Add(time.Second))
}
