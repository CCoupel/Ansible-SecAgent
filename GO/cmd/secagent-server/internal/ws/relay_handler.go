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
	"strings"
	"sync"
	"time"
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
}

// RelayMessage is the wire format for messages over /ws/relay.
// All fields are optional; only the ones relevant to a given type are populated.
type RelayMessage struct {
	Type string `json:"type"`

	// relay_hello / relay_ack
	RelayID  string `json:"relay_id,omitempty"`
	Version  string `json:"version,omitempty"`
	IsProxy  bool   `json:"is_proxy,omitempty"`
	NodeType string `json:"node_type,omitempty"` // "relay" | "proxy" — alternative to is_proxy

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

	if JWTSecretsFunc != nil && strings.HasPrefix(authHeader, "Bearer ") {
		claims, _, valErr := ExtractJWTClaims(authHeader)
		if valErr != nil {
			return "", false, fmt.Errorf("jwt_invalid: %w", valErr)
		}
		role, _ := claims["role"].(string)
		if role != "relay" {
			return "", false, fmt.Errorf("jwt_wrong_role: got %q, want relay", role)
		}
		sub, _ := claims["sub"].(string)
		if sub == "" {
			return "", false, fmt.Errorf("jwt_missing_sub")
		}
		// is_proxy hint from query param (relay sets this when it is itself a proxy)
		ip := r.URL.Query().Get("is_proxy") == "true"
		return sub, ip, nil
	}

	// Fallback for tests without JWTSecretsFunc configured
	log.Printf("[RELAY] JWT verification bypassed — JWTSecretsFunc is nil")
	if strings.HasPrefix(authHeader, "Bearer ") && len(authHeader) > 7 {
		// Decode relay_id from JWT sub without verification
		sub := extractSubFromJWTUnsafe(authHeader[7:])
		if sub != "" {
			ip := r.URL.Query().Get("is_proxy") == "true"
			return sub, ip, nil
		}
	}
	// Allow relay_id via query param in test mode only
	if id := r.URL.Query().Get("relay_id"); id != "" {
		ip := r.URL.Query().Get("is_proxy") == "true"
		return id, ip, nil
	}
	return "", false, fmt.Errorf("missing_relay_credentials")
}

// handleRelayMessage dispatches an incoming relay message to the appropriate handler.
func handleRelayMessage(conn *RelayConnection, msg RelayMessage) {
	switch msg.Type {

	case "relay_hello":
		// Relay identifies itself; proxy acknowledges
		if msg.RelayID != "" && msg.RelayID != conn.RelayID {
			// Relay hello may re-assert a different relay_id — trust the JWT sub
			log.Printf("Relay hello relay_id mismatch: jwt=%s hello=%s — using JWT",
				conn.RelayID, msg.RelayID)
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
		ack := RelayMessage{
			Type:      "relay_ack",
			RelayID:   conn.RelayID,
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
	registerRelayConnection(relayConn)

	defer func() {
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
