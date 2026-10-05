package ws

import (
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	CheckOrigin:     func(r *http.Request) bool { return true },
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
}

// WebSocketCloseCodes represent the custom close codes for WebSocket connections (ARCHITECTURE.md §4)
const (
	WSCloseRevoked = 4001 // Token revoked — agent must not reconnect
	WSCloseExpired = 4002 // Token expired — agent should refresh then reconnect
	WSCloseNormal  = 4000 // Normal close
)

// AgentConnection represents an active WebSocket connection from a secagent-minion
type AgentConnection struct {
	Hostname string
	Conn     *websocket.Conn
	mu       sync.RWMutex
}

// Message represents a message sent over the WebSocket
type Message struct {
	TaskID    string `json:"task_id"`
	Type      string `json:"type"` // ack, stdout, result, put_file, fetch_file
	RC        int    `json:"rc"`
	Stdout    string `json:"stdout"`
	Stderr    string `json:"stderr"`
	Truncated bool   `json:"truncated"`
	Data      string `json:"data"` // For fetch_file
	Error     string `json:"error"`
	Chunk     string `json:"chunk"` // For stdout streaming
}

// TaskResult represents the final result of a task
type TaskResult struct {
	TaskID    string `json:"task_id"`
	RC        int    `json:"rc"`
	Stdout    string `json:"stdout"`
	Stderr    string `json:"stderr"`
	Truncated bool   `json:"truncated"`
}

// Global state for WebSocket connections (all access from the event loop — no locking required)
var (
	// hostname -> active WebSocket connection
	wsConnections = make(map[string]*AgentConnection)
	connectionsMu = sync.RWMutex{}

	// task_id -> channel that receives the result
	pendingTasks = make(map[string]chan Message)
	tasksMu      = sync.RWMutex{}

	// task_id -> accumulated stdout string
	stdoutBuffers = make(map[string]string)
	buffersMu     = sync.RWMutex{}

	// task_id -> hostname mapping for cleanup on disconnect
	taskHostnames = make(map[string]string)
	taskHostMu    = sync.RWMutex{}

	// Maximum accumulated stdout per task (5 MB — ARCHITECTURE.md §2)
	stdoutMaxBytes = 5 * 1024 * 1024

	// RekeyFunc is called when an agent authenticates with the previous JWT secret.
	// It should sign a new JWT and send the encrypted token to the agent.
	// Injected from handlers at startup; nil = send a plain rekey signal (no encrypted token).
	RekeyFunc func(hostname string) bool

	// DispatchFunc is called when an agent connects (host.up) or disconnects (host.down).
	// Injected from main.go at startup to avoid an import cycle between ws and hooks.
	// Signature: (event, hostname, status, enrolledAt) — enrolledAt is always "" here.
	// nil = no dispatch (tests, degraded mode).
	DispatchFunc func(event string, hostname string, status string, enrolledAt string)
)

// SetRekeyFunc injects the function used to issue a new encrypted token to an agent.
// Called at startup by main.go after handlers are initialized.
func SetRekeyFunc(fn func(hostname string) bool) {
	RekeyFunc = fn
}

// CustomError represents errors returned by WebSocket handlers
type CustomError struct {
	Error string `json:"error"`
}

// nowISO returns the current time in ISO 8601 format
func nowISO() string {
	return time.Now().UTC().Format(time.RFC3339)
}

// RegisterConnection registers a WebSocket connection for a hostname
func RegisterConnection(hostname string, conn *AgentConnection) {
	connectionsMu.Lock()
	defer connectionsMu.Unlock()

	// Close any existing connection for this hostname
	if oldConn, exists := wsConnections[hostname]; exists {
		log.Printf("Replacing stale WS for hostname: %s", hostname)
		_ = oldConn.Conn.Close()
	}

	wsConnections[hostname] = conn
	log.Printf("Agent connected: hostname=%s", hostname)

	if DispatchFunc != nil {
		go DispatchFunc("host.up", hostname, "connected", "")
	}
}

// UnregisterConnection removes a hostname from active connections
func UnregisterConnection(hostname string) {
	connectionsMu.Lock()
	defer connectionsMu.Unlock()

	delete(wsConnections, hostname)
	log.Printf("Agent disconnected: hostname=%s", hostname)

	if DispatchFunc != nil {
		go DispatchFunc("host.down", hostname, "disconnected", "")
	}

	// Resolve all pending futures with error
	ResolveFuturesForHostname(hostname, "agent_disconnected")
}

// GetConnection retrieves a WebSocket connection by hostname
func GetConnection(hostname string) (*AgentConnection, error) {
	connectionsMu.RLock()
	defer connectionsMu.RUnlock()

	conn, exists := wsConnections[hostname]
	if !exists {
		return nil, fmt.Errorf("agent_offline")
	}
	return conn, nil
}

// RegisterFuture creates and registers a channel for a task result
func RegisterFuture(taskID string, hostname string) chan Message {
	tasksMu.Lock()
	defer tasksMu.Unlock()

	resultChan := make(chan Message, 1)
	pendingTasks[taskID] = resultChan

	taskHostMu.Lock()
	taskHostnames[taskID] = hostname
	taskHostMu.Unlock()

	return resultChan
}

// UnregisterFuture removes a pending future without resolving it (used for cleanup on send failure or timeout).
func UnregisterFuture(taskID string) {
	tasksMu.Lock()
	delete(pendingTasks, taskID)
	tasksMu.Unlock()

	taskHostMu.Lock()
	delete(taskHostnames, taskID)
	taskHostMu.Unlock()

	buffersMu.Lock()
	delete(stdoutBuffers, taskID)
	buffersMu.Unlock()
}

// ResolveFuturesForHostname resolves all pending futures for a hostname with an error
func ResolveFuturesForHostname(hostname string, errorMsg string) {
	taskHostMu.RLock()
	taskIDs := []string{}
	for taskID, h := range taskHostnames {
		if h == hostname {
			taskIDs = append(taskIDs, taskID)
		}
	}
	taskHostMu.RUnlock()

	for _, taskID := range taskIDs {
		tasksMu.RLock()
		resultChan, exists := pendingTasks[taskID]
		tasksMu.RUnlock()

		if exists {
			select {
			case resultChan <- Message{TaskID: taskID, Error: errorMsg}:
			default:
				// Channel already has a result or is closed
			}
			log.Printf("Future resolved with error on disconnect: task_id=%s error=%s hostname=%s",
				taskID, errorMsg, hostname)
		}

		// Cleanup
		tasksMu.Lock()
		delete(pendingTasks, taskID)
		tasksMu.Unlock()

		buffersMu.Lock()
		delete(stdoutBuffers, taskID)
		buffersMu.Unlock()

		taskHostMu.Lock()
		delete(taskHostnames, taskID)
		taskHostMu.Unlock()
	}
}

// SendToAgent sends a JSON message to a connected agent over its WebSocket
func SendToAgent(hostname string, message map[string]interface{}) error {
	conn, err := GetConnection(hostname)
	if err != nil {
		return err
	}

	conn.mu.Lock()
	defer conn.mu.Unlock()

	// Register task_id → hostname mapping if task_id is present
	if taskID, ok := message["task_id"].(string); ok {
		taskHostMu.Lock()
		taskHostnames[taskID] = hostname
		taskHostMu.Unlock()
	}

	return conn.Conn.WriteJSON(message)
}

// HandleMessage dispatches a message received from an agent
func HandleMessage(msg Message, hostname string) {
	taskID := msg.TaskID
	msgType := msg.Type

	if taskID == "" || msgType == "" {
		log.Printf("WS message missing task_id or type: hostname=%s msg=%+v", hostname, msg)
		return
	}

	switch msgType {
	case "ack":
		// Subprocess started — just log
		log.Printf("Task ack received: task_id=%s hostname=%s", taskID, hostname)

	case "stdout":
		// Accumulate stdout, enforce 5 MB cap
		buffersMu.Lock()
		buf := stdoutBuffers[taskID]
		combined := buf + msg.Chunk
		if len([]byte(combined)) > stdoutMaxBytes {
			// Truncate to max size
			runes := []rune(combined)
			for len(string(runes)) > stdoutMaxBytes {
				runes = runes[:len(runes)-1]
			}
			combined = string(runes)
			log.Printf("Stdout buffer truncated: task_id=%s hostname=%s", taskID, hostname)
		}
		stdoutBuffers[taskID] = combined
		buffersMu.Unlock()

	case "result":
		// Final result — resolve future
		buffersMu.Lock()
		accumulatedStdout := stdoutBuffers[taskID]
		buffersMu.Unlock()

		if msg.Stdout == "" && accumulatedStdout != "" {
			msg.Stdout = accumulatedStdout
		}

		tasksMu.RLock()
		resultChan, exists := pendingTasks[taskID]
		tasksMu.RUnlock()

		if exists {
			select {
			case resultChan <- msg:
				log.Printf("Task result received: task_id=%s rc=%d hostname=%s", taskID, msg.RC, hostname)
			default:
				log.Printf("Result channel full or closed: task_id=%s hostname=%s", taskID, hostname)
			}
		} else {
			log.Printf("Result received but no pending future: task_id=%s hostname=%s", taskID, hostname)
		}

		// Cleanup
		tasksMu.Lock()
		delete(pendingTasks, taskID)
		tasksMu.Unlock()

		buffersMu.Lock()
		delete(stdoutBuffers, taskID)
		buffersMu.Unlock()

		taskHostMu.Lock()
		delete(taskHostnames, taskID)
		taskHostMu.Unlock()

	default:
		log.Printf("Unknown WS message type: type=%s task_id=%s hostname=%s", msgType, taskID, hostname)
	}
}

// agentJTICheckFn decides whether the agent presenting jti may connect (see SetAgentJTICheckFunc).
var (
	agentJTICheckMu sync.RWMutex
	agentJTICheckFn func(hostname, jti string, usedPrevious bool) error
)

// SetAgentJTICheckFunc injects the revocation check used at the /ws/agent handshake. The
// function returns nil when the token is acceptable, an error otherwise (revoked, replaced,
// unknown agent, store failure). usedPrevious is true when the token was validated with the
// previous JWT secret (rotation grace period).
func SetAgentJTICheckFunc(fn func(hostname, jti string, usedPrevious bool) error) {
	agentJTICheckMu.Lock()
	agentJTICheckFn = fn
	agentJTICheckMu.Unlock()
}

// checkAgentJTI fails closed: without a configured check no verified token is accepted.
func checkAgentJTI(hostname, jti string, usedPrevious bool) error {
	agentJTICheckMu.RLock()
	fn := agentJTICheckFn
	agentJTICheckMu.RUnlock()
	if fn == nil {
		return fmt.Errorf("blacklist_not_configured")
	}
	if jti == "" {
		return fmt.Errorf("token_without_jti")
	}
	return fn(hostname, jti, usedPrevious)
}

// truncateJTI keeps the log readable without reproducing a full identifier.
func truncateJTI(jti string) string {
	if len(jti) > 8 {
		return jti[:8] + "…"
	}
	return jti
}

// agentRole is the JWT "role" claim carried by every token issued to a minion (SECURITY.md §2).
const agentRole = "agent"

// extractHostnameFromRequest validates the JWT Bearer token using dual-key validation
// and extracts the "sub" claim as hostname. There is no unsigned fallback.
// Returns (hostname, usedPreviousKey, error).
func extractHostnameFromRequest(r *http.Request) (hostname string, usedPrevious bool, err error) {
	id, err := authenticateAgentRequest(r)
	if err != nil {
		return "", false, err
	}
	return id.Hostname, id.UsedPrevious, nil
}

// agentIdentity is what the /ws/agent handshake established about the caller. It always comes
// from a JWT whose signature was verified.
type agentIdentity struct {
	Hostname     string
	JTI          string
	UsedPrevious bool
}

// authenticateAgentRequest validates the Bearer token (dual-key) and returns the identity.
//
// Fail closed (same model as extractRelayAuth on /ws/relay): the ONLY accepted credential is a
// Bearer JWT signed with the server secret, carrying role "agent" and a non-empty sub. No
// verifier configured, no/empty/non-Bearer Authorization header, a bad signature, another role,
// or a bare ?hostname= are all refused. Nothing the client sends unsigned is ever trusted.
func authenticateAgentRequest(r *http.Request) (agentIdentity, error) {
	if JWTSecretsFunc == nil {
		log.Printf("[SECURITY WARNING] agent connection refused: JWTSecretsFunc is not configured (fail closed)")
		return agentIdentity{}, fmt.Errorf("jwt_not_configured")
	}
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") || len(authHeader) <= len("Bearer ") {
		log.Printf("[SECURITY WARNING] agent connection refused: missing bearer token")
		return agentIdentity{}, fmt.Errorf("missing_agent_credentials")
	}
	claims, prev, valErr := ExtractJWTClaims(authHeader)
	if valErr != nil {
		return agentIdentity{}, fmt.Errorf("jwt_invalid: %w", valErr)
	}
	if role, _ := claims["role"].(string); role != agentRole {
		log.Printf("[SECURITY WARNING] agent connection refused: wrong JWT role %q", role)
		return agentIdentity{}, fmt.Errorf("jwt_wrong_role")
	}
	sub, _ := claims["sub"].(string)
	if sub == "" {
		return agentIdentity{}, fmt.Errorf("jwt_missing_sub")
	}
	jti, _ := claims["jti"].(string)
	return agentIdentity{Hostname: sub, JTI: jti, UsedPrevious: prev}, nil
}

// AgentHandler manages WebSocket connections from secagent-minions.
//
// Flow:
//  1. Validate JWT (dual-key if rotation in progress) — reject with 401 on failure
//  2. Extract hostname from JWT "sub" claim
//  3. Upgrade connection
//  4. If validated with previous key: send rekey message opportunistically
//  5. Register connection and loop on incoming messages
//  6. On disconnect: cleanup, resolve pending futures
func AgentHandler(w http.ResponseWriter, r *http.Request) {
	id, err := authenticateAgentRequest(r)
	if err != nil {
		log.Printf("WS auth rejected: %v", err)
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}
	hostname, usedPrevious := id.Hostname, id.UsedPrevious

	// Revocation / token-replacement check BEFORE the upgrade (401, no close code, SECURITY.md §4).
	// Fail closed: a token is only accepted when the check is configured and passes.
	if err := checkAgentJTI(hostname, id.JTI, usedPrevious); err != nil {
		log.Printf("[SECURITY WARNING] agent connection refused: hostname=%q jti=%q: %v",
			hostname, truncateJTI(id.JTI), err)
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	// Upgrade HTTP → WebSocket
	conn, upgradeErr := upgrader.Upgrade(w, r, nil)
	if upgradeErr != nil {
		log.Printf("WebSocket upgrade failed: %v", upgradeErr)
		return
	}

	agentConn := &AgentConnection{
		Hostname: hostname,
		Conn:     conn,
	}
	RegisterConnection(hostname, agentConn)

	// If agent authenticated with the previous JWT secret, send rekey message
	// so it gets a fresh token signed with the current secret.
	if usedPrevious {
		sent := false
		if RekeyFunc != nil {
			// Send encrypted rekey (includes new token_encrypted)
			sent = RekeyFunc(hostname)
		}
		if !sent {
			// Fallback: plain rekey signal (agent should re-enroll)
			agentConn.mu.Lock()
			if err := conn.WriteJSON(map[string]interface{}{"type": "rekey"}); err != nil {
				log.Printf("rekey WriteJSON: hostname=%s err=%v", hostname, err)
			}
			agentConn.mu.Unlock()
		}
		log.Printf("Rekey sent to agent: hostname=%s encrypted=%v", hostname, sent)
	}

	defer func() {
		UnregisterConnection(hostname)
		_ = conn.Close()
	}()

	for {
		var msg Message
		err := conn.ReadJSON(&msg)
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("WebSocket error: %v for hostname: %s", err, hostname)
			}
			break
		}
		HandleMessage(msg, hostname)
	}
}

// CloseAgent sends a WebSocket close frame to a connected agent and removes the connection.
// Used by revoke endpoint to disconnect an agent with code 4001 (token revoked).
func CloseAgent(hostname string, code int, reason string) bool {
	connectionsMu.Lock()
	conn, exists := wsConnections[hostname]
	if !exists {
		connectionsMu.Unlock()
		return false
	}
	delete(wsConnections, hostname)
	connectionsMu.Unlock()

	conn.mu.Lock()
	closeMsg := websocket.FormatCloseMessage(code, reason)
	if err := conn.Conn.WriteMessage(websocket.CloseMessage, closeMsg); err != nil {
		log.Printf("CloseAgent WriteMessage: hostname=%s code=%d err=%v", hostname, code, err)
	}
	_ = conn.Conn.Close()
	conn.mu.Unlock()

	// Resolve any pending futures for this hostname
	ResolveFuturesForHostname(hostname, "agent_revoked")

	log.Printf("Agent force-closed: hostname=%s code=%d reason=%s", hostname, code, reason)
	return true
}

// GetConnectedCount returns the number of currently connected agents.
func GetConnectedCount() int {
	connectionsMu.RLock()
	defer connectionsMu.RUnlock()
	return len(wsConnections)
}

// GetPendingTaskCount returns the number of tasks awaiting a result.
func GetPendingTaskCount() int {
	tasksMu.RLock()
	defer tasksMu.RUnlock()
	return len(pendingTasks)
}

// GetConnectedHostnames returns the list of currently connected agent hostnames.
func GetConnectedHostnames() []string {
	connectionsMu.RLock()
	defer connectionsMu.RUnlock()
	hosts := make([]string, 0, len(wsConnections))
	for h := range wsConnections {
		hosts = append(hosts, h)
	}
	return hosts
}

// WaitForResult waits for a task result on a channel with timeout
// Returns the result or an error if timeout occurs
func WaitForResult(resultChan chan Message, timeout time.Duration) (Message, error) {
	select {
	case result := <-resultChan:
		return result, nil
	case <-time.After(timeout):
		return Message{}, fmt.Errorf("timeout waiting for task result")
	}
}
