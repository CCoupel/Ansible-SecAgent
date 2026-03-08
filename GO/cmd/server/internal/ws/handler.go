package ws

import (
	"encoding/base64"
	"encoding/json"
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

// AgentConnection represents an active WebSocket connection from a relay-agent
type AgentConnection struct {
	Hostname string
	Conn     *websocket.Conn
	mu       sync.RWMutex
}

// Message represents a message sent over the WebSocket
type Message struct {
	TaskID    string `json:"task_id"`
	Type      string `json:"type"`     // ack, stdout, result, put_file, fetch_file
	RC        int    `json:"rc"`
	Stdout    string `json:"stdout"`
	Stderr    string `json:"stderr"`
	Truncated bool   `json:"truncated"`
	Data      string `json:"data"`  // For fetch_file
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
		oldConn.Conn.Close()
	}

	wsConnections[hostname] = conn
	log.Printf("Agent connected: hostname=%s", hostname)
}

// UnregisterConnection removes a hostname from active connections
func UnregisterConnection(hostname string) {
	connectionsMu.Lock()
	defer connectionsMu.Unlock()

	delete(wsConnections, hostname)
	log.Printf("Agent disconnected: hostname=%s", hostname)

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

// extractHostnameFromRequest validates the JWT Bearer token using dual-key validation
// and extracts the "sub" claim as hostname. Falls back to ?hostname= query param
// only when JWTSecretsFunc is not configured (e.g. tests without DB).
// Returns (hostname, usedPreviousKey, error).
func extractHostnameFromRequest(r *http.Request) (hostname string, usedPrevious bool, err error) {
	authHeader := r.Header.Get("Authorization")

	// If JWT validation is configured, use it (production path)
	if JWTSecretsFunc != nil && strings.HasPrefix(authHeader, "Bearer ") {
		claims, prev, valErr := ExtractJWTClaims(authHeader)
		if valErr != nil {
			return "", false, fmt.Errorf("jwt_invalid: %w", valErr)
		}
		sub, _ := claims["sub"].(string)
		if sub == "" {
			return "", false, fmt.Errorf("jwt_missing_sub")
		}
		return sub, prev, nil
	}

	// Fallback: extract sub from JWT payload without verification (tests / no-DB mode)
	log.Printf("[SECURITY WARNING] JWT verification bypassed — JWTSecretsFunc is nil")
	if strings.HasPrefix(authHeader, "Bearer ") && len(authHeader) > 7 {
		sub := extractSubFromJWTUnsafe(authHeader[7:])
		if sub != "" {
			return sub, false, nil
		}
	}

	// Last resort: query param (legacy / tests)
	if h := r.URL.Query().Get("hostname"); h != "" {
		return h, false, nil
	}

	return "", false, fmt.Errorf("missing_hostname")
}

// extractSubFromJWTUnsafe decodes the JWT payload without signature verification.
// Used only when JWTSecretsFunc is not configured (tests, degraded mode).
func extractSubFromJWTUnsafe(tokenStr string) string {
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return ""
	}
	// JWT uses base64url without padding
	padded := parts[1]
	switch len(padded) % 4 {
	case 2:
		padded += "=="
	case 3:
		padded += "="
	}
	decoded, err := base64.StdEncoding.DecodeString(padded)
	if err != nil {
		// Try RawStdEncoding as fallback (no padding)
		decoded, err = base64.RawStdEncoding.DecodeString(parts[1])
		if err != nil {
			return ""
		}
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(decoded, &payload); err != nil {
		return ""
	}
	sub, _ := payload["sub"].(string)
	return sub
}

// AgentHandler manages WebSocket connections from relay-agents.
//
// Flow:
//  1. Validate JWT (dual-key if rotation in progress) — reject with 401 on failure
//  2. Extract hostname from JWT "sub" claim
//  3. Upgrade connection
//  4. If validated with previous key: send rekey message opportunistically
//  5. Register connection and loop on incoming messages
//  6. On disconnect: cleanup, resolve pending futures
func AgentHandler(w http.ResponseWriter, r *http.Request) {
	hostname, usedPrevious, err := extractHostnameFromRequest(r)
	if err != nil {
		log.Printf("WS auth rejected: %v", err)
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
			conn.WriteJSON(map[string]interface{}{"type": "rekey"}) //nolint:errcheck
			agentConn.mu.Unlock()
		}
		log.Printf("Rekey sent to agent: hostname=%s encrypted=%v", hostname, sent)
	}

	defer func() {
		UnregisterConnection(hostname)
		conn.Close()
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
	conn.Conn.WriteMessage(websocket.CloseMessage, closeMsg) //nolint:errcheck
	conn.Conn.Close()
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
