package ws

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
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
	TaskID   string                 `json:"task_id"`
	Type     string                 `json:"type"`     // ack, stdout, result, put_file, fetch_file
	RC       int                    `json:"rc"`
	Stdout   string                 `json:"stdout"`
	Stderr   string                 `json:"stderr"`
	Truncated bool                  `json:"truncated"`
	Data     string                 `json:"data"`     // For fetch_file
	Error    string                 `json:"error"`
	Chunk    string                 `json:"chunk"`    // For stdout streaming
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
)

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

	// TODO: Update agent_status in database to "connected"
	// store.UpdateAgentStatus(hostname, "connected", nowISO())
}

// UnregisterConnection removes a hostname from active connections
func UnregisterConnection(hostname string) {
	connectionsMu.Lock()
	defer connectionsMu.Unlock()

	delete(wsConnections, hostname)
	log.Printf("Agent disconnected: hostname=%s", hostname)

	// Resolve all pending futures with error
	ResolveFuturesForHostname(hostname, "agent_disconnected")

	// TODO: Update agent_status in database to "disconnected"
	// store.UpdateAgentStatus(hostname, "disconnected", nowISO())
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

	// TODO: Update agent last_seen timestamp in database
	// store.UpdateLastSeen(hostname)

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

// AgentHandler manages WebSocket connections from relay-agents
// Flow:
// 1. Verify JWT from Authorization header BEFORE accepting connection
// 2. Accept connection (only if JWT is valid)
// 3. Register in wsConnections
// 4. Receive messages in a loop until disconnect
// 5. On disconnect: update status, cleanup, resolve pending futures
func AgentHandler(w http.ResponseWriter, r *http.Request) {
	// TODO: Extract and verify JWT from r.Header.Get("Authorization")
	// For now, skip JWT verification (will be integrated with routes_register.go helpers)

	// Step 1: Upgrade connection
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade failed: %v", err)
		http.Error(w, "upgrade failed", http.StatusBadRequest)
		return
	}

	// Extract hostname from JWT (for now, use query parameter as fallback)
	// TODO: hostname := jwt_payload["sub"]
	hostname := r.URL.Query().Get("hostname")
	if hostname == "" {
		conn.WriteMessage(websocket.CloseMessage,
			websocket.FormatCloseMessage(WSCloseRevoked, "missing hostname"))
		conn.Close()
		return
	}

	// Step 2: Register the connection
	agentConn := &AgentConnection{
		Hostname: hostname,
		Conn:     conn,
	}
	RegisterConnection(hostname, agentConn)

	// Step 3: Message reception loop
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
