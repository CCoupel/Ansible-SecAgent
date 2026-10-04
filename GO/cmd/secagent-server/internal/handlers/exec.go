package handlers

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"secagent-server/cmd/secagent-server/internal/proxy"
	"secagent-server/cmd/secagent-server/internal/ws"
)

// proxyRouter is always initialized by main.go (v3.0+).
// When non-nil, exec/upload/fetch operations check relay_routing before local agents.
var proxyRouter *proxy.ProxyRouter

// SetProxyRouter injects a ProxyRouter for relay task routing.
// Called unconditionally from main.go at startup.
func SetProxyRouter(r *proxy.ProxyRouter) { proxyRouter = r }

// ExecRequest represents a command execution request
type ExecRequest struct {
	TaskID       *string `json:"task_id"`       // Optional: caller-supplied task ID
	Cmd          string  `json:"cmd"`           // Command to execute
	Stdin        *string `json:"stdin"`         // Optional: base64-encoded stdin
	Timeout      int     `json:"timeout"`       // Seconds (default 30)
	Become       bool    `json:"become"`        // Enable privilege escalation
	BecomeMethod string  `json:"become_method"` // Method (default "sudo")
}

// UploadRequest represents a file upload request
type UploadRequest struct {
	TaskID *string `json:"task_id"` // Optional: caller-supplied task ID
	Dest   string  `json:"dest"`    // Destination path
	Data   string  `json:"data"`    // base64-encoded file content
	Mode   string  `json:"mode"`    // File mode (default "0644")
}

// FetchRequest represents a file fetch request
type FetchRequest struct {
	TaskID *string `json:"task_id"` // Optional: caller-supplied task ID
	Src    string  `json:"src"`     // Source path to fetch
}

// ExecResponse represents the result of task execution
type ExecResponse struct {
	RC        int    `json:"rc"`
	Stdout    string `json:"stdout"`
	Stderr    string `json:"stderr"`
	Truncated bool   `json:"truncated"`
}

// UploadResponse represents the result of file upload
type UploadResponse struct {
	RC int `json:"rc"`
}

// FetchResponse represents the result of file fetch
type FetchResponse struct {
	RC   int    `json:"rc"`
	Data string `json:"data"`
}

// Task result constants
const (
	fileMaxBytes     = 500 * 1024 // 500 KB decoded limit
	timeoutMarginSec = 5          // Extra seconds on top of task timeout
)

// In-memory storage for completed task results (task_id -> result)
var completedResults = make(map[string]map[string]interface{})

// newTaskID generates a new UUID-based task ID
func newTaskID() string {
	return uuid.New().String()
}

// nowTS returns the current Unix timestamp
func nowTS() int64 {
	return time.Now().Unix()
}

// validateExecRequest validates an ExecRequest
func validateExecRequest(req *ExecRequest) error {
	if strings.TrimSpace(req.Cmd) == "" {
		return fmt.Errorf("cmd must not be empty")
	}
	if req.Timeout <= 0 {
		req.Timeout = 30 // Default timeout
	}
	if req.BecomeMethod == "" {
		req.BecomeMethod = "sudo"
	}
	return nil
}

// validateUploadRequest validates an UploadRequest
func validateUploadRequest(req *UploadRequest) error {
	if strings.TrimSpace(req.Dest) == "" {
		return fmt.Errorf("dest must not be empty")
	}
	if strings.TrimSpace(req.Data) == "" {
		return fmt.Errorf("data must not be empty")
	}
	if req.Mode == "" {
		req.Mode = "0644"
	}
	return nil
}

// validateFetchRequest validates a FetchRequest
func validateFetchRequest(req *FetchRequest) error {
	if strings.TrimSpace(req.Src) == "" {
		return fmt.Errorf("src must not be empty")
	}
	return nil
}

// isLocalAgent reports whether hostname has a live /ws/agent connection on this node. A live
// connection takes precedence over relay_routing: a relay declaring a host that is connected
// here must not be able to divert its tasks (and become_pass stdin).
func isLocalAgent(hostname string) bool {
	_, err := ws.GetConnection(hostname)
	return err == nil
}

// checkAgentOnline verifies that an agent has an active WebSocket connection.
// Returns error with "hostname must not be empty" or "agent_offline".
func checkAgentOnline(hostname string) error {
	if hostname == "" {
		return fmt.Errorf("hostname must not be empty")
	}
	if _, err := ws.GetConnection(hostname); err != nil {
		return fmt.Errorf("agent_offline")
	}
	return nil
}

// logExecSafe logs an exec request with explicit stdin markers.
//
// SECURITY (CRITICAL): become_pass must never appear in any log.
//   - become=true  + stdin non-nil  → "stdin=<redacted>"
//   - become=false + stdin non-nil  → "stdin=<set>"
//   - stdin nil (any)               → "stdin=none"
//
// Using explicit string markers (not %v on a *string) ensures the behaviour
// is intentional and not accidentally safe via pointer-address printing.
func logExecSafe(hostname string, taskID string, req *ExecRequest) {
	var stdinMarker string
	switch {
	case req.Stdin == nil:
		stdinMarker = "none"
	case req.Become:
		stdinMarker = "<redacted>"
	default:
		stdinMarker = "<set>"
	}
	log.Printf("Exec request: hostname=%s task_id=%s cmd=%s become=%v stdin=%s timeout=%d",
		hostname, taskID, req.Cmd, req.Become, stdinMarker, req.Timeout)
}

// pointerString returns a pointer to a string
func pointerString(s string) *string {
	return &s
}

// sendTaskAndWait registers a result future, sends a message to the agent via
// WebSocket, and waits up to (timeout + timeoutMarginSec) for the result.
// Returns the result Message or an error.
func sendTaskAndWait(hostname, taskID string, message map[string]interface{}, timeout int) (ws.Message, error) {
	// Register channel before send to avoid race where result arrives before we listen
	resultChan := ws.RegisterFuture(taskID, hostname)

	if err := ws.SendToAgent(hostname, message); err != nil {
		// Cleanup the orphaned future
		ws.UnregisterFuture(taskID)
		return ws.Message{}, fmt.Errorf("send_failed: %w", err)
	}

	totalTimeout := time.Duration(timeout+timeoutMarginSec) * time.Second
	result, err := ws.WaitForResult(resultChan, totalTimeout)
	if err != nil {
		ws.UnregisterFuture(taskID)
		return ws.Message{}, fmt.Errorf("timeout")
	}
	return result, nil
}

// writeAgentError writes a JSON error response for agent-side errors.
func writeAgentError(w http.ResponseWriter, errStr string, hostname, taskID string) {
	switch errStr {
	case "agent_disconnected":
		log.Printf("Agent disconnected during task: hostname=%s task_id=%s", hostname, taskID)
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "agent_disconnected"})
	case "agent_busy":
		log.Printf("Agent busy: hostname=%s task_id=%s", hostname, taskID)
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "agent_busy"})
	default:
		log.Printf("Agent error: hostname=%s task_id=%s error=%s", hostname, taskID, errStr)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": errStr})
	}
}

// POST /api/exec/{hostname} — Execute a command on a remote agent
func ExecCommand(w http.ResponseWriter, r *http.Request) {
	// Plugin token authentication (SECURITY.md §6)
	if _, ok := requirePluginAuth(w, r); !ok {
		return
	}

	hostname := r.PathValue("hostname")

	// Parse and validate request first (400 before 503)
	var req ExecRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json"})
		return
	}

	if err := validateExecRequest(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	// Generate or use provided task ID
	taskID := req.TaskID
	if taskID == nil || *taskID == "" {
		taskID = pointerString(newTaskID())
	}

	// Proxy mode: check if hostname is on a remote relay BEFORE checking local WS
	if proxyRouter != nil && !isLocalAgent(hostname) {
		// Anti-loop: read X-Relay-Hops, reject if budget exhausted, decrement for outgoing call
		proxyHops := proxy.DefaultMaxHops
		if hopStr := r.Header.Get(proxy.RelayHopsHeader); hopStr != "" {
			if n, convErr := strconv.Atoi(hopStr); convErr == nil {
				if n <= 0 {
					log.Printf("[PROXY] relay_loop_detected: hostname=%s hops=%d", hostname, n)
					writeJSON(w, http.StatusLoopDetected, map[string]string{"error": "relay_loop_detected"})
					return
				}
				proxyHops = n - 1
			}
		}
		proxyCtx := proxy.WithRelayHops(r.Context(), proxyHops)

		relayID, relayErr := proxyRouter.GetRelayForHostname(hostname)
		if relayErr == nil {
			// Hostname is managed by a downstream relay — route via proxy
			logExecSafe(hostname, *taskID, &req)
			proxyReq := proxy.ExecRequest{
				Cmd:          req.Cmd,
				Timeout:      req.Timeout,
				Become:       req.Become,
				BecomeMethod: req.BecomeMethod,
				TaskID:       *taskID,
			}
			if req.Stdin != nil {
				proxyReq.Stdin = *req.Stdin
			}
			resp, pErr := proxyRouter.RouteExec(proxyCtx, hostname, *taskID, proxyReq)
			if pErr != nil {
				writeProxyExecError(w, pErr, hostname, *taskID)
				return
			}
			log.Printf("Proxy exec complete: hostname=%s relay_id=%s task_id=%s rc=%d",
				hostname, relayID, *taskID, resp.RC)
			writeJSON(w, http.StatusOK, map[string]interface{}{
				"rc":        resp.RC,
				"stdout":    resp.Stdout,
				"stderr":    resp.Stderr,
				"truncated": resp.Truncated,
			})
			return
		} else if !errors.Is(relayErr, proxy.ErrHostNotFound) {
			// Real DB error — log but fall through to local agent
			log.Printf("[PROXY] relay routing lookup error: hostname=%s err=%v", hostname, relayErr)
		}
		// ErrHostNotFound → fall through to local agent lookup below
	}

	// Verify agent is connected via live WS registry
	if err := checkAgentOnline(hostname); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "agent_offline"})
		return
	}

	logExecSafe(hostname, *taskID, &req)

	// Build WebSocket message (ARCHITECTURE.md §4)
	message := map[string]interface{}{
		"task_id":       *taskID,
		"type":          "exec",
		"cmd":           req.Cmd,
		"timeout":       req.Timeout,
		"become":        req.Become,
		"become_method": req.BecomeMethod,
		"expires_at":    nowTS() + int64(req.Timeout),
	}
	if req.Stdin != nil {
		message["stdin"] = *req.Stdin
	}

	// Send to agent and wait for result
	result, err := sendTaskAndWait(hostname, *taskID, message, req.Timeout)
	if err != nil {
		if strings.Contains(err.Error(), "timeout") {
			writeJSON(w, http.StatusGatewayTimeout, map[string]string{"error": "task_timeout"})
		} else {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": err.Error()})
		}
		return
	}

	// Handle agent-side errors
	if result.Error != "" {
		writeAgentError(w, result.Error, hostname, *taskID)
		return
	}

	log.Printf("Exec complete: hostname=%s task_id=%s rc=%d", hostname, *taskID, result.RC)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"rc":        result.RC,
		"stdout":    result.Stdout,
		"stderr":    result.Stderr,
		"truncated": result.Truncated,
	})
}

// POST /api/upload/{hostname} — Transfer a file to a remote agent
func UploadFile(w http.ResponseWriter, r *http.Request) {
	// Plugin token authentication (SECURITY.md §6)
	if _, ok := requirePluginAuth(w, r); !ok {
		return
	}

	hostname := r.PathValue("hostname")

	// Parse and validate request first (400 before 503)
	var req UploadRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json"})
		return
	}

	if err := validateUploadRequest(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	// Validate decoded size before sending
	decoded, err := base64.StdEncoding.DecodeString(req.Data)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_base64"})
		return
	}

	if len(decoded) > fileMaxBytes {
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]interface{}{
			"error":     "payload_too_large",
			"max_bytes": fileMaxBytes,
		})
		return
	}

	// Generate or use provided task ID
	taskID := req.TaskID
	if taskID == nil || *taskID == "" {
		taskID = pointerString(newTaskID())
	}

	// Proxy mode: check relay routing before local WS
	if proxyRouter != nil && !isLocalAgent(hostname) {
		// Anti-loop: read X-Relay-Hops, reject if budget exhausted, decrement for outgoing call
		proxyHops := proxy.DefaultMaxHops
		if hopStr := r.Header.Get(proxy.RelayHopsHeader); hopStr != "" {
			if n, convErr := strconv.Atoi(hopStr); convErr == nil {
				if n <= 0 {
					log.Printf("[PROXY] relay_loop_detected: hostname=%s hops=%d", hostname, n)
					writeJSON(w, http.StatusLoopDetected, map[string]string{"error": "relay_loop_detected"})
					return
				}
				proxyHops = n - 1
			}
		}
		proxyCtx := proxy.WithRelayHops(r.Context(), proxyHops)

		relayID, relayErr := proxyRouter.GetRelayForHostname(hostname)
		if relayErr == nil {
			log.Printf("Upload request (proxy): hostname=%s relay_id=%s task_id=%s dest=%s size=%d",
				hostname, relayID, *taskID, req.Dest, len(decoded))
			proxyReq := proxy.UploadRequest{Dest: req.Dest, Data: req.Data, Mode: req.Mode}
			if pErr := proxyRouter.RouteUpload(proxyCtx, hostname, *taskID, proxyReq); pErr != nil {
				writeProxyExecError(w, pErr, hostname, *taskID)
				return
			}
			writeJSON(w, http.StatusOK, map[string]interface{}{"rc": 0})
			return
		} else if !errors.Is(relayErr, proxy.ErrHostNotFound) {
			log.Printf("[PROXY] relay routing lookup error: hostname=%s err=%v", hostname, relayErr)
		}
	}

	// Verify agent is connected (after validation)
	if err := checkAgentOnline(hostname); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "agent_offline"})
		return
	}

	log.Printf("Upload request: hostname=%s task_id=%s dest=%s size=%d",
		hostname, *taskID, req.Dest, len(decoded))

	// Build WebSocket message
	message := map[string]interface{}{
		"task_id": *taskID,
		"type":    "put_file",
		"dest":    req.Dest,
		"data":    req.Data,
		"mode":    req.Mode,
	}

	// Default timeout for file operations: 60s
	fileTimeout := 60
	result, err := sendTaskAndWait(hostname, *taskID, message, fileTimeout)
	if err != nil {
		if strings.Contains(err.Error(), "timeout") {
			writeJSON(w, http.StatusGatewayTimeout, map[string]string{"error": "task_timeout"})
		} else {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": err.Error()})
		}
		return
	}

	if result.Error != "" {
		writeAgentError(w, result.Error, hostname, *taskID)
		return
	}

	log.Printf("Upload complete: hostname=%s task_id=%s rc=%d", hostname, *taskID, result.RC)
	writeJSON(w, http.StatusOK, map[string]interface{}{"rc": result.RC})
}

// POST /api/fetch/{hostname} — Retrieve a file from a remote agent
func FetchFile(w http.ResponseWriter, r *http.Request) {
	// Plugin token authentication (SECURITY.md §6)
	if _, ok := requirePluginAuth(w, r); !ok {
		return
	}

	hostname := r.PathValue("hostname")

	// Parse and validate request first (400 before 503)
	var req FetchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json"})
		return
	}

	if err := validateFetchRequest(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	// Generate or use provided task ID
	taskID := req.TaskID
	if taskID == nil || *taskID == "" {
		taskID = pointerString(newTaskID())
	}

	// Proxy mode: check relay routing before local WS
	if proxyRouter != nil && !isLocalAgent(hostname) {
		// Anti-loop: read X-Relay-Hops, reject if budget exhausted, decrement for outgoing call
		proxyHops := proxy.DefaultMaxHops
		if hopStr := r.Header.Get(proxy.RelayHopsHeader); hopStr != "" {
			if n, convErr := strconv.Atoi(hopStr); convErr == nil {
				if n <= 0 {
					log.Printf("[PROXY] relay_loop_detected: hostname=%s hops=%d", hostname, n)
					writeJSON(w, http.StatusLoopDetected, map[string]string{"error": "relay_loop_detected"})
					return
				}
				proxyHops = n - 1
			}
		}
		proxyCtx := proxy.WithRelayHops(r.Context(), proxyHops)

		relayID, relayErr := proxyRouter.GetRelayForHostname(hostname)
		if relayErr == nil {
			log.Printf("Fetch request (proxy): hostname=%s relay_id=%s task_id=%s src=%s",
				hostname, relayID, *taskID, req.Src)
			proxyReq := proxy.FetchRequest{Src: req.Src}
			resp, pErr := proxyRouter.RouteFetch(proxyCtx, hostname, *taskID, proxyReq)
			if pErr != nil {
				writeProxyExecError(w, pErr, hostname, *taskID)
				return
			}
			writeJSON(w, http.StatusOK, map[string]interface{}{"rc": resp.RC, "data": resp.Data})
			return
		} else if !errors.Is(relayErr, proxy.ErrHostNotFound) {
			log.Printf("[PROXY] relay routing lookup error: hostname=%s err=%v", hostname, relayErr)
		}
	}

	// Verify agent is connected (after validation)
	if err := checkAgentOnline(hostname); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "agent_offline"})
		return
	}

	log.Printf("Fetch request: hostname=%s task_id=%s src=%s",
		hostname, *taskID, req.Src)

	// Build WebSocket message
	message := map[string]interface{}{
		"task_id": *taskID,
		"type":    "fetch_file",
		"src":     req.Src,
	}

	// Default timeout for file operations: 60s
	fileTimeout := 60
	result, err := sendTaskAndWait(hostname, *taskID, message, fileTimeout)
	if err != nil {
		if strings.Contains(err.Error(), "timeout") {
			writeJSON(w, http.StatusGatewayTimeout, map[string]string{"error": "task_timeout"})
		} else {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": err.Error()})
		}
		return
	}

	if result.Error != "" {
		writeAgentError(w, result.Error, hostname, *taskID)
		return
	}

	log.Printf("Fetch complete: hostname=%s task_id=%s rc=%d data_len=%d",
		hostname, *taskID, result.RC, len(result.Data))
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"rc":   result.RC,
		"data": result.Data,
	})
}

// writeProxyExecError writes the appropriate HTTP error for a proxy routing failure.
func writeProxyExecError(w http.ResponseWriter, err error, hostname, taskID string) {
	e := err.Error()
	log.Printf("Proxy exec error: hostname=%s task_id=%s err=%s", hostname, taskID, e)
	switch {
	case strings.Contains(e, "timeout"):
		writeJSON(w, http.StatusGatewayTimeout, map[string]string{"error": "task_timeout"})
	case strings.Contains(e, "relay_offline"), strings.Contains(e, "relay_disconnected"),
		strings.Contains(e, "dispatch_failed"):
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "relay_offline"})
	default:
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": e})
	}
}

// GET /api/async_status/{task_id} — Poll the status of an async task
func AsyncStatus(w http.ResponseWriter, r *http.Request) {
	taskID := r.PathValue("task_id")

	// Check completed cache first
	if result, exists := completedResults[taskID]; exists {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"task_id":   taskID,
			"status":    "finished",
			"rc":        result["rc"],
			"stdout":    result["stdout"],
			"stderr":    result["stderr"],
			"truncated": result["truncated"],
		})
		return
	}

	writeJSON(w, http.StatusNotFound, map[string]string{"error": "task_not_found"})
}

// StoreResult stores a completed task result for later retrieval via async_status
func StoreResult(taskID string, result map[string]interface{}) {
	completedResults[taskID] = map[string]interface{}{
		"rc":        result["rc"],
		"stdout":    result["stdout"],
		"stderr":    result["stderr"],
		"truncated": result["truncated"],
		"status":    "finished",
	}
}
