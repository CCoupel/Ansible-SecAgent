package handlers

import (
	"context"
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

// ErrAgentSuspended / ErrAgentStateUnavailable are the 503 error codes of a refused task (#173).
const (
	ErrAgentSuspended        = "agent_suspended"
	ErrAgentStateUnavailable = "agent_state_unavailable"
)

// refuseIfSuspended answers 503 and returns true when the agent must not receive a task: it is
// suspended (admin action, #173) or its state cannot be read (fail closed: an unreadable flag is
// never treated as "not suspended"). It runs BEFORE anything is sent to the agent. The WebSocket of
// a suspended agent stays open (only execution is refused, lifting the suspension is immediate).
func refuseIfSuspended(w http.ResponseWriter, hostname, taskID, op string) bool {
	suspended, err := AgentSuspended(hostname)
	switch {
	case err != nil:
		log.Printf("[SECURITY WARNING] %s refused: suspension state of %q unavailable: %v task_id=%q", op, hostname, err, taskID)
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": ErrAgentStateUnavailable})
		return true
	case suspended:
		log.Printf("[SECURITY WARNING] %s refused: agent %q is suspended task_id=%q", op, hostname, taskID)
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": ErrAgentSuspended})
		return true
	}
	return false
}

// AgentSuspended reports whether hostname is suspended on THIS node (the relay that holds the
// agent decides; a parent relays the refusal). Without a store the answer is an error: refusing
// is the only safe reading.
func AgentSuspended(hostname string) (bool, error) {
	if adminStore == nil {
		return false, fmt.Errorf("store_not_initialized")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return adminStore.IsAgentSuspended(ctx, hostname)
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
	log.Printf("Exec request: hostname=%q task_id=%q cmd=%s become=%v stdin=%s timeout=%d",
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
	resultChan, admitErr := ws.RegisterFuture(taskID, hostname)
	if admitErr != nil {
		return ws.Message{}, admitErr // typed: ErrAgentBusy / ErrTooManyTasks / ErrMemoryBudget (nothing was sent)
	}

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
		log.Printf("Agent disconnected during task: hostname=%q task_id=%q", hostname, taskID)
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "agent_disconnected"})
	case "agent_busy", "too_many_tasks", "memory_budget_exhausted":
		// the agent, or a relay below, refused the task (#179): same answer as an admission refusal here
		log.Printf("Task refused downstream: hostname=%q task_id=%q reason=%s", hostname, taskID, errStr)
		writeAdmissionCode(w, errStr)
	default:
		log.Printf("Agent error: hostname=%q task_id=%q error=%q", hostname, taskID, errStr)
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
					log.Printf("[PROXY] relay_loop_detected: hostname=%q hops=%d", hostname, n)
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
			log.Printf("Proxy exec complete: hostname=%q relay_id=%q task_id=%q rc=%d",
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
			log.Printf("[PROXY] relay routing lookup error: hostname=%q err=%v", hostname, relayErr)
		}
		// ErrHostNotFound → fall through to local agent lookup below
	}

	// Verify agent is connected via live WS registry
	if refuseIfSuspended(w, hostname, *taskID, "exec") {
		return
	}
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
		if writeAdmissionError(w, err) {
			return
		}
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

	log.Printf("Exec complete: hostname=%q task_id=%q rc=%d", hostname, *taskID, result.RC)
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
					log.Printf("[PROXY] relay_loop_detected: hostname=%q hops=%d", hostname, n)
					writeJSON(w, http.StatusLoopDetected, map[string]string{"error": "relay_loop_detected"})
					return
				}
				proxyHops = n - 1
			}
		}
		proxyCtx := proxy.WithRelayHops(r.Context(), proxyHops)

		relayID, relayErr := proxyRouter.GetRelayForHostname(hostname)
		if relayErr == nil {
			log.Printf("Upload request (proxy): hostname=%q relay_id=%q task_id=%q dest=%q size=%d",
				hostname, relayID, *taskID, req.Dest, len(decoded))
			proxyReq := proxy.UploadRequest{Dest: req.Dest, Data: req.Data, Mode: req.Mode}
			if pErr := proxyRouter.RouteUpload(proxyCtx, hostname, *taskID, proxyReq); pErr != nil {
				writeProxyExecError(w, pErr, hostname, *taskID)
				return
			}
			writeJSON(w, http.StatusOK, map[string]interface{}{"rc": 0})
			return
		} else if !errors.Is(relayErr, proxy.ErrHostNotFound) {
			log.Printf("[PROXY] relay routing lookup error: hostname=%q err=%v", hostname, relayErr)
		}
	}

	// Verify agent is connected (after validation)
	if refuseIfSuspended(w, hostname, *taskID, "upload") {
		return
	}
	if err := checkAgentOnline(hostname); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "agent_offline"})
		return
	}

	log.Printf("Upload request: hostname=%q task_id=%q dest=%q size=%d",
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
		if writeAdmissionError(w, err) {
			return
		}
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

	log.Printf("Upload complete: hostname=%q task_id=%q rc=%d", hostname, *taskID, result.RC)
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
					log.Printf("[PROXY] relay_loop_detected: hostname=%q hops=%d", hostname, n)
					writeJSON(w, http.StatusLoopDetected, map[string]string{"error": "relay_loop_detected"})
					return
				}
				proxyHops = n - 1
			}
		}
		proxyCtx := proxy.WithRelayHops(r.Context(), proxyHops)

		relayID, relayErr := proxyRouter.GetRelayForHostname(hostname)
		if relayErr == nil {
			log.Printf("Fetch request (proxy): hostname=%q relay_id=%q task_id=%q src=%q",
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
			log.Printf("[PROXY] relay routing lookup error: hostname=%q err=%v", hostname, relayErr)
		}
	}

	// Verify agent is connected (after validation)
	if refuseIfSuspended(w, hostname, *taskID, "fetch") {
		return
	}
	if err := checkAgentOnline(hostname); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "agent_offline"})
		return
	}

	log.Printf("Fetch request: hostname=%q task_id=%q src=%q",
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
		if writeAdmissionError(w, err) {
			return
		}
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

	log.Printf("Fetch complete: hostname=%q task_id=%q rc=%d data_len=%d",
		hostname, *taskID, result.RC, len(result.Data))
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"rc":   result.RC,
		"data": result.Data,
	})
}

// writeProxyExecError writes the appropriate HTTP error for a proxy routing failure.
func writeProxyExecError(w http.ResponseWriter, err error, hostname, taskID string) {
	e := err.Error()
	log.Printf("Proxy exec error: hostname=%q task_id=%q err=%q", hostname, taskID, e)
	switch {
	case strings.Contains(e, "too_many_tasks"):
		writeAdmissionCode(w, "too_many_tasks")
	case strings.Contains(e, "memory_budget_exhausted"):
		writeAdmissionCode(w, "memory_budget_exhausted")
	case strings.Contains(e, "agent_busy"):
		writeAdmissionCode(w, "agent_busy")
	case strings.Contains(e, "timeout"):
		writeJSON(w, http.StatusGatewayTimeout, map[string]string{"error": "task_timeout"})
	case strings.Contains(e, ErrAgentSuspended):
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": ErrAgentSuspended})
	case strings.Contains(e, ErrAgentStateUnavailable):
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": ErrAgentStateUnavailable})
	case strings.Contains(e, "relay_offline"), strings.Contains(e, "relay_disconnected"),
		strings.Contains(e, "dispatch_failed"):
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "relay_offline"})
	default:
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": e})
	}
}

// writeAdmissionCode answers a task refused for load (#179): 429 agent_busy / too_many_tasks, 503
// memory_budget_exhausted, each with a Retry-After in seconds. Nothing was sent to the agent.
func writeAdmissionCode(w http.ResponseWriter, code string) {
	status, retry := http.StatusTooManyRequests, ws.RetryAfterSeconds(ws.ErrAgentBusy)
	switch code {
	case "too_many_tasks":
		retry = ws.RetryAfterSeconds(ws.ErrTooManyTasks)
	case "memory_budget_exhausted":
		status, retry = http.StatusServiceUnavailable, ws.RetryAfterSeconds(ws.ErrMemoryBudget)
	}
	w.Header().Set("Retry-After", strconv.Itoa(retry))
	writeJSON(w, status, map[string]string{"error": code})
}

// writeAdmissionError writes the answer of an admission refusal; false when err is not one.
func writeAdmissionError(w http.ResponseWriter, err error) bool {
	if !ws.IsAdmissionError(err) {
		return false
	}
	writeAdmissionCode(w, err.Error())
	return true
}
