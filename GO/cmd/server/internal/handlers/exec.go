package handlers

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
)

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
	TaskID *string `json:"task_id"`  // Optional: caller-supplied task ID
	Dest   string  `json:"dest"`     // Destination path
	Data   string  `json:"data"`     // base64-encoded file content
	Mode   string  `json:"mode"`     // File mode (default "0644")
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
	timeoutMarginSec = 5           // Extra seconds on top of task timeout
)

// In-memory storage for completed task results (task_id -> result)
// In production, this would be in Redis or persistent storage
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
	if req.Timeout <= 0 {
		return fmt.Errorf("timeout must be positive")
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

// checkAgentOnline verifies that an agent has an active WebSocket connection
// Returns HTTP 503 if agent is offline
func checkAgentOnline(hostname string) error {
	// TODO: Check ws_connections map (from ws/handler.go)
	// For now, assume agent is online (will be integrated with WebSocket handler)
	if hostname == "" {
		return fmt.Errorf("hostname must not be empty")
	}
	return nil
}

// decodeResult interprets a result dict from an agent
// Handles error cases: agent_disconnected, agent_busy (rc=-1)
func decodeResult(result map[string]interface{}, hostname string, taskID string) (map[string]interface{}, error) {
	errStr, hasErr := result["error"].(string)
	if hasErr && errStr == "agent_disconnected" {
		log.Printf("Agent disconnected during task: hostname=%s task_id=%s", hostname, taskID)
		return nil, fmt.Errorf("agent_disconnected")
	}

	if rc, ok := result["rc"].(float64); ok && rc == -1 {
		runningTasks, _ := result["running_tasks"]
		log.Printf("Agent busy: hostname=%s task_id=%s running_tasks=%v", hostname, taskID, runningTasks)
		return nil, fmt.Errorf("agent_busy")
	}

	return result, nil
}

// logExecSafe logs exec request, masking stdin if become=True
func logExecSafe(hostname string, taskID string, req *ExecRequest) {
	stdinLog := req.Stdin
	if req.Become && req.Stdin != nil {
		stdinLog = pointerString("***REDACTED***")
	}
	log.Printf("Exec request: hostname=%s task_id=%s cmd=%s become=%v stdin=%v timeout=%d",
		hostname, taskID, req.Cmd, req.Become, stdinLog, req.Timeout)
}

// pointerString returns a pointer to a string
func pointerString(s string) *string {
	return &s
}

// POST /api/exec/{hostname} — Execute a command on a remote agent
func ExecCommand(w http.ResponseWriter, r *http.Request) {
	hostname := r.PathValue("hostname")

	// Verify agent is connected
	if err := checkAgentOnline(hostname); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": "agent_offline",
		})
		return
	}

	// Parse request
	var req ExecRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": "invalid_json",
		})
		return
	}

	// Validate request
	if err := validateExecRequest(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": err.Error(),
		})
		return
	}

	// Generate or use provided task ID
	taskID := req.TaskID
	if taskID == nil || *taskID == "" {
		taskID = pointerString(newTaskID())
	}

	now := nowTS()
	logExecSafe(hostname, *taskID, &req)

	// TODO: Register Future for task result (from ws/handler.go)
	// registerFuture(*taskID, hostname)

	// Construct message to send to agent via WebSocket
	message := map[string]interface{}{
		"task_id":        *taskID,
		"type":           "exec",
		"cmd":            req.Cmd,
		"stdin":          req.Stdin,
		"timeout":        req.Timeout,
		"become":         req.Become,
		"become_method":  req.BecomeMethod,
		"expires_at":     now + int64(req.Timeout),
	}

	// TODO: Publish to NATS (from broker/nats.go) or direct WebSocket send
	// For now, simulate successful send
	_ = message

	// TODO: Wait for result via asyncio.wait_for or channel receive
	// For now, return mock response
	result := map[string]interface{}{
		"rc":        0,
		"stdout":    "",
		"stderr":    "",
		"truncated": false,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"rc":        result["rc"],
		"stdout":    result["stdout"],
		"stderr":    result["stderr"],
		"truncated": result["truncated"],
	})
}

// POST /api/upload/{hostname} — Transfer a file to a remote agent
func UploadFile(w http.ResponseWriter, r *http.Request) {
	hostname := r.PathValue("hostname")

	// Verify agent is connected
	if err := checkAgentOnline(hostname); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": "agent_offline",
		})
		return
	}

	// Parse request
	var req UploadRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": "invalid_json",
		})
		return
	}

	// Validate request
	if err := validateUploadRequest(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": err.Error(),
		})
		return
	}

	// Validate decoded size before sending
	decoded, err := base64.StdEncoding.DecodeString(req.Data)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": "invalid_base64",
		})
		return
	}

	if len(decoded) > fileMaxBytes {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		json.NewEncoder(w).Encode(map[string]interface{}{
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

	log.Printf("Upload request: hostname=%s task_id=%s dest=%s size=%d",
		hostname, *taskID, req.Dest, len(decoded))

	// TODO: Register Future for task result
	// registerFuture(*taskID, hostname)

	// Construct message to send to agent
	message := map[string]interface{}{
		"task_id":    *taskID,
		"type":       "put_file",
		"dest":       req.Dest,
		"data":       req.Data,
		"mode":       req.Mode,
	}

	// TODO: Publish to NATS or direct WebSocket send
	_ = message

	// TODO: Wait for result
	result := map[string]interface{}{
		"rc": 0,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"rc": result["rc"],
	})
}

// POST /api/fetch/{hostname} — Retrieve a file from a remote agent
func FetchFile(w http.ResponseWriter, r *http.Request) {
	hostname := r.PathValue("hostname")

	// Verify agent is connected
	if err := checkAgentOnline(hostname); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": "agent_offline",
		})
		return
	}

	// Parse request
	var req FetchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": "invalid_json",
		})
		return
	}

	// Validate request
	if err := validateFetchRequest(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": err.Error(),
		})
		return
	}

	// Generate or use provided task ID
	taskID := req.TaskID
	if taskID == nil || *taskID == "" {
		taskID = pointerString(newTaskID())
	}

	log.Printf("Fetch request: hostname=%s task_id=%s src=%s",
		hostname, *taskID, req.Src)

	// TODO: Register Future for task result
	// registerFuture(*taskID, hostname)

	// Construct message to send to agent
	message := map[string]interface{}{
		"task_id": *taskID,
		"type":    "fetch_file",
		"src":     req.Src,
	}

	// TODO: Publish to NATS or direct WebSocket send
	_ = message

	// TODO: Wait for result
	result := map[string]interface{}{
		"rc":   0,
		"data": "",
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"rc":   result["rc"],
		"data": result["data"],
	})
}

// GET /api/async_status/{task_id} — Poll the status of an async task
func AsyncStatus(w http.ResponseWriter, r *http.Request) {
	taskID := r.PathValue("task_id")

	// Check completed cache first
	if result, exists := completedResults[taskID]; exists {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"task_id":   taskID,
			"status":    "finished",
			"rc":        result["rc"],
			"stdout":    result["stdout"],
			"stderr":    result["stderr"],
			"truncated": result["truncated"],
		})
		return
	}

	// TODO: Check if task is still in pending_futures (from ws/handler.go)
	// For now, return 404 if not in completed cache
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotFound)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"error": "task_not_found",
	})
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
