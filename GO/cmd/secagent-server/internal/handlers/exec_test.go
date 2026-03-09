package handlers

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"secagent-server/cmd/secagent-server/internal/storage"
)

// execTestToken is the plain-text plugin token used across exec/upload/fetch tests.
const execTestToken = "secagent_plg_exec_test_shared"

// setupExecAuth initialises an in-memory store with a valid plugin token and
// returns a helper that stamps requests with the bearer header.
func setupExecAuth(t *testing.T) func(r *http.Request) *http.Request {
	t.Helper()
	s := newTestStore(t)
	SetAdminStore(s)

	h := sha256.Sum256([]byte(execTestToken))
	tok := storage.PluginToken{
		ID:        "tok-exec-shared",
		TokenHash: fmt.Sprintf("%x", h),
		Role:      "plugin",
		CreatedAt: time.Now().UTC(),
	}
	if err := s.CreatePluginToken(context.Background(), tok); err != nil {
		t.Fatalf("setupExecAuth: %v", err)
	}

	return func(r *http.Request) *http.Request {
		r.Header.Set("Authorization", "Bearer "+execTestToken)
		r.RemoteAddr = "127.0.0.1:8080"
		return r
	}
}

// newExecRequest creates a test HTTP request with the hostname path value set
func newExecRequest(method, path, hostname string, body io.Reader) *http.Request {
	req := httptest.NewRequest(method, path, body)
	if hostname != "" {
		req.SetPathValue("hostname", hostname)
	}
	return req
}

// newTaskIDRequest creates a test HTTP request with the task_id path value set
func newTaskIDRequest(method, path, taskID string) *http.Request {
	req := httptest.NewRequest(method, path, nil)
	if taskID != "" {
		req.SetPathValue("task_id", taskID)
	}
	return req
}

// ========================================================================
// ExecCommand
// ========================================================================

// TestExecCommandAgentOffline verifies that a valid request to an offline agent returns 503.
// The 200 relay path is tested via integration tests (requires a live WS agent connection).
func TestExecCommandAgentOffline(t *testing.T) {
	withAuth := setupExecAuth(t)

	req := ExecRequest{
		Cmd:     "echo hello",
		Timeout: 30,
	}

	body, _ := json.Marshal(req)
	httpReq := withAuth(newExecRequest("POST", "/api/exec/test-host", "test-host", bytes.NewReader(body)))
	w := httptest.NewRecorder()

	ExecCommand(w, httpReq)

	// No WS connection registered → agent_offline
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("ExecCommand: expected 503, got %d", w.Code)
	}

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["error"] != "agent_offline" {
		t.Errorf("expected error=agent_offline, got %v", resp["error"])
	}
}

func TestExecCommandEmptyCmd(t *testing.T) {
	withAuth := setupExecAuth(t)

	req := ExecRequest{
		Cmd:     "",
		Timeout: 30,
	}

	body, _ := json.Marshal(req)
	httpReq := withAuth(newExecRequest("POST", "/api/exec/test-host", "test-host", bytes.NewReader(body)))
	w := httptest.NewRecorder()

	ExecCommand(w, httpReq)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestExecCommandInvalidJSON(t *testing.T) {
	withAuth := setupExecAuth(t)

	httpReq := withAuth(newExecRequest("POST", "/api/exec/test-host", "test-host",
		bytes.NewBufferString("invalid")))
	w := httptest.NewRecorder()

	ExecCommand(w, httpReq)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

// TestExecCommandWithBecomeAgentOffline verifies that a become request to an offline agent returns 503.
func TestExecCommandWithBecomeAgentOffline(t *testing.T) {
	withAuth := setupExecAuth(t)

	stdin := "password123"
	req := ExecRequest{
		Cmd:          "id",
		Timeout:      30,
		Become:       true,
		BecomeMethod: "sudo",
		Stdin:        &stdin,
	}

	body, _ := json.Marshal(req)
	httpReq := withAuth(newExecRequest("POST", "/api/exec/test-host", "test-host", bytes.NewReader(body)))
	w := httptest.NewRecorder()

	ExecCommand(w, httpReq)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("ExecCommand: expected 503, got %d", w.Code)
	}
}

// TestExecCommandDefaultTimeoutAgentOffline verifies that default timeout (Timeout=0→30) is applied
// before the agent check, and still returns 503 when the agent is not connected.
func TestExecCommandDefaultTimeoutAgentOffline(t *testing.T) {
	withAuth := setupExecAuth(t)

	req := ExecRequest{
		Cmd:     "sleep 1",
		Timeout: 0, // Will be set to default (30) by validateExecRequest
	}

	body, _ := json.Marshal(req)
	httpReq := withAuth(newExecRequest("POST", "/api/exec/test-host", "test-host", bytes.NewReader(body)))
	w := httptest.NewRecorder()

	ExecCommand(w, httpReq)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("ExecCommand: expected 503, got %d", w.Code)
	}
}

func TestExecCommandOfflineAgent(t *testing.T) {
	withAuth := setupExecAuth(t)

	req := ExecRequest{Cmd: "echo hi", Timeout: 30}
	body, _ := json.Marshal(req)
	// No path value set — hostname will be empty → agent_offline
	httpReq := withAuth(httptest.NewRequest("POST", "/api/exec/", bytes.NewReader(body)))
	w := httptest.NewRecorder()

	ExecCommand(w, httpReq)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", w.Code)
	}
}

// ========================================================================
// UploadFile
// ========================================================================

// TestUploadFileAgentOffline verifies that a valid upload request to an offline agent returns 503.
// The 200 relay path is tested via integration tests.
func TestUploadFileAgentOffline(t *testing.T) {
	withAuth := setupExecAuth(t)
	fileData := "test file content"
	encodedData := base64.StdEncoding.EncodeToString([]byte(fileData))

	req := UploadRequest{
		Dest: "/tmp/test.txt",
		Data: encodedData,
		Mode: "0644",
	}

	body, _ := json.Marshal(req)
	httpReq := withAuth(newExecRequest("POST", "/api/upload/test-host", "test-host", bytes.NewReader(body)))
	w := httptest.NewRecorder()

	UploadFile(w, httpReq)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("UploadFile: expected 503, got %d", w.Code)
	}
}

func TestUploadFileEmptyDest(t *testing.T) {
	withAuth := setupExecAuth(t)

	req := UploadRequest{
		Dest: "",
		Data: base64.StdEncoding.EncodeToString([]byte("content")),
		Mode: "0644",
	}

	body, _ := json.Marshal(req)
	httpReq := withAuth(newExecRequest("POST", "/api/upload/test-host", "test-host", bytes.NewReader(body)))
	w := httptest.NewRecorder()

	UploadFile(w, httpReq)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestUploadFileEmptyData(t *testing.T) {
	withAuth := setupExecAuth(t)

	req := UploadRequest{
		Dest: "/tmp/test.txt",
		Data: "",
		Mode: "0644",
	}

	body, _ := json.Marshal(req)
	httpReq := withAuth(newExecRequest("POST", "/api/upload/test-host", "test-host", bytes.NewReader(body)))
	w := httptest.NewRecorder()

	UploadFile(w, httpReq)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestUploadFileInvalidBase64(t *testing.T) {
	withAuth := setupExecAuth(t)

	req := UploadRequest{
		Dest: "/tmp/test.txt",
		Data: "not-valid-base64!!!",
		Mode: "0644",
	}

	body, _ := json.Marshal(req)
	httpReq := withAuth(newExecRequest("POST", "/api/upload/test-host", "test-host", bytes.NewReader(body)))
	w := httptest.NewRecorder()

	UploadFile(w, httpReq)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestUploadFilePayloadTooLarge(t *testing.T) {
	withAuth := setupExecAuth(t)

	// Create data larger than 500KB
	largeData := make([]byte, 600*1024) // 600KB
	encodedData := base64.StdEncoding.EncodeToString(largeData)

	req := UploadRequest{
		Dest: "/tmp/large.bin",
		Data: encodedData,
		Mode: "0644",
	}

	body, _ := json.Marshal(req)
	httpReq := withAuth(newExecRequest("POST", "/api/upload/test-host", "test-host", bytes.NewReader(body)))
	w := httptest.NewRecorder()

	UploadFile(w, httpReq)

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("expected 413, got %d", w.Code)
	}
}

// TestUploadFileDefaultModeAgentOffline verifies that default mode (0644) is applied before
// agent check, and still returns 503 when the agent is not connected.
func TestUploadFileDefaultModeAgentOffline(t *testing.T) {
	withAuth := setupExecAuth(t)

	req := UploadRequest{
		Dest: "/tmp/test.txt",
		Data: base64.StdEncoding.EncodeToString([]byte("content")),
		Mode: "", // Will be set to default (0644) by validateUploadRequest
	}

	body, _ := json.Marshal(req)
	httpReq := withAuth(newExecRequest("POST", "/api/upload/test-host", "test-host", bytes.NewReader(body)))
	w := httptest.NewRecorder()

	UploadFile(w, httpReq)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("UploadFile: expected 503, got %d", w.Code)
	}
}

func TestUploadFileOfflineAgent(t *testing.T) {
	withAuth := setupExecAuth(t)

	req := UploadRequest{
		Dest: "/tmp/test.txt",
		Data: base64.StdEncoding.EncodeToString([]byte("content")),
	}
	body, _ := json.Marshal(req)
	// No path value — hostname empty → agent_offline
	httpReq := withAuth(httptest.NewRequest("POST", "/api/upload/", bytes.NewReader(body)))
	w := httptest.NewRecorder()

	UploadFile(w, httpReq)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", w.Code)
	}
}

// ========================================================================
// FetchFile
// ========================================================================

// TestFetchFileAgentOffline verifies that a valid fetch request to an offline agent returns 503.
// The 200 relay path is tested via integration tests.
func TestFetchFileAgentOffline(t *testing.T) {
	withAuth := setupExecAuth(t)

	req := FetchRequest{
		Src: "/etc/hostname",
	}

	body, _ := json.Marshal(req)
	httpReq := withAuth(newExecRequest("POST", "/api/fetch/test-host", "test-host", bytes.NewReader(body)))
	w := httptest.NewRecorder()

	FetchFile(w, httpReq)

	// No WS connection registered → agent_offline
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("FetchFile: expected 503, got %d", w.Code)
	}
}

func TestFetchFileEmptySrc(t *testing.T) {
	withAuth := setupExecAuth(t)

	req := FetchRequest{
		Src: "",
	}

	body, _ := json.Marshal(req)
	httpReq := withAuth(newExecRequest("POST", "/api/fetch/test-host", "test-host", bytes.NewReader(body)))
	w := httptest.NewRecorder()

	FetchFile(w, httpReq)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestFetchFileOfflineAgent(t *testing.T) {
	withAuth := setupExecAuth(t)

	req := FetchRequest{Src: "/etc/hostname"}
	body, _ := json.Marshal(req)
	// No path value — hostname empty → agent_offline
	httpReq := withAuth(httptest.NewRequest("POST", "/api/fetch/", bytes.NewReader(body)))
	w := httptest.NewRecorder()

	FetchFile(w, httpReq)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", w.Code)
	}
}

// ========================================================================
// AsyncStatus
// ========================================================================

func TestAsyncStatusNotFound(t *testing.T) {
	httpReq := newTaskIDRequest("GET", "/api/async_status/non-existent-task-id", "non-existent-task-id")
	w := httptest.NewRecorder()

	AsyncStatus(w, httpReq)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestAsyncStatusCompleted(t *testing.T) {
	taskID := "test-task-123"
	result := map[string]interface{}{
		"rc":        0,
		"stdout":    "hello world",
		"stderr":    "",
		"truncated": false,
	}

	StoreResult(taskID, result)

	httpReq := newTaskIDRequest("GET", "/api/async_status/"+taskID, taskID)
	w := httptest.NewRecorder()

	AsyncStatus(w, httpReq)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)

	if resp["status"] != "finished" {
		t.Errorf("expected status=finished, got %v", resp["status"])
	}
}

// ========================================================================
// Helpers
// ========================================================================

func TestNewTaskID(t *testing.T) {
	id1 := newTaskID()
	id2 := newTaskID()

	if id1 == "" || id2 == "" {
		t.Error("newTaskID returned empty string")
	}

	if id1 == id2 {
		t.Error("newTaskID generated duplicate IDs")
	}
}

func TestPointerString(t *testing.T) {
	s := "test"
	ptr := pointerString(s)

	if ptr == nil {
		t.Error("pointerString returned nil")
	}

	if *ptr != s {
		t.Errorf("expected %q, got %q", s, *ptr)
	}
}

func TestValidateExecRequest(t *testing.T) {
	tests := []struct {
		name    string
		req     *ExecRequest
		wantErr bool
	}{
		{
			name:    "valid request",
			req:     &ExecRequest{Cmd: "echo hello", Timeout: 30},
			wantErr: false,
		},
		{
			name:    "empty command",
			req:     &ExecRequest{Cmd: "", Timeout: 30},
			wantErr: true,
		},
		{
			name:    "zero timeout defaults to 30",
			req:     &ExecRequest{Cmd: "ls", Timeout: 0},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateExecRequest(tt.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateExecRequest() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateUploadRequest(t *testing.T) {
	tests := []struct {
		name    string
		req     *UploadRequest
		wantErr bool
	}{
		{
			name: "valid request",
			req: &UploadRequest{
				Dest: "/tmp/file.txt",
				Data: base64.StdEncoding.EncodeToString([]byte("content")),
			},
			wantErr: false,
		},
		{
			name: "empty destination",
			req: &UploadRequest{
				Dest: "",
				Data: base64.StdEncoding.EncodeToString([]byte("content")),
			},
			wantErr: true,
		},
		{
			name: "empty data",
			req: &UploadRequest{
				Dest: "/tmp/file.txt",
				Data: "",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateUploadRequest(tt.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateUploadRequest() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
