package handlers

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

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

func TestExecCommandSuccess(t *testing.T) {
	req := ExecRequest{
		Cmd:     "echo hello",
		Timeout: 30,
	}

	body, _ := json.Marshal(req)
	httpReq := newExecRequest("POST", "/api/exec/test-host", "test-host", bytes.NewReader(body))
	w := httptest.NewRecorder()

	ExecCommand(w, httpReq)

	if w.Code != http.StatusOK {
		t.Errorf("ExecCommand: expected 200, got %d", w.Code)
	}

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)

	if _, ok := resp["rc"]; !ok {
		t.Error("expected rc in response")
	}
}

func TestExecCommandEmptyCmd(t *testing.T) {
	req := ExecRequest{
		Cmd:     "",
		Timeout: 30,
	}

	body, _ := json.Marshal(req)
	httpReq := newExecRequest("POST", "/api/exec/test-host", "test-host", bytes.NewReader(body))
	w := httptest.NewRecorder()

	ExecCommand(w, httpReq)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestExecCommandInvalidJSON(t *testing.T) {
	httpReq := newExecRequest("POST", "/api/exec/test-host", "test-host",
		bytes.NewBufferString("invalid"))
	w := httptest.NewRecorder()

	ExecCommand(w, httpReq)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestExecCommandWithBecome(t *testing.T) {
	stdin := "password123"
	req := ExecRequest{
		Cmd:          "id",
		Timeout:      30,
		Become:       true,
		BecomeMethod: "sudo",
		Stdin:        &stdin,
	}

	body, _ := json.Marshal(req)
	httpReq := newExecRequest("POST", "/api/exec/test-host", "test-host", bytes.NewReader(body))
	w := httptest.NewRecorder()

	ExecCommand(w, httpReq)

	if w.Code != http.StatusOK {
		t.Errorf("ExecCommand: expected 200, got %d", w.Code)
	}
}

func TestExecCommandDefaultTimeout(t *testing.T) {
	req := ExecRequest{
		Cmd:     "sleep 1",
		Timeout: 0, // Will be set to default (30)
	}

	body, _ := json.Marshal(req)
	httpReq := newExecRequest("POST", "/api/exec/test-host", "test-host", bytes.NewReader(body))
	w := httptest.NewRecorder()

	ExecCommand(w, httpReq)

	if w.Code != http.StatusOK {
		t.Errorf("ExecCommand: expected 200, got %d", w.Code)
	}
}

func TestExecCommandOfflineAgent(t *testing.T) {
	req := ExecRequest{Cmd: "echo hi", Timeout: 30}
	body, _ := json.Marshal(req)
	// No path value set — hostname will be empty → agent_offline
	httpReq := httptest.NewRequest("POST", "/api/exec/", bytes.NewReader(body))
	w := httptest.NewRecorder()

	ExecCommand(w, httpReq)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", w.Code)
	}
}

// ========================================================================
// UploadFile
// ========================================================================

func TestUploadFileSuccess(t *testing.T) {
	fileData := "test file content"
	encodedData := base64.StdEncoding.EncodeToString([]byte(fileData))

	req := UploadRequest{
		Dest: "/tmp/test.txt",
		Data: encodedData,
		Mode: "0644",
	}

	body, _ := json.Marshal(req)
	httpReq := newExecRequest("POST", "/api/upload/test-host", "test-host", bytes.NewReader(body))
	w := httptest.NewRecorder()

	UploadFile(w, httpReq)

	if w.Code != http.StatusOK {
		t.Errorf("UploadFile: expected 200, got %d", w.Code)
	}
}

func TestUploadFileEmptyDest(t *testing.T) {
	req := UploadRequest{
		Dest: "",
		Data: base64.StdEncoding.EncodeToString([]byte("content")),
		Mode: "0644",
	}

	body, _ := json.Marshal(req)
	httpReq := newExecRequest("POST", "/api/upload/test-host", "test-host", bytes.NewReader(body))
	w := httptest.NewRecorder()

	UploadFile(w, httpReq)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestUploadFileEmptyData(t *testing.T) {
	req := UploadRequest{
		Dest: "/tmp/test.txt",
		Data: "",
		Mode: "0644",
	}

	body, _ := json.Marshal(req)
	httpReq := newExecRequest("POST", "/api/upload/test-host", "test-host", bytes.NewReader(body))
	w := httptest.NewRecorder()

	UploadFile(w, httpReq)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestUploadFileInvalidBase64(t *testing.T) {
	req := UploadRequest{
		Dest: "/tmp/test.txt",
		Data: "not-valid-base64!!!",
		Mode: "0644",
	}

	body, _ := json.Marshal(req)
	httpReq := newExecRequest("POST", "/api/upload/test-host", "test-host", bytes.NewReader(body))
	w := httptest.NewRecorder()

	UploadFile(w, httpReq)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestUploadFilePayloadTooLarge(t *testing.T) {
	// Create data larger than 500KB
	largeData := make([]byte, 600*1024) // 600KB
	encodedData := base64.StdEncoding.EncodeToString(largeData)

	req := UploadRequest{
		Dest: "/tmp/large.bin",
		Data: encodedData,
		Mode: "0644",
	}

	body, _ := json.Marshal(req)
	httpReq := newExecRequest("POST", "/api/upload/test-host", "test-host", bytes.NewReader(body))
	w := httptest.NewRecorder()

	UploadFile(w, httpReq)

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("expected 413, got %d", w.Code)
	}
}

func TestUploadFileDefaultMode(t *testing.T) {
	req := UploadRequest{
		Dest: "/tmp/test.txt",
		Data: base64.StdEncoding.EncodeToString([]byte("content")),
		Mode: "", // Will be set to default (0644)
	}

	body, _ := json.Marshal(req)
	httpReq := newExecRequest("POST", "/api/upload/test-host", "test-host", bytes.NewReader(body))
	w := httptest.NewRecorder()

	UploadFile(w, httpReq)

	if w.Code != http.StatusOK {
		t.Errorf("UploadFile: expected 200, got %d", w.Code)
	}
}

func TestUploadFileOfflineAgent(t *testing.T) {
	req := UploadRequest{
		Dest: "/tmp/test.txt",
		Data: base64.StdEncoding.EncodeToString([]byte("content")),
	}
	body, _ := json.Marshal(req)
	// No path value — hostname empty → agent_offline
	httpReq := httptest.NewRequest("POST", "/api/upload/", bytes.NewReader(body))
	w := httptest.NewRecorder()

	UploadFile(w, httpReq)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", w.Code)
	}
}

// ========================================================================
// FetchFile
// ========================================================================

func TestFetchFileSuccess(t *testing.T) {
	req := FetchRequest{
		Src: "/etc/hostname",
	}

	body, _ := json.Marshal(req)
	httpReq := newExecRequest("POST", "/api/fetch/test-host", "test-host", bytes.NewReader(body))
	w := httptest.NewRecorder()

	FetchFile(w, httpReq)

	if w.Code != http.StatusOK {
		t.Errorf("FetchFile: expected 200, got %d", w.Code)
	}

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)

	if _, ok := resp["data"]; !ok {
		t.Error("expected data in response")
	}
}

func TestFetchFileEmptySrc(t *testing.T) {
	req := FetchRequest{
		Src: "",
	}

	body, _ := json.Marshal(req)
	httpReq := newExecRequest("POST", "/api/fetch/test-host", "test-host", bytes.NewReader(body))
	w := httptest.NewRecorder()

	FetchFile(w, httpReq)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestFetchFileOfflineAgent(t *testing.T) {
	req := FetchRequest{Src: "/etc/hostname"}
	body, _ := json.Marshal(req)
	// No path value — hostname empty → agent_offline
	httpReq := httptest.NewRequest("POST", "/api/fetch/", bytes.NewReader(body))
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
