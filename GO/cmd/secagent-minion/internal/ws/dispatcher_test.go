package ws

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"
)

// ========================================================================
// ReconnectManager
// ========================================================================

func TestReconnectManagerFirstDelay(t *testing.T) {
	r := NewReconnectManager(1.0, 60.0)
	delay := r.NextDelay()
	// First delay: 1.0 * 2^0 = 1s
	if delay != 1*time.Second {
		t.Errorf("first delay: got %s, want 1s", delay)
	}
}

func TestReconnectManagerExponentialBackoff(t *testing.T) {
	r := NewReconnectManager(1.0, 60.0)
	delays := []time.Duration{}
	for i := 0; i < 5; i++ {
		delays = append(delays, r.NextDelay())
	}
	// Delays: 1s, 2s, 4s, 8s, 16s
	expected := []time.Duration{
		1 * time.Second,
		2 * time.Second,
		4 * time.Second,
		8 * time.Second,
		16 * time.Second,
	}
	for i, d := range delays {
		if d != expected[i] {
			t.Errorf("delay[%d]: got %s, want %s", i, d, expected[i])
		}
	}
}

func TestReconnectManagerMaxDelay(t *testing.T) {
	r := NewReconnectManager(1.0, 4.0)
	// After enough attempts, should cap at maxDelay
	var maxSeen time.Duration
	for i := 0; i < 10; i++ {
		d := r.NextDelay()
		if d > maxSeen {
			maxSeen = d
		}
	}
	if maxSeen > 4*time.Second {
		t.Errorf("max delay exceeded: got %s, want <= 4s", maxSeen)
	}
}

func TestReconnectManagerReset(t *testing.T) {
	r := NewReconnectManager(1.0, 60.0)
	// Advance a few times
	r.NextDelay()
	r.NextDelay()
	r.NextDelay()

	r.Reset()
	// After reset, next delay should be back to base
	delay := r.NextDelay()
	if delay != 1*time.Second {
		t.Errorf("after Reset, delay: got %s, want 1s", delay)
	}
}

func TestReconnectManagerShouldReconnect(t *testing.T) {
	r := NewReconnectManager(1.0, 60.0)

	if !r.ShouldReconnect(1006) {
		t.Error("should reconnect for normal close codes")
	}
	if !r.ShouldReconnect(4000) {
		t.Error("should reconnect for code 4000")
	}
	if r.ShouldReconnect(CloseCodeRevoked) {
		t.Errorf("should NOT reconnect for code %d (revoked)", CloseCodeRevoked)
	}
}

func TestCloseCodeRevoked(t *testing.T) {
	if CloseCodeRevoked != 4001 {
		t.Errorf("CloseCodeRevoked: got %d, want 4001", CloseCodeRevoked)
	}
}

// ========================================================================
// NewDispatcher
// ========================================================================

func TestNewDispatcher(t *testing.T) {
	d := NewDispatcher(ConnConfig{}, nil)
	if d == nil {
		t.Error("NewDispatcher returned nil")
	}
	if d.tasks == nil {
		t.Error("tasks map is nil")
	}
}

// ========================================================================
// Dispatcher — task registration / cancellation
// ========================================================================

func TestRegisterAndUnregisterTask(t *testing.T) {
	d := NewDispatcher(ConnConfig{}, nil)

	called := false
	cancel := func() { called = true }

	d.registerTask("task-1", cancel)

	// Verify registered
	d.mu.Lock()
	_, exists := d.tasks["task-1"]
	d.mu.Unlock()
	if !exists {
		t.Error("task not registered")
	}

	d.unregisterTask("task-1")

	// Verify removed
	d.mu.Lock()
	_, exists = d.tasks["task-1"]
	d.mu.Unlock()
	if exists {
		t.Error("task still registered after unregister")
	}
	_ = called
}

func TestCancelTask(t *testing.T) {
	d := NewDispatcher(ConnConfig{}, nil)

	cancelled := make(chan struct{}, 1)
	ctx, cancel := context.WithCancel(context.Background())
	_ = ctx

	d.registerTask("task-cancel", func() {
		cancel()
		cancelled <- struct{}{}
	})

	d.cancelTask("task-cancel")

	select {
	case <-cancelled:
		// Expected
	case <-time.After(100 * time.Millisecond):
		t.Error("cancel function not called")
	}
}

func TestCancelUnknownTask(t *testing.T) {
	d := NewDispatcher(ConnConfig{}, nil)
	// Should not panic
	d.cancelTask("nonexistent-task")
}

// ========================================================================
// Message types — JSON marshaling
// ========================================================================

func TestBaseMsgJSON(t *testing.T) {
	msg := BaseMsg{TaskID: "t1", Type: "exec"}
	data, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded BaseMsg
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.TaskID != "t1" {
		t.Errorf("TaskID: got %q, want t1", decoded.TaskID)
	}
	if decoded.Type != "exec" {
		t.Errorf("Type: got %q, want exec", decoded.Type)
	}
}

func TestExecMsgJSON(t *testing.T) {
	msg := ExecMsg{
		BaseMsg:  BaseMsg{TaskID: "t1", Type: "exec"},
		Cmd:      "echo hello",
		Stdin:    "aGVsbG8=",
		Timeout:  30,
		Become:   true,
		ExpiresAt: 9999999999,
	}
	data, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded ExecMsg
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.Cmd != "echo hello" {
		t.Errorf("Cmd: got %q", decoded.Cmd)
	}
	if !decoded.Become {
		t.Error("Become not preserved")
	}
	if decoded.Timeout != 30 {
		t.Errorf("Timeout: got %d, want 30", decoded.Timeout)
	}
}

func TestPutFileMsgJSON(t *testing.T) {
	msg := PutFileMsg{
		BaseMsg: BaseMsg{TaskID: "t2", Type: "put_file"},
		Dest:    "/tmp/file.txt",
		Data:    "aGVsbG8=",
		Mode:    "0644",
	}
	data, _ := json.Marshal(msg)
	var decoded PutFileMsg
	json.Unmarshal(data, &decoded)
	if decoded.Dest != "/tmp/file.txt" {
		t.Errorf("Dest: got %q", decoded.Dest)
	}
	if decoded.Mode != "0644" {
		t.Errorf("Mode: got %q", decoded.Mode)
	}
}

func TestFetchFileMsgJSON(t *testing.T) {
	msg := FetchFileMsg{
		BaseMsg: BaseMsg{TaskID: "t3", Type: "fetch_file"},
		Src:     "/etc/hostname",
	}
	data, _ := json.Marshal(msg)
	var decoded FetchFileMsg
	json.Unmarshal(data, &decoded)
	if decoded.Src != "/etc/hostname" {
		t.Errorf("Src: got %q", decoded.Src)
	}
}

func TestCancelMsgJSON(t *testing.T) {
	msg := CancelMsg{BaseMsg: BaseMsg{TaskID: "t4", Type: "cancel"}}
	data, _ := json.Marshal(msg)
	var decoded CancelMsg
	json.Unmarshal(data, &decoded)
	if decoded.TaskID != "t4" {
		t.Errorf("TaskID: got %q", decoded.TaskID)
	}
}

// ========================================================================
// ConnConfig
// ========================================================================

func TestConnConfigFields(t *testing.T) {
	cfg := ConnConfig{
		ServerURL: "wss://relay.example.com/ws/agent",
		JWT:       "eyJhbGciOiJSUzI1NiJ9.test.sig",
		CABundle:  "/etc/ssl/certs/ca.pem",
	}
	if cfg.ServerURL != "wss://relay.example.com/ws/agent" {
		t.Error("ServerURL not preserved")
	}
	if cfg.JWT == "" {
		t.Error("JWT is empty")
	}
}

// ========================================================================
// buildTLSConfig
// ========================================================================

func TestBuildTLSConfigNoBundle(t *testing.T) {
	cfg, err := buildTLSConfig("", false)
	if err != nil {
		t.Fatalf("buildTLSConfig empty: %v", err)
	}
	if cfg == nil {
		t.Error("TLS config is nil")
	}
	if cfg.RootCAs != nil {
		t.Error("RootCAs should be nil when no bundle provided (use system store)")
	}
}

func TestBuildTLSConfigNonexistentBundle(t *testing.T) {
	_, err := buildTLSConfig("/nonexistent/ca.pem", false)
	if err == nil {
		t.Error("expected error for nonexistent CA bundle")
	}
}

func TestBuildTLSConfigInvalidPEM(t *testing.T) {
	dir := t.TempDir()
	caFile := dir + "/ca.pem"
	// Write invalid PEM
	os.WriteFile(caFile, []byte("not valid pem"), 0644)

	_, err := buildTLSConfig(caFile, false)
	if err == nil {
		t.Error("expected error for invalid CA PEM")
	}
}

// ========================================================================
// isClose helper
// ========================================================================

func TestIsCloseNonCloseError(t *testing.T) {
	err := context.DeadlineExceeded
	result := isClose(err, nil)
	if result {
		t.Error("isClose should return false for non-CloseError")
	}
}

// ========================================================================
// min helper
// ========================================================================

func TestMin(t *testing.T) {
	if min(3, 5) != 3 {
		t.Errorf("min(3,5): got %d, want 3", min(3, 5))
	}
	if min(5, 3) != 3 {
		t.Errorf("min(5,3): got %d, want 3", min(5, 3))
	}
	if min(4, 4) != 4 {
		t.Errorf("min(4,4): got %d, want 4", min(4, 4))
	}
}

// ========================================================================
// Constants
// ========================================================================

func TestConstants(t *testing.T) {
	if MaxConcurrentTasks != 10 {
		t.Errorf("MaxConcurrentTasks: got %d, want 10", MaxConcurrentTasks)
	}
	if StdoutBufferMax != 5*1024*1024 {
		t.Errorf("StdoutBufferMax: got %d, want %d", StdoutBufferMax, 5*1024*1024)
	}
}
