package executor

import (
	"context"
	"encoding/base64"
	"runtime"
	"strings"
	"testing"
	"time"
)

// skipIfWindows skips tests that rely on /bin/sh which is not available on Windows.
func skipIfWindows(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("skipping: /bin/sh not available on Windows")
	}
}

// ========================================================================
// New / Executor construction
// ========================================================================

func TestNew(t *testing.T) {
	e := New()
	if e == nil {
		t.Error("New() returned nil")
	}
}

// ========================================================================
// Run — nominal
// ========================================================================

func TestRunEchoHello(t *testing.T) {
	skipIfWindows(t)
	e := New()
	res := e.Run(context.Background(), ExecRequest{
		TaskID:  "task-1",
		Cmd:     "echo hello",
		Timeout: 5,
	})
	if res.RC != 0 {
		t.Errorf("rc: got %d, want 0", res.RC)
	}
	if !strings.Contains(res.Stdout, "hello") {
		t.Errorf("stdout: got %q, want 'hello'", res.Stdout)
	}
	if res.Truncated {
		t.Error("truncated should be false")
	}
}

func TestRunExitCode(t *testing.T) {
	skipIfWindows(t)
	e := New()
	res := e.Run(context.Background(), ExecRequest{
		TaskID:  "task-exit",
		Cmd:     "exit 42",
		Timeout: 5,
	})
	if res.RC != 42 {
		t.Errorf("rc: got %d, want 42", res.RC)
	}
}

func TestRunStderrCapture(t *testing.T) {
	skipIfWindows(t)
	e := New()
	res := e.Run(context.Background(), ExecRequest{
		TaskID:  "task-stderr",
		Cmd:     "echo errormsg >&2",
		Timeout: 5,
	})
	if !strings.Contains(res.Stderr, "errormsg") {
		t.Errorf("stderr: got %q, want 'errormsg'", res.Stderr)
	}
}

func TestRunDefaultTimeout(t *testing.T) {
	skipIfWindows(t)
	e := New()
	// Timeout=0 → DefaultTimeout (30s), command finishes quickly
	res := e.Run(context.Background(), ExecRequest{
		TaskID:  "task-default-timeout",
		Cmd:     "echo ok",
		Timeout: 0,
	})
	if res.RC != 0 {
		t.Errorf("rc: got %d, want 0", res.RC)
	}
}

// ========================================================================
// Run — expiration
// ========================================================================

func TestRunExpiredTask(t *testing.T) {
	e := New()
	res := e.Run(context.Background(), ExecRequest{
		TaskID:    "task-expired",
		Cmd:       "echo hello",
		Timeout:   5,
		ExpiresAt: time.Now().Unix() - 1, // already expired
	})
	if res.RC != -1 {
		t.Errorf("rc: got %d, want -1", res.RC)
	}
	if res.Stderr != "task expired" {
		t.Errorf("stderr: got %q, want 'task expired'", res.Stderr)
	}
}

func TestRunNotExpiredTask(t *testing.T) {
	skipIfWindows(t)
	e := New()
	res := e.Run(context.Background(), ExecRequest{
		TaskID:    "task-not-expired",
		Cmd:       "echo hello",
		Timeout:   5,
		ExpiresAt: time.Now().Unix() + 3600, // far in the future
	})
	if res.RC != 0 {
		t.Errorf("rc: got %d, want 0", res.RC)
	}
}

func TestRunZeroExpiresAtMeansNoExpiry(t *testing.T) {
	skipIfWindows(t)
	e := New()
	res := e.Run(context.Background(), ExecRequest{
		TaskID:    "task-no-expiry",
		Cmd:       "echo ok",
		Timeout:   5,
		ExpiresAt: 0, // disabled
	})
	if res.RC != 0 {
		t.Errorf("rc: got %d, want 0", res.RC)
	}
}

// ========================================================================
// Run — timeout
// ========================================================================

func TestRunTimeout(t *testing.T) {
	skipIfWindows(t)
	e := New()
	start := time.Now()
	res := e.Run(context.Background(), ExecRequest{
		TaskID:  "task-timeout",
		Cmd:     "sleep 60",
		Timeout: 1,
	})
	elapsed := time.Since(start)
	if res.RC != -15 {
		t.Errorf("rc: got %d, want -15", res.RC)
	}
	if elapsed > 5*time.Second {
		t.Errorf("timeout took too long: %s", elapsed)
	}
}

// ========================================================================
// Run — context cancellation
// ========================================================================

func TestRunContextCancelled(t *testing.T) {
	skipIfWindows(t)
	e := New()
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()
	res := e.Run(ctx, ExecRequest{
		TaskID:  "task-cancel",
		Cmd:     "sleep 60",
		Timeout: 30,
	})
	if res.RC != -15 {
		t.Errorf("rc: got %d, want -15 on cancel", res.RC)
	}
}

// ========================================================================
// Run — stdin (become masking)
// ========================================================================

func TestRunWithStdinBase64(t *testing.T) {
	skipIfWindows(t)
	e := New()
	stdinData := "hello from stdin"
	stdinB64 := base64.StdEncoding.EncodeToString([]byte(stdinData))
	res := e.Run(context.Background(), ExecRequest{
		TaskID:   "task-stdin",
		Cmd:      "cat",
		StdinB64: stdinB64,
		Timeout:  5,
	})
	if res.RC != 0 {
		t.Errorf("rc: got %d, want 0", res.RC)
	}
	if !strings.Contains(res.Stdout, stdinData) {
		t.Errorf("stdout: got %q, want stdin content", res.Stdout)
	}
}

func TestRunWithBecomeFlag(t *testing.T) {
	skipIfWindows(t)
	e := New()
	// become=true triggers log masking but doesn't change execution
	res := e.Run(context.Background(), ExecRequest{
		TaskID:   "task-become",
		Cmd:      "echo become-test",
		StdinB64: base64.StdEncoding.EncodeToString([]byte("password")),
		Become:   true,
		Timeout:  5,
	})
	if res.RC != 0 {
		t.Errorf("rc: got %d, want 0", res.RC)
	}
}

func TestRunInvalidBase64Stdin(t *testing.T) {
	skipIfWindows(t)
	e := New()
	// Invalid base64 → stdin is nil, command still runs
	res := e.Run(context.Background(), ExecRequest{
		TaskID:   "task-bad-stdin",
		Cmd:      "echo ok",
		StdinB64: "not-valid-base64!!!",
		Timeout:  5,
	})
	// Command should still run (stdin just not provided)
	if res.RC != 0 {
		t.Errorf("rc: got %d, want 0", res.RC)
	}
}

// ========================================================================
// Run — stdout truncation (5 MB)
// ========================================================================

func TestRunStdoutTruncation(t *testing.T) {
	skipIfWindows(t)
	e := New()
	// Generate > 5MB of output
	// yes outputs 'y\n' indefinitely — we limit via head -c 6MB (6291456 bytes)
	res := e.Run(context.Background(), ExecRequest{
		TaskID:  "task-truncate",
		Cmd:     "yes | head -c 6291456",
		Timeout: 30,
	})
	if !res.Truncated {
		t.Error("expected truncated=true for >5MB stdout")
	}
	if len([]byte(res.Stdout)) > StdoutBufferMax {
		t.Errorf("stdout exceeds max: got %d bytes", len([]byte(res.Stdout)))
	}
}

// ========================================================================
// Run — command start failure
// ========================================================================

func TestRunCommandNotFound(t *testing.T) {
	skipIfWindows(t)
	e := New()
	// /bin/sh -c "nonexistentcmd" → exit 127 (not found)
	res := e.Run(context.Background(), ExecRequest{
		TaskID:  "task-notfound",
		Cmd:     "nonexistentcommandthatdoesnotexist12345",
		Timeout: 5,
	})
	// Shell returns 127 for command not found
	if res.RC == 0 {
		t.Error("expected non-zero rc for command not found")
	}
}

// ========================================================================
// limitedBuffer
// ========================================================================

func TestLimitedBufferWrite(t *testing.T) {
	var buf limitedBuffer
	data := []byte("hello world")
	n, err := buf.Write(data)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if n != len(data) {
		t.Errorf("n: got %d, want %d", n, len(data))
	}
	if string(buf.Bytes()) != "hello world" {
		t.Errorf("bytes: got %q, want %q", buf.Bytes(), "hello world")
	}
}

func TestLimitedBufferStopsAtLimit(t *testing.T) {
	var buf limitedBuffer
	// Write StdoutBufferMax+2048 bytes
	large := make([]byte, StdoutBufferMax+2048)
	for i := range large {
		large[i] = 'x'
	}
	buf.Write(large)
	// Buffer accepts up to StdoutBufferMax+1024 bytes
	if len(buf.Bytes()) > StdoutBufferMax+1024 {
		t.Errorf("buffer too large: %d bytes", len(buf.Bytes()))
	}
}

// ========================================================================
// bytesReader
// ========================================================================

func TestBytesReaderRead(t *testing.T) {
	data := []byte("test data")
	r := newBytesReader(data)
	buf := make([]byte, len(data))
	n, err := r.Read(buf)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if n != len(data) {
		t.Errorf("n: got %d, want %d", n, len(data))
	}
	if string(buf) != "test data" {
		t.Errorf("data: got %q, want %q", buf, "test data")
	}
}

func TestBytesReaderEOF(t *testing.T) {
	r := newBytesReader([]byte("a"))
	buf := make([]byte, 10)
	r.Read(buf) // consume all
	n, err := r.Read(buf)
	if n != 0 {
		t.Errorf("expected n=0 at EOF, got %d", n)
	}
	if err == nil {
		t.Error("expected EOF error")
	}
}

// ========================================================================
// ExecRequest / ExecResult structs
// ========================================================================

func TestExecRequestFields(t *testing.T) {
	req := ExecRequest{
		TaskID:    "t1",
		Cmd:       "ls",
		StdinB64:  "aGVsbG8=",
		Timeout:   30,
		Become:    true,
		ExpiresAt: 9999999999,
	}
	if req.TaskID != "t1" {
		t.Error("TaskID not preserved")
	}
	if req.Cmd != "ls" {
		t.Error("Cmd not preserved")
	}
	if req.Timeout != 30 {
		t.Error("Timeout not preserved")
	}
	if !req.Become {
		t.Error("Become not preserved")
	}
}

func TestExecResultFields(t *testing.T) {
	res := ExecResult{
		TaskID:    "t1",
		RC:        0,
		Stdout:    "output",
		Stderr:    "",
		Truncated: false,
	}
	if res.TaskID != "t1" {
		t.Error("TaskID not preserved")
	}
	if res.RC != 0 {
		t.Error("RC not preserved")
	}
	if res.Stdout != "output" {
		t.Error("Stdout not preserved")
	}
}

// ========================================================================
// Constants
// ========================================================================

func TestConstants(t *testing.T) {
	if StdoutBufferMax != 5*1024*1024 {
		t.Errorf("StdoutBufferMax: got %d, want %d", StdoutBufferMax, 5*1024*1024)
	}
	if DefaultTimeout != 30*time.Second {
		t.Errorf("DefaultTimeout: got %s, want 30s", DefaultTimeout)
	}
}
