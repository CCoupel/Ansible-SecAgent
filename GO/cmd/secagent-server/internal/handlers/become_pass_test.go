// become_pass_test.go — Tests that become_pass (stdin when become=true) is never logged.
//
// SECURITY (CRITICAL): logExecSafe must redact stdin when become=true.
// A leaked become_pass would expose privilege-escalation credentials.
//
// Implementation note: logExecSafe logs stdin as a *string with %v, which emits
// the pointer address — the actual string value is never emitted.  When become=true,
// the pointer is replaced with one pointing to "***REDACTED***", so any future
// refactor that switches to %s or *stdinLog will still emit "***REDACTED***" rather
// than the real password.
package handlers

import (
	"bytes"
	"log"
	"os"
	"strings"
	"testing"
)

// TestLogExecSafe_BecomePassMasked verifies that the actual stdin value is NEVER
// present in the log when become=true.
// This is the primary SECURITY guard against become_pass leaking to logs.
func TestLogExecSafe_BecomePassMasked(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	secretPass := "become_pass_v3ry_s3cr3t"
	stdin := secretPass
	req := &ExecRequest{
		Cmd:    "whoami",
		Stdin:  &stdin,
		Become: true,
	}
	logExecSafe("test-host", "task-become-sec", req)

	logged := buf.String()
	// CRITICAL: the actual password must NEVER appear in any log line
	if strings.Contains(logged, secretPass) {
		t.Errorf("SECURITY: become_pass leaked in log output: %q", logged)
	}
}

// TestLogExecSafe_NoBecomeNoMask verifies that when become=false, the function
// proceeds normally (no suppression / no REDACTED substitution applied).
func TestLogExecSafe_NoBecomeNoMask(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	plainStdin := "plain_stdin_value"
	req := &ExecRequest{
		Cmd:    "echo hello",
		Stdin:  &plainStdin,
		Become: false,
	}
	logExecSafe("test-host", "task-nobec", req)

	logged := buf.String()
	// Log line must be present and must contain become=false marker
	if !strings.Contains(logged, "become=false") {
		t.Errorf("expected become=false in log, got: %q", logged)
	}
}

// TestLogExecSafe_NilStdin verifies that nil stdin is handled without panic.
func TestLogExecSafe_NilStdin(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	req := &ExecRequest{
		Cmd:    "ls",
		Stdin:  nil,
		Become: true,
	}
	// Must not panic
	logExecSafe("test-host", "task-nilstdin", req)
}
