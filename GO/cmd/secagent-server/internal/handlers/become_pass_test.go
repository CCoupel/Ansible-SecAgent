// become_pass_test.go — Regression tests for logExecSafe stdin masking.
//
// SECURITY (CRITICAL): become_pass (stdin when become=true) must NEVER appear
// in any log line.  These tests act as mutation guards: they FAIL if the masking
// is removed, bypassed, or the real value is logged in any form.
package handlers

import (
	"bytes"
	"log"
	"os"
	"strings"
	"testing"
)

// TestLogExecSafe_BecomePassMasked verifies two properties simultaneously:
//  1. The actual secret is ABSENT from the log (security invariant).
//  2. The "<redacted>" marker IS present (intentional masking, not accidental).
//
// Removing the masking code or logging the real value causes this test to FAIL.
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

	// Property 1 — SECURITY: actual secret must never appear
	if strings.Contains(logged, secretPass) {
		t.Errorf("SECURITY: become_pass leaked in log: %q", logged)
	}

	// Property 2 — MASKING: explicit marker must be present
	// This fails if someone removes the masking or changes it to %v on pointer.
	if !strings.Contains(logged, "<redacted>") {
		t.Errorf("expected explicit '<redacted>' marker in log when become=true, got: %q", logged)
	}

	// Property 3 — no pointer address must appear (no accidental %v on *string)
	if strings.Contains(logged, "0x") {
		t.Errorf("pointer address leaked in log (use explicit marker, not %%v on *string): %q", logged)
	}
}

// TestLogExecSafe_NoBecomeStdinSet verifies that a non-nil stdin with become=false
// logs "<set>" (not the actual value, not "<redacted>", not a pointer address).
func TestLogExecSafe_NoBecomeStdinSet(t *testing.T) {
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

	if !strings.Contains(logged, "stdin=<set>") {
		t.Errorf("expected 'stdin=<set>' in log for non-become with stdin, got: %q", logged)
	}
	if strings.Contains(logged, plainStdin) {
		t.Errorf("stdin value must not appear in log even when become=false, got: %q", logged)
	}
	if strings.Contains(logged, "0x") {
		t.Errorf("pointer address in log: %q", logged)
	}
}

// TestLogExecSafe_NilStdin verifies that nil stdin logs "stdin=none" without panic.
func TestLogExecSafe_NilStdin(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	req := &ExecRequest{
		Cmd:    "ls",
		Stdin:  nil,
		Become: true,
	}
	logExecSafe("test-host", "task-nilstdin", req)

	logged := buf.String()
	if !strings.Contains(logged, "stdin=none") {
		t.Errorf("expected 'stdin=none' for nil stdin, got: %q", logged)
	}
}

// TestLogExecSafe_MutationGuard_WouldFailIfMaskingRemoved demonstrates (without
// modifying the repo) that removing the masking would cause the test to fail.
// We do this by calling logExecSafe directly and checking the output; if someone
// inlined the secret with %s/*req.Stdin, this test catches it.
func TestLogExecSafe_MutationGuard_SecretNeverSet(t *testing.T) {
	// This test uses a unique sentinel that would appear verbatim if the
	// masking were bypassed (e.g. logged as *req.Stdin or fmt.Sprintf("%s", *stdinLog)).
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	sentinel := "MUTATION_GUARD_SECRET_XYZ789"
	req := &ExecRequest{
		Cmd:    "id",
		Stdin:  &sentinel,
		Become: true,
	}
	logExecSafe("host-mut", "task-mut", req)

	logged := buf.String()
	if strings.Contains(logged, sentinel) {
		t.Errorf("MUTATION GUARD TRIGGERED: secret appeared in log — masking is broken: %q", logged)
	}
	if !strings.Contains(logged, "<redacted>") {
		t.Errorf("MUTATION GUARD: '<redacted>' marker absent — masking was removed: %q", logged)
	}
}
