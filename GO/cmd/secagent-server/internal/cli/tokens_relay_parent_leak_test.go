package cli

import (
	"bytes"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
)

// The relay-parent JWT is a secret shown ONCE by `tokens create` (stdout). These tests run the
// real CLI in a child process (so stdout, stderr, log and slog output are the real, separate
// streams and os.Exit paths are exercised) and prove the JWT never appears anywhere else:
// not in `create` stderr / logs / errors, not in `list`, not in `revoke`.

const (
	leakJWTHeader  = "eyJhbGciOiJFZERTQSJ9"
	leakJWTPayload = "eyJyb2xlIjoicmVsYXktcGFyZW50Iiwic3ViIjoiY2VudHJhbCJ9"
	leakJWTSig     = "U0VDUkVULVNJR05BVFVSRS1BQkNERUZHSElKSw"
	leakJWT        = leakJWTHeader + "." + leakJWTPayload + "." + leakJWTSig
)

func jwtNeedles() []string {
	return []string{leakJWT, leakJWTHeader, leakJWTPayload[:20], leakJWTPayload[20:], leakJWTSig[:16], leakJWTSig[16:]}
}

func assertNoJWT(t *testing.T, stream, content string) {
	t.Helper()
	for _, n := range jwtNeedles() {
		if strings.Contains(content, n) {
			t.Errorf("JWT (fragment %q) leaked on %s:\n%s", n, stream, content)
		}
	}
}

// TestCLIHelperProcess is the child side: it runs the CLI with the args given in the environment.
func TestCLIHelperProcess(t *testing.T) {
	if os.Getenv("CLI_HELPER_PROCESS") != "1" {
		t.Skip("helper process only")
	}
	rootCmd.SetArgs(strings.Split(os.Getenv("CLI_HELPER_ARGS"), "\x1f"))
	Execute()
	os.Exit(0)
}

// runCLI runs `secagent-server <args>` in a child process against the mock API (mockServer).
func runCLI(t *testing.T, args ...string) (stdout, stderr string, exit int) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestCLIHelperProcess$")
	cmd.Env = append(os.Environ(), "CLI_HELPER_PROCESS=1", "CLI_HELPER_ARGS="+strings.Join(args, "\x1f"))
	var so, se bytes.Buffer
	cmd.Stdout, cmd.Stderr = &so, &se
	err := cmd.Run()
	if ee, ok := err.(*exec.ExitError); ok {
		exit = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("run CLI: %v", err)
	}
	return so.String(), se.String(), exit
}

// apiWithJWT answers every request with `status` and a body that CONTAINS the JWT (as the create
// response legitimately does, and as a faulty / hostile server could for any other call): the CLI
// must only ever display what it is meant to display.
func apiWithJWT(t *testing.T, status int, body func() any) *atomic.Int32 {
	t.Helper()
	var calls atomic.Int32
	mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(status)
		mustEncode(t, w, body())
	})
	return &calls
}

func createResponse() any {
	return map[string]any{"token": leakJWT, "id": "uuid-rp-1", "role": "relay-parent", "sub": "central",
		"jti": "jti-1", "expires_at": "2027-01-01T00:00:00Z", "created_at": "2026-10-04T00:00:00Z"}
}

func TestLeak_Create_JWTShownExactlyOnceOnStdoutOnly(t *testing.T) {
	for _, format := range []string{"table", "json"} {
		t.Run(format, func(t *testing.T) {
			apiWithJWT(t, http.StatusCreated, createResponse)
			out, errOut, code := runCLI(t, "--format", format, "tokens", "create", "--role", "relay-parent", "--sub", "central", "--aud", "dmz1", "--expires", "30d")
			if code != 0 {
				t.Fatalf("exit %d, stderr: %s", code, errOut)
			}
			if n := strings.Count(out, leakJWT); n != 1 {
				t.Errorf("the JWT must be printed exactly once on stdout, got %d:\n%s", n, out)
			}
			if strings.TrimSpace(errOut) != "" {
				assertNoJWT(t, "stderr (logs, slog, errors)", errOut)
			}
		})
	}
}

func TestLeak_Create_ErrorPathsNeverPrintJWT(t *testing.T) {
	tests := []struct {
		name   string
		args   []string
		status int
		body   func() any
		raw    string // when set, sent verbatim instead of JSON (malformed response)
		code   int
		stderr string
		calls  int32
	}{
		{name: "aud missing", args: []string{"--role", "relay-parent", "--sub", "central", "--expires", "30d"}, status: 201, body: createResponse, code: 1, stderr: "--aud"},
		{name: "expiry beyond 365d", args: []string{"--role", "relay-parent", "--sub", "central", "--aud", "dmz1", "--expires", "366d"}, status: 201, body: createResponse, code: 1, stderr: "365d"},
		{name: "sub missing", args: []string{"--role", "relay-parent", "--expires", "30d"}, status: 201, body: createResponse, code: 1, stderr: "--sub"},
		{name: "API 500 whose body carries a token", args: []string{"--role", "relay-parent", "--sub", "central", "--aud", "dmz1", "--expires", "30d"}, status: 500,
			body: func() any { return map[string]any{"error": "db_error", "token": leakJWT} }, code: 1, stderr: "db_error", calls: 1},
		{name: "API 401", args: []string{"--role", "relay-parent", "--sub", "central", "--aud", "dmz1", "--expires", "30d"}, status: 401,
			body: func() any { return map[string]any{"error": "unauthorized", "token": leakJWT} }, code: 1, stderr: "unauthorized", calls: 1},
		{name: "malformed 201 response containing the JWT", args: []string{"--role", "relay-parent", "--sub", "central", "--aud", "dmz1", "--expires", "30d"}, status: 201,
			raw: `{"token":"` + leakJWT + `"`, code: 1, stderr: "parse response", calls: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var calls atomic.Int32
			mockServer(t, func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.WriteHeader(tt.status)
				if tt.raw != "" {
					_, _ = w.Write([]byte(tt.raw))
					return
				}
				mustEncode(t, w, tt.body())
			})
			out, errOut, code := runCLI(t, append([]string{"tokens", "create"}, tt.args...)...)
			if code != tt.code {
				t.Errorf("exit code = %d, want %d (stderr: %s)", code, tt.code, errOut)
			}
			if !strings.Contains(errOut, tt.stderr) {
				t.Errorf("stderr must explain the failure (%q):\n%s", tt.stderr, errOut)
			}
			if calls.Load() != tt.calls {
				t.Errorf("API calls = %d, want %d", calls.Load(), tt.calls)
			}
			assertNoJWT(t, "stdout", out)
			assertNoJWT(t, "stderr", errOut)
		})
	}
}

func TestLeak_List_NeverPrintsAToken(t *testing.T) {
	apiWithJWT(t, http.StatusOK, func() any {
		// Metadata as the API returns it, plus a hypothetical "token" field: the table must ignore it.
		return []map[string]any{{"id": "uuid-rp-1", "role": "relay-parent", "sub": "central", "aud": "dmz1", "jti": "jti-1",
			"token_hash": "0123456789abcdef0123456789abcdef", "token": leakJWT, "revoked": false, "expires_at": "2027-01-01T00:00:00Z"}}
	})
	out, errOut, code := runCLI(t, "tokens", "list", "--role", "relay-parent")
	if code != 0 {
		t.Fatalf("exit %d, stderr: %s", code, errOut)
	}
	for _, want := range []string{"uuid-rp-1", "central -> dmz1"} {
		if !strings.Contains(out, want) {
			t.Errorf("list output lacks %q:\n%s", want, out)
		}
	}
	assertNoJWT(t, "stdout", out)
	assertNoJWT(t, "stderr", errOut)
}

func TestLeak_List_APIErrorNeverPrintsAToken(t *testing.T) {
	apiWithJWT(t, http.StatusInternalServerError, func() any { return map[string]any{"error": "db_error", "token": leakJWT} })
	out, errOut, code := runCLI(t, "tokens", "list", "--role", "relay-parent")
	if code != 1 || !strings.Contains(errOut, "db_error") {
		t.Errorf("exit %d, stderr: %s", code, errOut)
	}
	assertNoJWT(t, "stdout", out)
	assertNoJWT(t, "stderr", errOut)
}

func TestLeak_Revoke_NeverPrintsAToken(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		apiWithJWT(t, http.StatusOK, func() any { return map[string]any{"status": "revoked", "id": "uuid-rp-1", "token": leakJWT} })
		out, errOut, code := runCLI(t, "tokens", "revoke", "uuid-rp-1")
		if code != 0 || !strings.Contains(out, "Token uuid-rp-1 revoked") {
			t.Errorf("exit %d, stdout: %s, stderr: %s", code, out, errOut)
		}
		assertNoJWT(t, "stdout", out)
		assertNoJWT(t, "stderr", errOut)
	})
	t.Run("not found", func(t *testing.T) {
		apiWithJWT(t, http.StatusNotFound, func() any { return map[string]any{"error": "token_not_found", "token": leakJWT} })
		out, errOut, code := runCLI(t, "tokens", "revoke", "nope")
		if code != 2 || !strings.Contains(errOut, "not found") {
			t.Errorf("exit %d, stderr: %s", code, errOut)
		}
		assertNoJWT(t, "stdout", out)
		assertNoJWT(t, "stderr", errOut)
	})
	t.Run("server error", func(t *testing.T) {
		apiWithJWT(t, http.StatusInternalServerError, func() any { return map[string]any{"error": "db_error", "token": leakJWT} })
		out, errOut, code := runCLI(t, "tokens", "revoke", "uuid-rp-1")
		if code != 1 || !strings.Contains(errOut, "db_error") {
			t.Errorf("exit %d, stderr: %s", code, errOut)
		}
		assertNoJWT(t, "stdout", out)
		assertNoJWT(t, "stderr", errOut)
	})
}
