package cli

import (
	"bytes"
	"log"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const fakeParentJWT = "eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoicmVsYXktcGFyZW50In0.c2lnbmF0dXJl"

// resetCreateFlags restores the 'tokens create' flags: cobra keeps values between Execute calls.
func resetCreateFlags(t *testing.T) {
	t.Helper()
	for name, def := range map[string]string{
		"role": "", "sub": "", "expires": "never", "description": "", "hostname-pattern": "",
		"allowed-ips": "", "allowed-hostname-pattern": "",
	} {
		if err := tokensCreateCmd.Flags().Set(name, def); err != nil {
			t.Fatalf("reset --%s: %v", name, err)
		}
	}
	if err := tokensCreateCmd.Flags().Set("reusable", "false"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resetCreateFlags2() })
}

func resetCreateFlags2() {
	for _, name := range []string{"role", "sub", "description"} {
		_ = tokensCreateCmd.Flags().Set(name, "")
	}
	_ = tokensCreateCmd.Flags().Set("expires", "never")
}

func runCreate(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var err error
	out := captureStdout(t, func() {
		rootCmd.SetArgs(append([]string{"tokens", "create"}, args...))
		err = rootCmd.Execute()
	})
	return out, err
}

func TestTokensCreate_RelayParent_Success(t *testing.T) {
	resetCreateFlags(t)
	var gotBody map[string]interface{}
	mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		mustDecode(t, r.Body, &gotBody)
		w.WriteHeader(http.StatusCreated)
		mustEncode(t, w, map[string]interface{}{
			"token": fakeParentJWT, "id": "uuid-rp-1", "role": "relay-parent", "sub": "central",
			"jti": "jti-1", "expires_at": "2027-01-01T00:00:00Z", "created_at": time.Now().UTC().Format(time.RFC3339),
		})
	})
	out, err := runCreate(t, "--role", "relay-parent", "--sub", "central", "--expires", "90d", "--description", "uplink")
	if err != nil {
		t.Fatal(err)
	}
	if gotBody["role"] != "relay-parent" || gotBody["sub"] != "central" || gotBody["description"] != "uplink" {
		t.Errorf("request body = %v", gotBody)
	}
	exp, perr := time.Parse(time.RFC3339, gotBody["expires_at"].(string))
	if perr != nil || time.Until(exp) < 89*24*time.Hour || time.Until(exp) > 91*24*time.Hour {
		t.Errorf("expires_at = %v (%v), want ~90d", gotBody["expires_at"], perr)
	}
	for _, want := range []string{fakeParentJWT, "shown only once", "uuid-rp-1", "relay-parent", "central"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
}

func TestTokensCreate_RelayParent_RefusedBeforeAnyRequest(t *testing.T) {
	var calls atomic.Int32
	mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusCreated)
	})
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"no sub", []string{"--role", "relay-parent", "--expires", "30d"}, "--sub"},
		{"bad sub", []string{"--role", "relay-parent", "--sub", "a b!", "--expires", "30d"}, "--sub"},
		{"no expiry", []string{"--role", "relay-parent", "--sub", "central"}, "--expires is required"},
		{"explicit never", []string{"--role", "relay-parent", "--sub", "central", "--expires", "never"}, "--expires is required"},
		{"beyond the cap", []string{"--role", "relay-parent", "--sub", "central", "--expires", "366d"}, "365d"},
		{"unknown role", []string{"--role", "relay-child", "--sub", "central", "--expires", "30d"}, "--role must be"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetCreateFlags(t)
			_, err := runCreate(t, tt.args...)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("err = %v, want it to mention %q", err, tt.want)
			}
		})
	}
	if calls.Load() != 0 {
		t.Errorf("the API was called %d times for invalid input", calls.Load())
	}
}

func TestTokensCreate_RelayParent_ExactlyAtTheCapIsAccepted(t *testing.T) {
	resetCreateFlags(t)
	mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		mustEncode(t, w, map[string]interface{}{"token": fakeParentJWT, "id": "x", "role": "relay-parent", "created_at": "t"})
	})
	if _, err := runCreate(t, "--role", "relay-parent", "--sub", "central", "--expires", "365d"); err != nil {
		t.Errorf("365d must be accepted: %v", err)
	}
}

func TestTokensList_RelayParent_ShowsMetadataNeverTheToken(t *testing.T) {
	var gotPath string
	mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.RequestURI()
		mustEncode(t, w, []map[string]interface{}{{
			"id": "uuid-rp-1", "role": "relay-parent", "sub": "central", "jti": "jti-1",
			"expires_at": "2027-01-01T00:00:00Z", "revoked": true, "created_at": "2026-10-04T00:00:00Z",
		}})
	})
	out := captureStdout(t, func() {
		rootCmd.SetArgs([]string{"tokens", "list", "--role", "relay-parent"})
		if err := rootCmd.Execute(); err != nil {
			t.Errorf("list: %v", err)
		}
	})
	if gotPath != "/api/admin/tokens?role=relay-parent" {
		t.Errorf("path = %s", gotPath)
	}
	for _, want := range []string{"uuid-rp-1", "relay-parent", "parent=central", "true"} {
		if !strings.Contains(out, want) {
			t.Errorf("list output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "<nil>") || strings.Contains(out, "eyJ") {
		t.Errorf("unexpected content in list output:\n%s", out)
	}
	_ = tokensListCmd.Flags().Set("role", "")
}

// The CLI prints the JWT on stdout exactly once, on purpose; it must reach no log.
func TestTokensCreate_RelayParent_JWTNeverLogged(t *testing.T) {
	resetCreateFlags(t)
	var std, structured bytes.Buffer
	prevLog, prevSlog := log.Writer(), slog.Default()
	log.SetOutput(&std)
	slog.SetDefault(slog.New(slog.NewTextHandler(&structured, nil)))
	t.Cleanup(func() { log.SetOutput(prevLog); slog.SetDefault(prevSlog) })

	mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		mustEncode(t, w, map[string]interface{}{"token": fakeParentJWT, "id": "x", "role": "relay-parent", "sub": "central", "created_at": "t"})
	})
	out, err := runCreate(t, "--role", "relay-parent", "--sub", "central", "--expires", "30d")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(out, fakeParentJWT) != 1 {
		t.Errorf("the token must be printed exactly once, got %d", strings.Count(out, fakeParentJWT))
	}
	for _, sink := range []string{std.String(), structured.String()} {
		if strings.Contains(sink, fakeParentJWT) || strings.Contains(sink, "test-token") {
			t.Errorf("a secret leaked in logs: %q", sink)
		}
	}
}
