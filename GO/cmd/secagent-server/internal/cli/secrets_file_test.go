package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"secagent-server/internal/secretenv"
)

func cliSecretFile(t *testing.T, content string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "s")
	if err := os.WriteFile(p, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCLISecrets_FromFile(t *testing.T) {
	t.Setenv("ADMIN_TOKEN", "")
	t.Setenv("RSA_MASTER_KEY", "")
	t.Setenv("ADMIN_TOKEN_FILE", cliSecretFile(t, "tok-from-file\n", 0o600))
	t.Setenv("RSA_MASTER_KEY_FILE", cliSecretFile(t, "mk-from-file\n", 0o600))
	if v, err := adminToken(); err != nil || v != "tok-from-file" {
		t.Fatalf("adminToken = %q %v", v, err)
	}
	if v, err := masterKeyFromEnv(); err != nil || v != "mk-from-file" {
		t.Fatalf("masterKey = %q %v", v, err)
	}
}

func TestCLISecrets_Refusals(t *testing.T) {
	t.Setenv("ADMIN_TOKEN", "direct")
	t.Setenv("ADMIN_TOKEN_FILE", cliSecretFile(t, "file", 0o600))
	if _, err := adminToken(); !errors.Is(err, secretenv.ErrBothSet) {
		t.Fatalf("got %v", err)
	}
	t.Setenv("ADMIN_TOKEN", "")
	t.Setenv("ADMIN_TOKEN_FILE", cliSecretFile(t, "file", 0o644))
	if _, err := adminToken(); !errors.Is(err, secretenv.ErrPermissions) {
		t.Fatalf("got %v", err)
	}
	t.Setenv("RSA_MASTER_KEY", "direct")
	t.Setenv("RSA_MASTER_KEY_FILE", cliSecretFile(t, "file", 0o600))
	if _, err := masterKeyFromEnv(); !errors.Is(err, secretenv.ErrBothSet) {
		t.Fatalf("got %v", err)
	}
}

// An unreadable admin token means the request is never sent (no anonymous call).
func TestAPIRequest_SecretFileErrorSendsNothing(t *testing.T) {
	t.Setenv("ADMIN_TOKEN", "")
	t.Setenv("ADMIN_TOKEN_FILE", cliSecretFile(t, "file", 0o666))
	_, _, sent, err := apiRequestOnce("http://127.0.0.1:1", "GET", "/api/x", nil)
	if err == nil || sent || strings.Contains(err.Error(), "file") && strings.Contains(err.Error(), "Bearer") {
		t.Fatalf("sent=%v err=%v", sent, err)
	}
}
