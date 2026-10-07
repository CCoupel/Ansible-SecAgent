package server

import (
	"bytes"
	"errors"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"secagent-server/cmd/secagent-server/internal/handlers"
	"secagent-server/internal/secretenv"
)

func secretFile(t *testing.T, content string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(p, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

// #196: JWT_SECRET_KEY, ADMIN_TOKEN and RSA_MASTER_KEY may each come from X_FILE.
func TestConfigFromEnv_SecretsFromFiles(t *testing.T) {
	setServerEnv(t)
	t.Setenv("JWT_SECRET_KEY", "")
	t.Setenv("ADMIN_TOKEN", "")
	t.Setenv("RSA_MASTER_KEY", "")
	t.Setenv("JWT_SECRET_KEY_FILE", secretFile(t, "jwt-from-file\n", 0o600))
	t.Setenv("ADMIN_TOKEN_FILE", secretFile(t, "admin-from-file\n", 0o400))
	t.Setenv("RSA_MASTER_KEY_FILE", secretFile(t, "master-from-file \n", 0o600))
	cfg, err := ConfigFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.JWTSecret != "jwt-from-file" || cfg.AdminToken != "admin-from-file" || cfg.MasterKey != "master-from-file" {
		t.Fatalf("secrets = %q %q %q", cfg.JWTSecret, cfg.AdminToken, cfg.MasterKey)
	}
}

func TestConfigFromEnv_DirectSecretsStillAccepted(t *testing.T) {
	setServerEnv(t)
	t.Setenv("RSA_MASTER_KEY", "direct-master")
	t.Setenv("JWT_SECRET_KEY_FILE", "")
	t.Setenv("ADMIN_TOKEN_FILE", "")
	t.Setenv("RSA_MASTER_KEY_FILE", "")
	cfg, err := ConfigFromEnv()
	if err != nil || cfg.JWTSecret != "s" || cfg.AdminToken != "a" || cfg.MasterKey != "direct-master" {
		t.Fatalf("%+v %v", cfg, err)
	}
}

// fail closed: both defined, or an unsafe / missing / empty file, refuses to start, never echoing a value.
func TestConfigFromEnv_SecretFileRefusals(t *testing.T) {
	for _, name := range []string{"JWT_SECRET_KEY", "ADMIN_TOKEN", "RSA_MASTER_KEY"} {
		t.Run(name+" both set", func(t *testing.T) {
			setServerEnv(t)
			t.Setenv(name, "direct-value-XYZ")
			t.Setenv(name+"_FILE", secretFile(t, "file-value-XYZ", 0o600))
			_, err := ConfigFromEnv()
			if !errors.Is(err, secretenv.ErrBothSet) {
				t.Fatalf("got %v", err)
			}
			if strings.Contains(err.Error(), "value-XYZ") {
				t.Fatalf("error leaks a value: %v", err)
			}
		})
		t.Run(name+" unsafe permissions", func(t *testing.T) {
			setServerEnv(t)
			t.Setenv(name, "")
			t.Setenv(name+"_FILE", secretFile(t, "file-value-XYZ", 0o644))
			if _, err := ConfigFromEnv(); !errors.Is(err, secretenv.ErrPermissions) {
				t.Fatalf("got %v", err)
			}
		})
		t.Run(name+" missing file", func(t *testing.T) {
			setServerEnv(t)
			t.Setenv(name, "")
			t.Setenv(name+"_FILE", filepath.Join(t.TempDir(), "absent"))
			if _, err := ConfigFromEnv(); !errors.Is(err, secretenv.ErrFileUnreadable) {
				t.Fatalf("got %v", err)
			}
		})
		t.Run(name+" empty file", func(t *testing.T) {
			setServerEnv(t)
			t.Setenv(name, "")
			t.Setenv(name+"_FILE", secretFile(t, "\n", 0o600))
			if _, err := ConfigFromEnv(); !errors.Is(err, secretenv.ErrEmpty) {
				t.Fatalf("got %v", err)
			}
		})
	}
}

// No secret value in the startup logs, whichever way it was provided.
func TestConfigFromEnv_NoSecretValueInStartupLogs(t *testing.T) {
	setServerEnv(t)
	t.Setenv("JWT_SECRET_KEY", "")
	t.Setenv("ADMIN_TOKEN", "")
	t.Setenv("RSA_MASTER_KEY", "master-DIRECT-4242")
	t.Setenv("JWT_SECRET_KEY_FILE", secretFile(t, "jwt-FILE-4242", 0o600))
	t.Setenv("ADMIN_TOKEN_FILE", secretFile(t, "admin-FILE-4242", 0o600))
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(prev)
	if _, err := ConfigFromEnv(); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "4242") {
		t.Fatalf("a secret reached the logs: %s", buf.String())
	}
}

func TestRSAMasterKeyFromBuildConfigIsUsedByTheHandlers(t *testing.T) {
	t.Setenv("RSA_MASTER_KEY", "")
	handlers.ConfigureMasterKey("from-file-key")
	defer handlers.ConfigureMasterKey("")
	if _, err := handlers.SealPushToken("relay1", "child-jwt"); err != nil {
		t.Fatalf("a master key configured at startup (file) must be usable without the env var: %v", err)
	}
}
