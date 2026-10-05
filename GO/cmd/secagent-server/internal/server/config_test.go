package server

import (
	"errors"
	"strings"
	"testing"
)

func setServerEnv(t *testing.T) {
	t.Helper()
	t.Setenv("JWT_SECRET_KEY", "s")
	t.Setenv("ADMIN_TOKEN", "a")
	for _, k := range []string{EnvAPIAddr, EnvAdminAddr, EnvWSAddr, "NATS_URL", "DATABASE_URL", "LOG_LEVEL",
		"REPEATER_ID", "REPEATER_UPSTREAM_URL", "REPEATER_UPSTREAM_TOKEN"} {
		t.Setenv(k, "")
	}
}

func TestConfigFromEnv_DefaultsAreTheHistoricalPorts(t *testing.T) {
	setServerEnv(t)
	cfg, err := ConfigFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.APIAddr != ":7770" || cfg.AdminAddr != ":7771" || cfg.WSAddr != ":7772" {
		t.Errorf("addresses = %q %q %q, want :7770 :7771 :7772", cfg.APIAddr, cfg.AdminAddr, cfg.WSAddr)
	}
	if cfg.NATSURL != "nats://localhost:4222" || cfg.DatabaseURL != "sqlite:///./relay.db" || cfg.LogLevel != "INFO" {
		t.Errorf("defaults = %+v", cfg)
	}
	if cfg.Repeater != nil {
		t.Error("no repeater configuration expected")
	}
}

func TestConfigFromEnv_ListenAddressesOverridable(t *testing.T) {
	setServerEnv(t)
	t.Setenv(EnvAPIAddr, "127.0.0.1:18770")
	t.Setenv(EnvAdminAddr, "10.0.0.5:18771")
	t.Setenv(EnvWSAddr, ":18772")
	cfg, err := ConfigFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.APIAddr != "127.0.0.1:18770" || cfg.AdminAddr != "10.0.0.5:18771" || cfg.WSAddr != ":18772" {
		t.Errorf("addresses = %q %q %q", cfg.APIAddr, cfg.AdminAddr, cfg.WSAddr)
	}
}

func TestConfigFromEnv_RejectsMalformedAddresses(t *testing.T) {
	for _, name := range []string{EnvAPIAddr, EnvAdminAddr, EnvWSAddr} {
		t.Run(name, func(t *testing.T) {
			setServerEnv(t)
			t.Setenv(name, "7770") // missing colon
			_, err := ConfigFromEnv()
			if err == nil || !strings.Contains(err.Error(), name) {
				t.Errorf("err = %v, want it to name %s", err, name)
			}
		})
	}
}

func TestConfigFromEnv_RequiredSecrets(t *testing.T) {
	setServerEnv(t)
	t.Setenv("JWT_SECRET_KEY", "")
	if _, err := ConfigFromEnv(); !errors.Is(err, ErrMissingJWTSecret) {
		t.Errorf("err = %v", err)
	}
	setServerEnv(t)
	t.Setenv("ADMIN_TOKEN", "")
	if _, err := ConfigFromEnv(); !errors.Is(err, ErrMissingAdminToken) {
		t.Errorf("err = %v", err)
	}
}

func TestConfigFromEnv_InvalidRepeaterConfigIsReported(t *testing.T) {
	setServerEnv(t)
	t.Setenv("REPEATER_UPSTREAM_URL", "wss://parent:7772") // REPEATER_ID and token missing
	_, err := ConfigFromEnv()
	var rep *InvalidRepeaterConfigError
	if !errors.As(err, &rep) || !strings.Contains(err.Error(), "invalid repeater configuration") {
		t.Errorf("err = %v", err)
	}
}

func TestConfigFromEnv_ValidRepeaterConfig(t *testing.T) {
	setServerEnv(t)
	t.Setenv("REPEATER_ID", "dmz1")
	t.Setenv("REPEATER_UPSTREAM_URL", "wss://parent:7772")
	t.Setenv("REPEATER_UPSTREAM_TOKEN", "tok")
	cfg, err := ConfigFromEnv()
	if err != nil || cfg.Repeater == nil || cfg.Repeater.ID != "dmz1" {
		t.Fatalf("cfg = %+v err = %v", cfg.Repeater, err)
	}
}
