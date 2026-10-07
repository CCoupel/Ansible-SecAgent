package server

import (
	"errors"
	"os"
	"path/filepath"
	"secagent-server/cmd/secagent-server/internal/tlsca"
	"strings"
	"testing"
)

func setServerEnv(t *testing.T) {
	t.Helper()
	t.Setenv("JWT_SECRET_KEY", "s")
	t.Setenv("ADMIN_TOKEN", "a")
	t.Setenv("TLS_DISABLE", "true")
	t.Setenv("ADMIN_INSECURE_HTTP", "true")
	t.Setenv("ADMIN_INSECURE_HTTP_ACK", AdminInsecureHTTPAckValue) // these tests are not about the admin exposure
	for _, k := range []string{EnvAPIAddr, EnvAdminAddr, EnvWSAddr, "DATABASE_URL", "STATE_DIR", "STATE_MAX_BYTES", "RELAY_SINGLE_INSTANCE", "RELAY_STATUS_FILE", "LOG_LEVEL",
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
	if cfg.StateDir != "/data" || cfg.LogLevel != "INFO" {
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

func TestConfigFromEnv_NeverSetsTheTuneSeam(t *testing.T) {
	setServerEnv(t)
	cfg, err := ConfigFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Tune != nil {
		t.Error("Config.Tune is a test seam: ConfigFromEnv must never set it")
	}
}

func TestConfigFromEnv_GroupVars(t *testing.T) {
	setServerEnv(t)
	t.Setenv("RELAY_GROUP_VARS", `{"env":"staging","ansible_python_interpreter":"/usr/bin/python3"}`)
	cfg, err := ConfigFromEnv()
	if err != nil || cfg.GroupVars["env"] != "staging" {
		t.Fatalf("cfg.GroupVars = %v err = %v", cfg.GroupVars, err)
	}
	for name, bad := range map[string]string{
		"invalid JSON": `{env: staging}`,
		"template":     `{"x":"{{ 1 }}"}`,
		"reserved key": `{"ansible_host":"1.2.3.4"}`,
	} {
		setServerEnv(t)
		t.Setenv("RELAY_GROUP_VARS", bad)
		if _, err := ConfigFromEnv(); err == nil || !strings.Contains(err.Error(), "RELAY_GROUP_VARS") {
			t.Errorf("%s: err = %v, want a start-up error naming RELAY_GROUP_VARS", name, err)
		}
	}
}

// #177: an invalid TRUSTED_PROXY_CIDRS refuses to start, in ConfigFromEnv and in Build.
func TestConfig_InvalidTrustedProxyCIDRsRefusesToStart(t *testing.T) {
	t.Setenv("JWT_SECRET_KEY", "s")
	t.Setenv("ADMIN_TOKEN", "a")
	t.Setenv("TLS_DISABLE", "true")
	t.Setenv("ADMIN_INSECURE_HTTP", "true")
	t.Setenv("ADMIN_INSECURE_HTTP_ACK", AdminInsecureHTTPAckValue) // these tests are not about the admin exposure
	t.Setenv("TRUSTED_PROXY_CIDRS", "10.0.0.0/8,not-a-cidr")
	if _, err := ConfigFromEnv(); err == nil || !strings.Contains(err.Error(), "TRUSTED_PROXY_CIDRS") {
		t.Fatalf("ConfigFromEnv error = %v, want a TRUSTED_PROXY_CIDRS error", err)
	}
	if _, err := Build(Config{TLSDisable: true, AdminAddr: "127.0.0.1:0", JWTSecret: "s", AdminToken: "a", StateDir: testStateDir(t), InsecureTestState: true, WriteGuard: allowWrites, TrustedProxyCIDRs: "10.0.0.0/99"}); err == nil {
		t.Fatal("Build must refuse an invalid CIDR")
	}
	t.Setenv("TRUSTED_PROXY_CIDRS", "10.0.0.0/8, 192.168.0.0/16")
	cfg, err := ConfigFromEnv()
	if err != nil || cfg.TrustedProxyCIDRs == "" {
		t.Fatalf("valid list: (%+v, %v)", cfg, err)
	}
}

// #177b: TRUSTED_PROXY_CIDRS with a /0 range refuses to start (fail closed), in ConfigFromEnv and Build.
func TestConfig_TrustedProxyCIDRsPrefixZeroRefusesToStart(t *testing.T) {
	for _, bad := range []string{"0.0.0.0/0", "::/0", "10.0.0.0/8,0.0.0.0/0"} {
		t.Setenv("JWT_SECRET_KEY", "s")
		t.Setenv("ADMIN_TOKEN", "a")
		t.Setenv("TLS_DISABLE", "true")
		t.Setenv("ADMIN_INSECURE_HTTP", "true")
		t.Setenv("ADMIN_INSECURE_HTTP_ACK", AdminInsecureHTTPAckValue)
		t.Setenv("TRUSTED_PROXY_CIDRS", bad)
		if _, err := ConfigFromEnv(); err == nil || !strings.Contains(err.Error(), "TRUSTED_PROXY_CIDRS") {
			t.Errorf("ConfigFromEnv(%q) error = %v, want a TRUSTED_PROXY_CIDRS error", bad, err)
		}
		if _, err := Build(Config{TLSDisable: true, AdminAddr: "127.0.0.1:0", JWTSecret: "s", AdminToken: "a", StateDir: testStateDir(t), InsecureTestState: true, WriteGuard: allowWrites, TrustedProxyCIDRs: bad}); err == nil {
			t.Errorf("Build(%q) must refuse a /0 range", bad)
		}
	}
}

// #160: DATABASE_URL (SQLite) is an ERROR, not a warning: ignoring it would let the operator
// believe a database is still in use. STATE_DIR / STATE_MAX_BYTES are read and validated.
func TestConfigFromEnv_StateSettings(t *testing.T) {
	setServerEnv(t)
	t.Setenv("DATABASE_URL", "sqlite:////data/relay.db")
	if _, err := ConfigFromEnv(); err == nil || !strings.Contains(err.Error(), "DATABASE_URL is no longer supported") {
		t.Fatalf("DATABASE_URL set: %v", err)
	} else if !errors.Is(err, ErrDatabaseURLRemoved) {
		t.Errorf("not ErrDatabaseURLRemoved: %v", err)
	}
	t.Setenv("DATABASE_URL", "")
	t.Setenv("STATE_DIR", "/srv/relay-state")
	t.Setenv("STATE_MAX_BYTES", "1048576")
	cfg, err := ConfigFromEnv()
	if err != nil || cfg.StateDir != "/srv/relay-state" || cfg.StateMaxBytes != 1048576 {
		t.Fatalf("cfg = %+v %v", cfg, err)
	}
	if cfg.WriteGuard != nil || cfg.InsecureTestState {
		t.Error("the environment can never set the write guard nor the insecure test mode")
	}
	t.Setenv("STATE_MAX_BYTES", "lots")
	if _, err := ConfigFromEnv(); err == nil {
		t.Error("an invalid STATE_MAX_BYTES must be refused")
	}
}

// RELAY_SINGLE_INSTANCE (the transitional opt-in of #160) is gone: the lock is always on. The variable
// is ignored with a warning, whatever its value, and no Config field reflects it.
func TestConfigFromEnv_SingleInstanceIsObsoleteAndIgnored(t *testing.T) {
	setServerEnv(t)
	for _, v := range []string{"true", "false", "1", "garbage"} {
		t.Setenv("RELAY_SINGLE_INSTANCE", v)
		if _, err := ConfigFromEnv(); err != nil {
			t.Errorf("RELAY_SINGLE_INSTANCE=%q must be ignored, got %v", v, err)
		}
	}
}

// The local status file must stay out of the shared STATE_DIR.
func TestConfigFromEnv_StatusFileMustBeOutsideStateDir(t *testing.T) {
	setServerEnv(t)
	dir := t.TempDir()
	t.Setenv("STATE_DIR", dir)
	t.Setenv("RELAY_STATUS_FILE", filepath.Join(dir, "status.json"))
	if _, err := ConfigFromEnv(); err == nil || !strings.Contains(err.Error(), "outside STATE_DIR") {
		t.Fatalf("status file inside STATE_DIR must be refused, got %v", err)
	}
	t.Setenv("RELAY_STATUS_FILE", filepath.Join(t.TempDir(), "status.json"))
	cfg, err := ConfigFromEnv()
	if err != nil || cfg.StatusFile == "" {
		t.Fatalf("outside is accepted: %v %q", err, cfg.StatusFile)
	}
}

func TestConfigFromEnv_CAFile(t *testing.T) {
	setServerEnv(t)
	if cfg, err := ConfigFromEnv(); err != nil || cfg.CAFile != "" {
		t.Fatalf("unset: %+v %v", cfg.CAFile, err)
	}
	bad := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(bad, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("REPEATER_CA_FILE", bad)
	if _, err := ConfigFromEnv(); !errors.Is(err, tlsca.ErrInvalidCAFile) {
		t.Fatalf("an unusable CA file must refuse the start, got %v", err)
	}
	t.Setenv("REPEATER_CA_FILE", filepath.Join(t.TempDir(), "absent.pem"))
	if _, err := ConfigFromEnv(); !errors.Is(err, tlsca.ErrInvalidCAFile) {
		t.Fatalf("a missing CA file must refuse the start, got %v", err)
	}
}
