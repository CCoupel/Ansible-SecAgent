// Package server holds the wiring of secagent-server: configuration, construction of every
// component (store, hooks, handlers, repeater client, dialers, routers) and the lifecycle
// (listen, serve, graceful shutdown). main() only reads the environment and calls it, so the
// real start-up sequence can be exercised by tests (#155).
package server

import (
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"secagent-server/cmd/secagent-server/internal/config"
	"secagent-server/cmd/secagent-server/internal/handlers"
	"secagent-server/cmd/secagent-server/internal/repeater"
)

// Default listen addresses (unchanged since v1).
const (
	DefaultAPIAddr   = ":7770" // public API + agent/relay WebSocket (compat)
	DefaultAdminAddr = ":7771" // admin API (never exposed publicly)
	DefaultWSAddr    = ":7772" // WebSocket
)

// Environment variables overriding the listen addresses (host:port or :port).
const (
	EnvAPIAddr   = "API_ADDR"
	EnvAdminAddr = "ADMIN_ADDR"
	EnvWSAddr    = "WS_ADDR"
)

// Config is everything the server needs to start.
type Config struct {
	JWTSecret   string
	AdminToken  string
	DatabaseURL string
	LogLevel    string

	// Listen addresses; empty = the defaults above.
	APIAddr   string
	AdminAddr string
	WSAddr    string
	// Optional pre-bound listeners (tests: ephemeral ports). They take precedence over the addresses.
	APIListener   net.Listener
	AdminListener net.Listener
	WSListener    net.Listener

	// Tune adjusts the repeater timing options (MinBackoff, MaxBackoff, AgentListInterval,
	// PingInterval, HandshakeTimeout) of the uplink / pull client and of the push dialers before
	// they are created. It is a TEST SEAM: ConfigFromEnv never sets it (no operator knob, no remote
	// surface: a too short backoff would hammer the parent). TLS settings are not exposed.
	Tune func(*repeater.Options, *repeater.DialerOptions)

	// GroupVars are this relay's Ansible group variables (RELAY_GROUP_VARS), validated.
	GroupVars map[string]any

	// TrustedProxyCIDRs (TRUSTED_PROXY_CIDRS, comma separated) are the reverse proxies whose
	// X-Forwarded-For is believed; empty = never (#177). An invalid CIDR refuses the start.
	TrustedProxyCIDRs string

	// TLSCert / TLSKey (TLS_CERT / TLS_KEY) are the PEM files of the server certificate (full chain)
	// and its key, served on the API and WebSocket ports (and on the admin port with AdminTLS).
	// TLSDisable (TLS_DISABLE=true) serves plain HTTP: tests and local CI only. Without a complete
	// pair and without TLSDisable, Build refuses to start (fail closed, #175).
	TLSCert, TLSKey string
	TLSDisable      bool
	AdminTLS        bool
	// TLSReloadInterval is how often the certificate files are checked for a change (0 = 60 s).
	// Test seam: ConfigFromEnv leaves it zero.
	TLSReloadInterval time.Duration
	// tlsNow is the clock of the certificate validity checks (tests).
	tlsNow func() time.Time

	// Repeater is the validated child-relay configuration (REPEATER_UPSTREAM_*); nil = no pull parent.
	Repeater *config.RepeaterConfig
}

// ErrMissingJWTSecret / ErrMissingAdminToken are returned by ConfigFromEnv.
var (
	ErrMissingJWTSecret  = errors.New("JWT_SECRET_KEY environment variable is required")
	ErrMissingAdminToken = errors.New("ADMIN_TOKEN environment variable is required")
)

// ConfigFromEnv reads and validates the server configuration from the environment.
// PROXY_MODE and PROXY_RELAYS are silently ignored (removed in v3.0, #123).
func ConfigFromEnv() (Config, error) {
	cfg := Config{
		JWTSecret:         os.Getenv("JWT_SECRET_KEY"),
		AdminToken:        os.Getenv("ADMIN_TOKEN"),
		DatabaseURL:       envOr("DATABASE_URL", "sqlite:///./relay.db"),
		LogLevel:          envOr("LOG_LEVEL", "INFO"),
		TrustedProxyCIDRs: os.Getenv(handlers.EnvTrustedProxyCIDRs),
		APIAddr:           envOr(EnvAPIAddr, DefaultAPIAddr),
		AdminAddr:         envOr(EnvAdminAddr, DefaultAdminAddr),
		WSAddr:            envOr(EnvWSAddr, DefaultWSAddr),
		TLSCert:           os.Getenv(EnvTLSCert),
		TLSKey:            os.Getenv(EnvTLSKey),
	}
	var terr error
	if cfg.TLSDisable, terr = envStrictBool(EnvTLSDisable); terr != nil {
		return Config{}, terr
	}
	if cfg.AdminTLS, terr = envStrictBool(EnvAdminTLS); terr != nil {
		return Config{}, terr
	}
	if err := validateTLSConfig(cfg); err != nil {
		return Config{}, err
	}
	for name, addr := range map[string]string{EnvAPIAddr: cfg.APIAddr, EnvAdminAddr: cfg.AdminAddr, EnvWSAddr: cfg.WSAddr} {
		if _, _, err := net.SplitHostPort(addr); err != nil {
			return Config{}, fmt.Errorf("invalid %s %q: %w", name, addr, err)
		}
	}
	if _, err := handlers.ParseTrustedProxyCIDRs(cfg.TrustedProxyCIDRs); err != nil {
		return Config{}, err
	}
	if cfg.JWTSecret == "" {
		return Config{}, ErrMissingJWTSecret
	}
	if cfg.AdminToken == "" {
		return Config{}, ErrMissingAdminToken
	}
	// Child relay configuration (#124): validated at startup, token never logged.
	rep, err := config.LoadRepeaterConfig()
	if err != nil {
		return Config{}, &InvalidRepeaterConfigError{Err: err}
	}
	cfg.Repeater = rep
	gv, err := config.LoadGroupVars()
	if err != nil {
		return Config{}, fmt.Errorf("%s: %w", config.EnvRelayGroupVars, err)
	}
	cfg.GroupVars = gv
	return cfg, nil
}

// InvalidRepeaterConfigError wraps a REPEATER_* validation failure.
type InvalidRepeaterConfigError struct{ Err error }

func (e *InvalidRepeaterConfigError) Error() string {
	return "invalid repeater configuration: " + e.Err.Error()
}
func (e *InvalidRepeaterConfigError) Unwrap() error { return e.Err }

// envStrictBool reads "true" / "false" / unset (false): any other value is an error, so that
// TLS_DISABLE=1 or =yes can never silently mean something else than intended.
func envStrictBool(name string) (bool, error) {
	switch v := os.Getenv(name); v {
	case "", "false":
		return false, nil
	case "true":
		return true, nil
	default:
		return false, fmt.Errorf("invalid %s: must be \"true\" or \"false\"", name)
	}
}

func envOr(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

func (c Config) apiAddr() string   { return orDefault(c.APIAddr, DefaultAPIAddr) }
func (c Config) adminAddr() string { return orDefault(c.AdminAddr, DefaultAdminAddr) }
func (c Config) wsAddr() string    { return orDefault(c.WSAddr, DefaultWSAddr) }

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
