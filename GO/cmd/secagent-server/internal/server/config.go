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

	"secagent-server/cmd/secagent-server/internal/config"
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
	NATSURL     string
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
		JWTSecret:   os.Getenv("JWT_SECRET_KEY"),
		AdminToken:  os.Getenv("ADMIN_TOKEN"),
		NATSURL:     envOr("NATS_URL", "nats://localhost:4222"),
		DatabaseURL: envOr("DATABASE_URL", "sqlite:///./relay.db"),
		LogLevel:    envOr("LOG_LEVEL", "INFO"),
		APIAddr:     envOr(EnvAPIAddr, DefaultAPIAddr),
		AdminAddr:   envOr(EnvAdminAddr, DefaultAdminAddr),
		WSAddr:      envOr(EnvWSAddr, DefaultWSAddr),
	}
	for name, addr := range map[string]string{EnvAPIAddr: cfg.APIAddr, EnvAdminAddr: cfg.AdminAddr, EnvWSAddr: cfg.WSAddr} {
		if _, _, err := net.SplitHostPort(addr); err != nil {
			return Config{}, fmt.Errorf("invalid %s %q: %w", name, addr, err)
		}
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
	return cfg, nil
}

// InvalidRepeaterConfigError wraps a REPEATER_* validation failure.
type InvalidRepeaterConfigError struct{ Err error }

func (e *InvalidRepeaterConfigError) Error() string {
	return "invalid repeater configuration: " + e.Err.Error()
}
func (e *InvalidRepeaterConfigError) Unwrap() error { return e.Err }

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
