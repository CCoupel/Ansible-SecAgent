// Package server holds the wiring of secagent-server: configuration, construction of every
// component (store, hooks, handlers, repeater client, dialers, routers) and the lifecycle
// (listen, serve, graceful shutdown). main() only reads the environment and calls it, so the
// real start-up sequence can be exercised by tests (#155).
package server

import (
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"secagent-server/cmd/secagent-server/internal/config"
	"secagent-server/cmd/secagent-server/internal/handlers"
	"secagent-server/cmd/secagent-server/internal/localstatus"
	"secagent-server/cmd/secagent-server/internal/lock"
	"secagent-server/cmd/secagent-server/internal/repeater"
	"secagent-server/cmd/secagent-server/internal/state"
	"secagent-server/cmd/secagent-server/internal/tlsca"
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
	JWTSecret  string
	AdminToken string
	LogLevel   string

	// StateDir is STATE_DIR (default /data): the directory of relay.state (#160). The state must
	// have been created by `secagent-server state init`; the server never creates it.
	StateDir string
	// StateMaxBytes is STATE_MAX_BYTES (0 = the default ceiling).
	StateMaxBytes int64
	// WriteGuard is the write guard of the state engine: the lock identity check of #163. While it
	// is nil the instance is read-only (every write fails with storage.ErrReadOnly). Never set from
	// the environment.
	WriteGuard func() error
	// InsecureTestState accepts a state created with `state init --insecure-test-mode` (secrets in
	// clear). TEST SEAM: never set by ConfigFromEnv, and refused when RSA_MASTER_KEY is set.
	InsecureTestState bool
	// PurgeInterval is the period of the blacklist purge task (0 = one hour). TEST SEAM.
	PurgeInterval time.Duration

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
	// AdminInsecureHTTP / AdminInsecureHTTPAck: the explicit derogation for a plain-HTTP admin port
	// on a non-loopback address (see adminExposure).
	AdminInsecureHTTP    bool
	AdminInsecureHTTPAck string
	// TLSReloadInterval is how often the certificate files are checked for a change (0 = 60 s).
	// Test seam: ConfigFromEnv leaves it zero.
	TLSReloadInterval time.Duration
	// tlsNow is the clock of the certificate validity checks (tests).
	tlsNow func() time.Time

	// CAFile is REPEATER_CA_FILE: the PEM bundle of the CAs trusted by every outbound link (pull link
	// to the parent, push dial-out to children). It REPLACES the system roots; set but unusable =
	// the start is refused. There is no skip-verify option (#147).
	CAFile string

	// StatusFile is RELAY_STATUS_FILE (default /run/secagent/status.json): the LOCAL health file read
	// by `secagent-server status --local`. It must be outside STATE_DIR.
	StatusFile string

	// LockParams / LockHooks / Listen are TEST SEAMS, never set by ConfigFromEnv (no operator
	// knob: a too aggressive lock calibration or an injected listener must not be deployable).
	// LockParams zero = lock.DefaultParams(). Listen, when set, binds the "api", "admin" and "ws"
	// listeners at the moment the node starts serving (after the promotion), instead of the addresses.
	LockParams lock.Params
	LockHooks  lock.Hooks
	Listen     func(name string) (net.Listener, error)
	// OnReady is called once the promoted node serves (all listeners up). Test seam.
	OnReady func(*Node)

	// set by RunInstance (the promoted master), not by callers
	certs        *certStore       // certificates validated before the lock loop
	minWriteSeq  uint64           // lowest write_seq of a state this master may accept (anti-replay)
	onStateWrite func(seq uint64) // publishes the state write_seq in relay.lock

	// Repeater is the validated child-relay configuration (REPEATER_UPSTREAM_*); nil = no pull parent.
	Repeater *config.RepeaterConfig
}

// ErrDatabaseURLRemoved is returned when DATABASE_URL is still set: since v3.0.3 the relay state is
// the file relay.state in STATE_DIR (no SQLite, no migration of an existing relay.db).
var ErrDatabaseURLRemoved = errors.New("DATABASE_URL is no longer supported: the relay state is now relay.state in STATE_DIR (default /data); unset DATABASE_URL and create the state with 'secagent-server state init' (existing relay.db data is NOT migrated)")

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
		StateDir:          state.DirFromEnv(),
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
	if os.Getenv("RELAY_SINGLE_INSTANCE") != "" {
		// the transitional opt-in of #160 is gone: the lock (#163) is always on, even for one instance
		log.Printf("[WARN] RELAY_SINGLE_INSTANCE is obsolete and ignored: the exclusivity lock is always active (#163)")
	}
	if cfg.AdminInsecureHTTP, terr = envStrictBool(EnvAdminInsecureHTTP); terr != nil {
		return Config{}, terr
	}
	cfg.AdminInsecureHTTPAck = os.Getenv(EnvAdminInsecureHTTPAck)
	if err := validateTLSConfig(cfg); err != nil {
		return Config{}, err
	}
	if _, err := adminExposure(cfg); err != nil {
		return Config{}, err
	}
	cfg.CAFile = strings.TrimSpace(os.Getenv(tlsca.EnvCAFile))
	if _, err := tlsca.Load(cfg.CAFile); err != nil {
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
	cfg.StatusFile = localstatus.PathFromEnv()
	stateDirForCheck := cfg.StateDir
	if stateDirForCheck == "" {
		stateDirForCheck = state.DefaultStateDir
	}
	if err := localstatus.CheckOutside(cfg.StatusFile, stateDirForCheck); err != nil {
		return Config{}, err
	}
	if v := os.Getenv("DATABASE_URL"); v != "" {
		// SQLite is gone: ignoring the variable would let the operator believe a database is
		// still in use, so this is an error, not a warning (unlike the obsolete NATS_URL).
		return Config{}, ErrDatabaseURLRemoved
	}
	max, err := state.MaxBytesFromEnv()
	if err != nil {
		return Config{}, err
	}
	cfg.StateMaxBytes = max
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

// ErrStateReplayed: the state file is older than the write_seq published by the previous master.
var ErrStateReplayed = errors.New("state replay refused: relay.state is older than the previous master's last write (#163)")

// ErrLockLost is returned by Run after Abort: the master lock was lost, the process must exit.
var ErrLockLost = errors.New("master lock lost")
