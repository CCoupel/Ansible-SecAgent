// Package config reads the server configuration from environment variables.
package config

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"regexp"
	"strings"

	"secagent-server/internal/endpoints"
)

// Environment variables describing the (single) parent of a child relay.
const (
	EnvRepeaterID            = "REPEATER_ID"
	EnvRepeaterUpstreamURL   = "REPEATER_UPSTREAM_URL"
	EnvRepeaterUpstreamToken = "REPEATER_UPSTREAM_TOKEN"
)

// repeaterIDPattern: REPEATER_ID is also an Ansible group name and a JWT sub,
// so restrict it to a safe charset.
var repeaterIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,62}$`)

// ErrInvalidRepeaterConfig wraps every validation failure of the repeater config.
var ErrInvalidRepeaterConfig = errors.New("invalid repeater configuration")

// RepeaterConfig is the configuration of a child relay opening a WSS link
// to its parent.
type RepeaterConfig struct {
	ID          string // REPEATER_ID (== jwt.sub, relay_chain element, Ansible group)
	UpstreamURL string // REPEATER_UPSTREAM_URL as given (wss://..., comma separated list accepted)
	// UpstreamURLs are the validated, normalized addresses of UpstreamURL (one per parent instance,
	// same token for all: the instances share their state, hence their secrets).
	UpstreamURLs  []string
	UpstreamToken string // REPEATER_UPSTREAM_TOKEN (secret, never logged)
}

// LogValue implements slog.LogValuer and redacts the token.
func (c RepeaterConfig) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("id", c.ID),
		slog.String("upstream_url", c.UpstreamURL),
		slog.String("upstream_token", "***"),
	)
}

// String redacts the token so the config is safe to print.
func (c RepeaterConfig) String() string {
	return fmt.Sprintf("RepeaterConfig{ID:%q UpstreamURL:%q UpstreamToken:***}", c.ID, c.UpstreamURL)
}

// GoString redacts the token for %#v.
func (c RepeaterConfig) GoString() string { return c.String() }

// LoadRepeaterConfig reads the environment. It returns (nil, nil) when
// REPEATER_UPSTREAM_URL is absent (standalone/root server), and an error when
// the variables are missing or inconsistent.
func LoadRepeaterConfig() (*RepeaterConfig, error) {
	return loadRepeaterConfig(os.Getenv)
}

func loadRepeaterConfig(getenv func(string) string) (*RepeaterConfig, error) {
	id := strings.TrimSpace(getenv(EnvRepeaterID))
	upstream := strings.TrimSpace(getenv(EnvRepeaterUpstreamURL))
	token := strings.TrimSpace(getenv(EnvRepeaterUpstreamToken))

	if upstream == "" {
		if token != "" {
			return nil, fmt.Errorf("%w: %s is set but %s is missing", ErrInvalidRepeaterConfig, EnvRepeaterUpstreamToken, EnvRepeaterUpstreamURL)
		}
		if id != "" && !repeaterIDPattern.MatchString(id) {
			return nil, fmt.Errorf("%w: %s %q must match %s", ErrInvalidRepeaterConfig, EnvRepeaterID, id, repeaterIDPattern)
		}
		return nil, nil
	}

	if id == "" {
		return nil, fmt.Errorf("%w: %s is required when %s is set", ErrInvalidRepeaterConfig, EnvRepeaterID, EnvRepeaterUpstreamURL)
	}
	if !repeaterIDPattern.MatchString(id) {
		return nil, fmt.Errorf("%w: %s %q must match %s", ErrInvalidRepeaterConfig, EnvRepeaterID, id, repeaterIDPattern)
	}
	if token == "" {
		return nil, fmt.Errorf("%w: %s is required when %s is set", ErrInvalidRepeaterConfig, EnvRepeaterUpstreamToken, EnvRepeaterUpstreamURL)
	}
	// A list of addresses (one per instance of the parent, #165): each one is validated alone.
	// The errors never echo an address: it may carry credentials.
	urls, err := endpoints.ParseSchemes(upstream, "wss")
	if err != nil {
		switch {
		case errors.Is(err, endpoints.ErrUserinfo):
			return nil, fmt.Errorf("%w: %s must not contain userinfo (credentials belong in %s)", ErrInvalidRepeaterConfig, EnvRepeaterUpstreamURL, EnvRepeaterUpstreamToken)
		case errors.Is(err, endpoints.ErrScheme):
			return nil, fmt.Errorf("%w: %s must use the wss:// scheme (TLS required)", ErrInvalidRepeaterConfig, EnvRepeaterUpstreamURL)
		default:
			return nil, fmt.Errorf("%w: %s is not a valid address list (%s)", ErrInvalidRepeaterConfig, EnvRepeaterUpstreamURL, strings.TrimPrefix(err.Error(), "endpoints: "))
		}
	}
	list := make([]string, len(urls))
	for i, u := range urls {
		list[i] = u.String()
	}
	return &RepeaterConfig{ID: id, UpstreamURL: upstream, UpstreamURLs: list, UpstreamToken: token}, nil
}

// IsRepeaterClientMode reports whether this node must open a link to a parent,
// i.e. REPEATER_UPSTREAM_URL is defined.
func IsRepeaterClientMode() bool {
	return strings.TrimSpace(os.Getenv(EnvRepeaterUpstreamURL)) != ""
}

// Environment variables of the trust anchor of a non-root relay (#141, L1e).
const (
	EnvRepeaterRootID          = "REPEATER_ROOT_ID"
	EnvRepeaterRootLinkKeyFile = "REPEATER_ROOT_LINK_KEY_FILE"

	maxRootLinkKeyFileSize = 4096
)

// LinkAnchorConfig is the root identity and the pinned root public key (the anchor). The key is
// public (exported by `keys link-pubkey`), so the file is not a secret: it only has to be a regular
// file nobody else can write (it is the root of trust of the whole subtree).
type LinkAnchorConfig struct {
	RootID string            // REPEATER_ROOT_ID: expected `iss` of every link token
	Key    ed25519.PublicKey // REPEATER_ROOT_LINK_KEY_FILE content; nil when not given
}

// LoadLinkAnchorConfig reads REPEATER_ROOT_ID / REPEATER_ROOT_LINK_KEY_FILE. It returns (nil, nil)
// when neither is set. A key file without a root id is refused (the id is part of the anchor);
// a root id alone is accepted (the key may already be persisted in link_trust).
func LoadLinkAnchorConfig() (*LinkAnchorConfig, error) {
	return loadLinkAnchorConfig(os.Getenv)
}

func loadLinkAnchorConfig(getenv func(string) string) (*LinkAnchorConfig, error) {
	id := strings.TrimSpace(getenv(EnvRepeaterRootID))
	path := strings.TrimSpace(getenv(EnvRepeaterRootLinkKeyFile))
	if id == "" && path == "" {
		return nil, nil
	}
	if id == "" {
		return nil, fmt.Errorf("%w: %s is required when %s is set", ErrInvalidRepeaterConfig, EnvRepeaterRootID, EnvRepeaterRootLinkKeyFile)
	}
	if !repeaterIDPattern.MatchString(id) {
		return nil, fmt.Errorf("%w: %s %q must match %s", ErrInvalidRepeaterConfig, EnvRepeaterRootID, id, repeaterIDPattern)
	}
	cfg := &LinkAnchorConfig{RootID: id}
	if path == "" {
		return cfg, nil
	}
	key, err := ReadRootLinkKeyFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrInvalidRepeaterConfig, EnvRepeaterRootLinkKeyFile, err)
	}
	cfg.Key = key
	return cfg, nil
}

// ReadRootLinkKeyFile reads a PEM "PUBLIC KEY" (PKIX) holding one Ed25519 public key. The file must
// be a regular file (no symbolic link), at most 4 KiB, and neither group- nor world-writable.
func ReadRootLinkKeyFile(path string) (ed25519.PublicKey, error) {
	li, err := os.Lstat(path)
	if err != nil {
		return nil, errors.New("cannot read the file")
	}
	if li.Mode()&os.ModeSymlink != 0 || !li.Mode().IsRegular() {
		return nil, errors.New("must be a regular file (no symbolic link)")
	}
	if li.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("file is writable by group or others (mode %04o)", li.Mode().Perm())
	}
	if li.Size() > maxRootLinkKeyFileSize {
		return nil, errors.New("file is too large")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.New("cannot read the file")
	}
	defer f.Close()
	if fi, err := f.Stat(); err != nil || !os.SameFile(li, fi) {
		return nil, errors.New("file changed while reading")
	}
	data, err := io.ReadAll(io.LimitReader(f, maxRootLinkKeyFileSize+1))
	if err != nil || len(data) > maxRootLinkKeyFileSize {
		return nil, errors.New("cannot read the file")
	}
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "PUBLIC KEY" || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, errors.New("expected exactly one PEM \"PUBLIC KEY\" block")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, errors.New("not a PKIX public key")
	}
	k, ok := pub.(ed25519.PublicKey)
	if !ok || len(k) != ed25519.PublicKeySize {
		return nil, errors.New("not an Ed25519 public key")
	}
	return k, nil
}
