// Package config reads the server configuration from environment variables.
package config

import (
	"errors"
	"fmt"
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
