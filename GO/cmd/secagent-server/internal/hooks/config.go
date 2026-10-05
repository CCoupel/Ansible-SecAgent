// Package hooks implements the event hooks system: loading a JSON config,
// dispatching events asynchronously, and executing typed actions
// (webhook / shell / file / api). See DOC/server/HOOKS_SPEC.md.
package hooks

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
)

// HooksConfig is the root of the hooks JSON configuration file.
type HooksConfig struct {
	Hooks []HookDef `json:"hooks"`
}

// HookDef maps an event type to a list of actions to execute.
// An optional Filter restricts the hook to events that travelled through a given relay (#126).
type HookDef struct {
	Event   string      `json:"event"`
	Filter  *HookFilter `json:"filter,omitempty"`
	Actions []ActionDef `json:"actions"`
}

// HookFilter restricts a hook. A nil filter always matches. RelayChainContains, when set, matches
// only events whose relay_chain (relays traversed since the origin) contains that relay id.
// An empty filter object is refused at load time (it would silently behave like "no filter").
type HookFilter struct {
	RelayChainContains string `json:"relay_chain_contains,omitempty"`
}

// relayIDPattern is the shape of a REPEATER_ID: also a safe value for templates and environment.
var relayIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,62}$`)

// Matches reports whether the filter accepts an event with the given relay_chain.
func (f *HookFilter) Matches(relayChain []string) bool {
	if f == nil || f.RelayChainContains == "" {
		return true
	}
	for _, id := range relayChain {
		if id == f.RelayChainContains {
			return true
		}
	}
	return false
}

// Validate checks the configuration. LoadConfig calls it: a configuration that does not validate
// is rejected as a whole (fail closed: the previous configuration, or none, stays in force).
func (c *HooksConfig) Validate() error {
	for i, h := range c.Hooks {
		if h.Event == "" {
			return fmt.Errorf("hook[%d]: missing event", i)
		}
		if h.Filter != nil {
			if h.Filter.RelayChainContains == "" {
				return fmt.Errorf("hook[%d] (%s): empty filter: set relay_chain_contains or remove the filter", i, h.Event)
			}
			if !relayIDPattern.MatchString(h.Filter.RelayChainContains) {
				return fmt.Errorf("hook[%d] (%s): relay_chain_contains %q is not a valid relay id", i, h.Event, h.Filter.RelayChainContains)
			}
		}
	}
	return nil
}

// ActionDef configures a single hook action.
// The Type field selects which executor is used:
//
//	"webhook" — HTTP POST with standardised JSON payload and HMAC signing
//	"shell"   — subprocess with env-var injection
//	"file"    — append templated text to a local file
//	"api"     — HTTP request with configurable method, headers, body
type ActionDef struct {
	Type           string            `json:"type"`          // webhook|shell|file|api
	URL            string            `json:"url,omitempty"` // webhook, api
	Secret         string            `json:"secret,omitempty"`
	Method         string            `json:"method,omitempty"`          // api (default GET)
	Headers        map[string]string `json:"headers,omitempty"`         // api
	Body           interface{}       `json:"body,omitempty"`            // api
	Cmd            string            `json:"cmd,omitempty"`             // shell
	Args           []string          `json:"args,omitempty"`            // shell
	Path           string            `json:"path,omitempty"`            // file
	Append         string            `json:"append,omitempty"`          // file
	MaxRetries     int               `json:"max_retries,omitempty"`     // webhook, api
	TimeoutSeconds int               `json:"timeout_seconds,omitempty"` // webhook, shell, api
}

const defaultConfigPath = "/etc/secagent-server/hooks.json"

// ConfigPath returns the hooks config file path.
// Reads RELAY_HOOKS_CONFIG env var; falls back to /etc/secagent-server/hooks.json.
func ConfigPath() string {
	if p := os.Getenv("RELAY_HOOKS_CONFIG"); p != "" {
		return p
	}
	return defaultConfigPath
}

// LoadConfig reads and parses the hooks JSON configuration file.
// Returns (nil, nil) when the file does not exist — not an error; the server
// starts normally with zero hooks active.
// Returns (nil, err) when the file exists but contains invalid JSON.
func LoadConfig(path string) (*HooksConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var cfg HooksConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}
