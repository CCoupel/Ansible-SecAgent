package state

import (
	"fmt"
	"strings"
	"time"
)

// Relay node modes.
const (
	ModePull = "pull"
	ModePush = "push"
)

// EncPrefix marks an encrypted secret (AES-256-GCM, RSA_MASTER_KEY).
const EncPrefix = "enc:"

// Keys of server_config whose value is a secret: they are encrypted field by field as soon as a
// master key is configured (and never written in clear then).
var secretConfigKeys = map[string]bool{
	"rsa_key_current":     true,
	"rsa_key_previous":    true,
	"jwt_secret_current":  true,
	"jwt_secret_previous": true,
}

// IsSecretConfigKey reports whether a server_config key holds a secret.
func IsSecretConfigKey(k string) bool { return secretConfigKeys[k] }

// Entities. Every value stored in the model is immutable: a mutation replaces the whole value
// (Tx.Put* deep-copies its argument), which makes the copy-on-write of a batch a cheap map copy.

// Agent is an enrolled minion. LastSeen/Status are volatile: they are only persisted when the
// file is written for another reason (piggyback, see Options.Piggyback).
type Agent struct {
	Hostname     string    `json:"hostname"`
	PublicKeyPEM string    `json:"public_key_pem"`
	TokenJTI     string    `json:"token_jti,omitempty"`
	EnrolledAt   time.Time `json:"enrolled_at"`
	Suspended    bool      `json:"suspended,omitempty"`
	// Revoked (#193) is set by the revocation, in the same write as the JTI blacklist, and survives the
	// expiry of that blacklist entry: a revoked host is refused by every path that would give it a
	// JWT/JTI (enrollment included) until an admin lifts it explicitly (DELETE of the agent). Optional
	// at read: a state written before this field existed simply has it false (schema_version unchanged).
	Revoked  bool           `json:"revoked,omitempty"`
	Vars     map[string]any `json:"vars,omitempty"`
	LastSeen *time.Time     `json:"last_seen,omitempty"`
}

// AuthorizedKey is a pre-authorized public key.
type AuthorizedKey struct {
	Hostname     string    `json:"hostname"`
	PublicKeyPEM string    `json:"public_key_pem"`
	ApprovedAt   time.Time `json:"approved_at"`
	ApprovedBy   string    `json:"approved_by"`
}

// EnrollmentToken: only the SHA-256 of the token is stored.
type EnrollmentToken struct {
	ID              string     `json:"id"`
	TokenHash       string     `json:"token_hash"`
	HostnamePattern string     `json:"hostname_pattern"`
	Reusable        bool       `json:"reusable,omitempty"`
	UseCount        int        `json:"use_count,omitempty"`
	LastUsedAt      *time.Time `json:"last_used_at,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	ExpiresAt       *time.Time `json:"expires_at,omitempty"`
	CreatedBy       string     `json:"created_by,omitempty"`
}

// PluginToken: only the SHA-256 of the token is stored.
type PluginToken struct {
	ID                     string     `json:"id"`
	TokenHash              string     `json:"token_hash"`
	Description            string     `json:"description,omitempty"`
	Role                   string     `json:"role"`
	AllowedIPs             string     `json:"allowed_ips,omitempty"`
	AllowedHostnamePattern string     `json:"allowed_hostname_pattern,omitempty"`
	CreatedAt              time.Time  `json:"created_at"`
	ExpiresAt              *time.Time `json:"expires_at,omitempty"`
	Revoked                bool       `json:"revoked,omitempty"`
	LastUsedAt             *time.Time `json:"last_used_at,omitempty"`
	LastUsedIP             string     `json:"last_used_ip,omitempty"`
}

// RelayParentToken: metadata of a relay-parent token (never the JWT itself).
type RelayParentToken struct {
	ID          string     `json:"id"`
	JTI         string     `json:"jti"`
	ParentID    string     `json:"parent_id"`
	Description string     `json:"description,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	ExpiresAt   time.Time  `json:"expires_at"`
	RevokedAt   *time.Time `json:"revoked_at,omitempty"`
}

// BlacklistEntry is a revoked JWT identifier.
type BlacklistEntry struct {
	JTI       string    `json:"jti"`
	Hostname  string    `json:"hostname,omitempty"`
	RevokedAt time.Time `json:"revoked_at"`
	Reason    string    `json:"reason,omitempty"`
	ExpiresAt time.Time `json:"expires_at"`
}

// RelayNode is the CONFIGURATION of a child relay. Its status, last_seen and relay_chain are
// volatile (rebuilt by the topology snapshots) and never stored here.
type RelayNode struct {
	ID          string         `json:"id"`
	RelayID     string         `json:"relay_id"`
	URLs        []string       `json:"urls,omitempty"`
	Description string         `json:"description,omitempty"`
	Mode        string         `json:"mode"`
	IsProxy     bool           `json:"is_proxy,omitempty"`
	CreatedAt   time.Time      `json:"created_at"`
	JTI         string         `json:"jti,omitempty"`
	TokenExp    int64          `json:"token_exp,omitempty"`
	Revoked     bool           `json:"revoked,omitempty"`
	GroupVars   map[string]any `json:"group_vars,omitempty"`
	// TokenHash (pull: SHA-256 of the relay token) and TokenSecret (push: the token the parent
	// presents to the child, ALWAYS "enc:"-prefixed) are distinct fields.
	TokenHash   string `json:"token_hash,omitempty"`
	TokenSecret string `json:"token_secret,omitempty"`
}

// Payload is the permanent content of the state file. Keys: hostname, id, jti, relay_id, key.
type Payload struct {
	Agents            map[string]Agent            `json:"agents"`
	AuthorizedKeys    map[string]AuthorizedKey    `json:"authorized_keys"`
	EnrollmentTokens  map[string]EnrollmentToken  `json:"enrollment_tokens"`
	PluginTokens      map[string]PluginToken      `json:"plugin_tokens"`
	RelayParentTokens map[string]RelayParentToken `json:"relay_parent_tokens"`
	Blacklist         map[string]BlacklistEntry   `json:"blacklist"`
	RelayNodes        map[string]RelayNode        `json:"relay_nodes"`
	ServerConfig      map[string]string           `json:"server_config"`
}

func newPayload() Payload {
	return Payload{
		Agents:            map[string]Agent{},
		AuthorizedKeys:    map[string]AuthorizedKey{},
		EnrollmentTokens:  map[string]EnrollmentToken{},
		PluginTokens:      map[string]PluginToken{},
		RelayParentTokens: map[string]RelayParentToken{},
		Blacklist:         map[string]BlacklistEntry{},
		RelayNodes:        map[string]RelayNode{},
		ServerConfig:      map[string]string{},
	}
}

// model is the in-memory state: the payload plus the unique/secondary indexes.
type model struct {
	Payload
	seq uint64

	enrollByHash  map[string]string // token_hash → enrollment token id
	pluginByHash  map[string]string // token_hash → plugin token id
	parentByJTI   map[string]string // jti → relay-parent token id
	relayByID     map[string]string // relay node uuid → relay_id
	relayByTokHsh map[string]string // pull token_hash → relay_id (when set)
}

func cloneMap[V any](m map[string]V) map[string]V {
	out := make(map[string]V, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// clone copies the maps (values are immutable: no deep copy needed).
func (m *model) clone() *model {
	return &model{
		Payload: Payload{
			Agents:            cloneMap(m.Agents),
			AuthorizedKeys:    cloneMap(m.AuthorizedKeys),
			EnrollmentTokens:  cloneMap(m.EnrollmentTokens),
			PluginTokens:      cloneMap(m.PluginTokens),
			RelayParentTokens: cloneMap(m.RelayParentTokens),
			Blacklist:         cloneMap(m.Blacklist),
			RelayNodes:        cloneMap(m.RelayNodes),
			ServerConfig:      cloneMap(m.ServerConfig),
		},
		seq:           m.seq,
		enrollByHash:  cloneMap(m.enrollByHash),
		pluginByHash:  cloneMap(m.pluginByHash),
		parentByJTI:   cloneMap(m.parentByJTI),
		relayByID:     cloneMap(m.relayByID),
		relayByTokHsh: cloneMap(m.relayByTokHsh),
	}
}

func cloneAny(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			out[k] = cloneAny(e)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = cloneAny(e)
		}
		return out
	default:
		return v
	}
}

func cloneVars(m map[string]any) map[string]any {
	if m == nil {
		return nil
	}
	return cloneAny(m).(map[string]any)
}

func cloneTime(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	c := *t
	return &c
}

func (a Agent) clone() Agent {
	a.Vars = cloneVars(a.Vars)
	a.LastSeen = cloneTime(a.LastSeen)
	return a
}
func (t EnrollmentToken) clone() EnrollmentToken {
	t.LastUsedAt, t.ExpiresAt = cloneTime(t.LastUsedAt), cloneTime(t.ExpiresAt)
	return t
}
func (t PluginToken) clone() PluginToken {
	t.LastUsedAt, t.ExpiresAt = cloneTime(t.LastUsedAt), cloneTime(t.ExpiresAt)
	return t
}
func (t RelayParentToken) clone() RelayParentToken { t.RevokedAt = cloneTime(t.RevokedAt); return t }
func (n RelayNode) clone() RelayNode {
	n.URLs = append([]string(nil), n.URLs...)
	n.GroupVars = cloneVars(n.GroupVars)
	return n
}

// buildIndexes (re)builds the indexes of a freshly decoded payload and checks uniqueness.
func (m *model) buildIndexes() error {
	m.enrollByHash = make(map[string]string, len(m.EnrollmentTokens))
	m.pluginByHash = make(map[string]string, len(m.PluginTokens))
	m.parentByJTI = make(map[string]string, len(m.RelayParentTokens))
	m.relayByID = make(map[string]string, len(m.RelayNodes))
	m.relayByTokHsh = make(map[string]string)
	for id, t := range m.EnrollmentTokens {
		if other, dup := m.enrollByHash[t.TokenHash]; dup {
			return fmt.Errorf("%w: enrollment token_hash shared by %q and %q", ErrDuplicate, other, id)
		}
		m.enrollByHash[t.TokenHash] = id
	}
	for id, t := range m.PluginTokens {
		if other, dup := m.pluginByHash[t.TokenHash]; dup {
			return fmt.Errorf("%w: plugin token_hash shared by %q and %q", ErrDuplicate, other, id)
		}
		m.pluginByHash[t.TokenHash] = id
	}
	for id, t := range m.RelayParentTokens {
		if other, dup := m.parentByJTI[t.JTI]; dup {
			return fmt.Errorf("%w: relay-parent jti shared by %q and %q", ErrDuplicate, other, id)
		}
		m.parentByJTI[t.JTI] = id
	}
	for rid, n := range m.RelayNodes {
		if other, dup := m.relayByID[n.ID]; dup {
			return fmt.Errorf("%w: relay node id shared by %q and %q", ErrDuplicate, other, rid)
		}
		m.relayByID[n.ID] = rid
		if n.TokenHash != "" {
			if other, dup := m.relayByTokHsh[n.TokenHash]; dup {
				return fmt.Errorf("%w: relay token_hash shared by %q and %q", ErrDuplicate, other, rid)
			}
			m.relayByTokHsh[n.TokenHash] = rid
		}
	}
	return nil
}

// checkEntries validates every map key against its entity (a file edited by hand or damaged
// must not load with a key that disagrees with its content).
func (m *model) checkEntries() error {
	for k, a := range m.Agents {
		if k == "" || a.Hostname != k {
			return fmt.Errorf("%w: agent key %q does not match hostname %q", ErrInvalid, k, a.Hostname)
		}
	}
	for k, a := range m.AuthorizedKeys {
		if k == "" || a.Hostname != k {
			return fmt.Errorf("%w: authorized key %q does not match hostname %q", ErrInvalid, k, a.Hostname)
		}
	}
	for k, t := range m.EnrollmentTokens {
		if err := checkEnrollmentToken(k, t); err != nil {
			return err
		}
	}
	for k, t := range m.PluginTokens {
		if err := checkPluginToken(k, t); err != nil {
			return err
		}
	}
	for k, t := range m.RelayParentTokens {
		if err := checkRelayParentToken(k, t); err != nil {
			return err
		}
	}
	for k, b := range m.Blacklist {
		if err := checkBlacklist(k, b); err != nil {
			return err
		}
	}
	return nil
}

func checkEnrollmentToken(k string, t EnrollmentToken) error {
	if k == "" || t.ID != k || t.TokenHash == "" || t.HostnamePattern == "" {
		return fmt.Errorf("%w: enrollment token %q needs id, token_hash and hostname_pattern", ErrInvalid, k)
	}
	return nil
}

func checkPluginToken(k string, t PluginToken) error {
	if k == "" || t.ID != k || t.TokenHash == "" || t.Role == "" {
		return fmt.Errorf("%w: plugin token %q needs id, token_hash and role", ErrInvalid, k)
	}
	return nil
}

func checkRelayParentToken(k string, t RelayParentToken) error {
	if k == "" || t.ID != k || t.JTI == "" || t.ParentID == "" {
		return fmt.Errorf("%w: relay-parent token %q needs id, jti and parent_id", ErrInvalid, k)
	}
	return nil
}

func checkBlacklist(k string, b BlacklistEntry) error {
	if k == "" || b.JTI != k || b.ExpiresAt.IsZero() {
		return fmt.Errorf("%w: blacklist entry %q needs jti and expires_at", ErrInvalid, k)
	}
	return nil
}

// checkRelayNode validates one relay node. A clear-text push token_secret is a SECURITY
// invariant violation (ErrSecurityInvariant), not a plain corruption.
func checkRelayNode(k string, n RelayNode) error {
	if k == "" || n.RelayID != k || n.ID == "" {
		return fmt.Errorf("%w: relay node %q needs relay_id and id", ErrInvalid, k)
	}
	switch n.Mode {
	case ModePull:
		if n.TokenSecret != "" {
			return fmt.Errorf("%w: pull relay %q must not carry a token_secret", ErrInvalid, k)
		}
	case ModePush:
		if n.TokenHash != "" {
			return fmt.Errorf("%w: push relay %q must not carry a token_hash", ErrInvalid, k)
		}
		if n.TokenSecret == "" {
			return fmt.Errorf("%w: push relay %q needs a token_secret", ErrInvalid, k)
		}
		if !strings.HasPrefix(n.TokenSecret, EncPrefix) || len(n.TokenSecret) == len(EncPrefix) {
			return fmt.Errorf("%w: push relay %q token_secret is not encrypted (%q prefix required)", ErrSecurityInvariant, k, EncPrefix)
		}
	default:
		return fmt.Errorf("%w: relay %q has mode %q (pull|push)", ErrInvalid, k, n.Mode)
	}
	if n.Revoked && n.JTI == "" {
		return fmt.Errorf("%w: revoked relay %q has no jti to blacklist", ErrInvalid, k)
	}
	return nil
}

// checkRevokedBlacklisted: a revoked relay whose token is still valid must have its jti in the
// blacklist. (An expired token needs no blacklist entry: the entry may have been purged.)
func (m *model) checkRevokedBlacklisted(relayID string, now time.Time) error {
	n, ok := m.RelayNodes[relayID]
	if !ok || !n.Revoked {
		return nil
	}
	if n.TokenExp > 0 && n.TokenExp <= now.Unix() {
		return nil
	}
	if _, bl := m.Blacklist[n.JTI]; !bl {
		return fmt.Errorf("%w: revoked relay %q: its jti is not blacklisted", ErrInvalid, relayID)
	}
	return nil
}

// validateAll is the full check run when a file is loaded.
func (m *model) validateAll(now time.Time) error {
	for k, n := range m.RelayNodes {
		if err := checkRelayNode(k, n); err != nil {
			return err
		}
	}
	if err := m.checkEntries(); err != nil {
		return err
	}
	if err := m.buildIndexes(); err != nil {
		return err
	}
	for k := range m.RelayNodes {
		if err := m.checkRevokedBlacklisted(k, now); err != nil {
			return err
		}
	}
	return nil
}
