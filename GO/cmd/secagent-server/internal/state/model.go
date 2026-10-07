package state

import (
	"encoding/base64"
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
	// link signing keys (v3.0.4, #141): the Ed25519 private key of the root, which signs the link
	// tokens. Same encryption as the other secrets (enc:, AAD = field name).
	ConfigLinkSigningKeyCurrent:  true,
	ConfigLinkSigningKeyPrevious: true,
}

// server_config keys holding the link signing key (root only).
const (
	ConfigLinkSigningKeyCurrent  = "link_signing_key_current"
	ConfigLinkSigningKeyPrevious = "link_signing_key_previous"
)

// Roles of a link token (signed by the root, #141/#146).
const (
	RoleRelayChild  = "relay-child"  // presented by the child to its parent (pull)
	RoleRelayParent = "relay-parent" // presented by the parent to its child (push)
)

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

// LinkToken is the registry entry of a link token minted by the root (schema v2, root only): the
// metadata for audit, listing and revocation. Never the token itself, nor its hash (the signature
// is what authenticates it). A revoked token (RevokedAt set) whose JTI has not expired is blacklisted
// in the SAME mutation.
type LinkToken struct {
	ID          string     `json:"id"`
	JTI         string     `json:"jti"`
	Role        string     `json:"role"` // RoleRelayChild | RoleRelayParent
	Sub         string     `json:"sub"`  // the presenter
	Aud         string     `json:"aud"`  // the verifier
	KID         string     `json:"kid"`  // signing key that signed it
	CreatedAt   time.Time  `json:"created_at"`
	ExpiresAt   time.Time  `json:"expires_at"`
	RevokedAt   *time.Time `json:"revoked_at,omitempty"`
	CreatedBy   string     `json:"created_by,omitempty"`
	Description string     `json:"description,omitempty"`
}

// LinkTrust is the trust anchor of a non-root relay (schema v2): the relay_id of the root (the
// expected "iss"), its PUBLIC link keys (current and previous, base64url WITHOUT padding of the 32
// raw Ed25519 bytes: the encoding of the link_keys wire message, with their kid) and the sequence
// number of the last link message accepted (anti-replay). Public data: never encrypted. The zero value
// means "no anchor": a non-root relay then refuses every incoming link (fail closed).
type LinkTrust struct {
	RootID      string `json:"root_id,omitempty"`
	CurrentPub  string `json:"current_pub,omitempty"`
	CurrentKID  string `json:"current_kid,omitempty"`
	PreviousPub string `json:"previous_pub,omitempty"`
	PreviousKID string `json:"previous_kid,omitempty"`
	Seq         uint64 `json:"seq,omitempty"`
}

// IsZero reports whether no anchor is recorded.
func (l LinkTrust) IsZero() bool { return l == LinkTrust{} }

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
	// schema v2 (absent from a v1 file, which reads as empty)
	LinkTokens map[string]LinkToken `json:"link_tokens"`
	LinkTrust  LinkTrust            `json:"link_trust"`
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
		LinkTokens:        map[string]LinkToken{},
	}
}

// model is the in-memory state: the payload plus the unique/secondary indexes.
type model struct {
	Payload
	seq uint64
	// schema is the schema_version of the file this model was loaded from (1: to be migrated by the
	// first write; 0 or SchemaVersion: current).
	schema int

	enrollByHash  map[string]string // token_hash → enrollment token id
	pluginByHash  map[string]string // token_hash → plugin token id
	parentByJTI   map[string]string // jti → relay-parent token id
	relayByID     map[string]string // relay node uuid → relay_id
	relayByTokHsh map[string]string // pull token_hash → relay_id (when set)
	linkByJTI     map[string]string // jti → link token id
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
			LinkTokens:        cloneMap(m.LinkTokens),
			LinkTrust:         m.LinkTrust,
		},
		seq:           m.seq,
		schema:        m.schema,
		linkByJTI:     cloneMap(m.linkByJTI),
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
func (t LinkToken) clone() LinkToken               { t.RevokedAt = cloneTime(t.RevokedAt); return t }
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
	m.linkByJTI = make(map[string]string, len(m.LinkTokens))
	for id, t := range m.LinkTokens {
		if other, dup := m.linkByJTI[t.JTI]; dup {
			return fmt.Errorf("%w: link token jti shared by %q and %q", ErrDuplicate, other, id)
		}
		m.linkByJTI[t.JTI] = id
	}
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
	for k, t := range m.LinkTokens {
		if err := checkLinkToken(k, t); err != nil {
			return err
		}
	}
	return nil
}

func checkLinkToken(k string, t LinkToken) error {
	if k == "" || t.ID != k || t.JTI == "" || t.Sub == "" || t.Aud == "" || t.KID == "" || t.ExpiresAt.IsZero() {
		return fmt.Errorf("%w: link token %q needs id, jti, sub, aud, kid and expires_at", ErrInvalid, k)
	}
	if t.Role != RoleRelayChild && t.Role != RoleRelayParent {
		return fmt.Errorf("%w: link token %q has role %q (%s|%s)", ErrInvalid, k, t.Role, RoleRelayChild, RoleRelayParent)
	}
	return nil
}

// checkLinkTrust validates the internal coherence of a trust anchor: a public key and its kid go
// together, a public key is a base64 Ed25519 key (32 bytes), "previous" and the sequence number
// need a "current", and the two kids differ.
func checkLinkTrust(l LinkTrust) error {
	for _, s := range []struct{ name, pub, kid string }{
		{"current", l.CurrentPub, l.CurrentKID}, {"previous", l.PreviousPub, l.PreviousKID},
	} {
		if (s.pub == "") != (s.kid == "") {
			return fmt.Errorf("%w: link_trust %s needs both a public key and a kid", ErrInvalid, s.name)
		}
		if s.pub != "" {
			raw, err := base64.RawURLEncoding.DecodeString(s.pub)
			if err != nil || len(raw) != 32 {
				return fmt.Errorf("%w: link_trust %s public key is not a base64url Ed25519 key (32 bytes)", ErrInvalid, s.name)
			}
		}
	}
	if l.CurrentPub != "" && l.RootID == "" {
		return fmt.Errorf("%w: link_trust has a public key but no root_id", ErrInvalid)
	}
	if l.CurrentPub == "" && (l.PreviousPub != "" || l.Seq != 0 || l.RootID != "") {
		return fmt.Errorf("%w: link_trust has a previous key or a sequence number but no current key", ErrInvalid)
	}
	if l.PreviousKID != "" && l.PreviousKID == l.CurrentKID {
		return fmt.Errorf("%w: link_trust current and previous kid are identical", ErrInvalid)
	}
	return nil
}

// checkLinks is the cross-section coherence of the link data: the previous signing key needs a
// current one, a registry of link tokens needs the key that signed them, and a revoked link token
// whose JTI has not expired is blacklisted (the same rule as a revoked relay).
func (m *model) checkLinks(now time.Time) error {
	if err := checkLinkTrust(m.LinkTrust); err != nil {
		return err
	}
	cur, prev := m.ServerConfig[ConfigLinkSigningKeyCurrent], m.ServerConfig[ConfigLinkSigningKeyPrevious]
	if prev != "" && cur == "" {
		return fmt.Errorf("%w: %s is set without %s", ErrInvalid, ConfigLinkSigningKeyPrevious, ConfigLinkSigningKeyCurrent)
	}
	if len(m.LinkTokens) > 0 && cur == "" {
		return fmt.Errorf("%w: link tokens are registered but there is no %s", ErrInvalid, ConfigLinkSigningKeyCurrent)
	}
	for id, t := range m.LinkTokens {
		if t.RevokedAt == nil || !t.ExpiresAt.After(now) {
			continue
		}
		if _, bl := m.Blacklist[t.JTI]; !bl {
			return fmt.Errorf("%w: revoked link token %q: its jti is not blacklisted", ErrInvalid, id)
		}
	}
	return nil
}

// checkSchemaOne: a v1 file cannot carry anything of schema v2.
func (m *model) checkSchemaOne() error {
	if m.schema != 1 {
		return nil
	}
	if len(m.LinkTokens) > 0 || !m.LinkTrust.IsZero() ||
		m.ServerConfig[ConfigLinkSigningKeyCurrent] != "" || m.ServerConfig[ConfigLinkSigningKeyPrevious] != "" {
		return fmt.Errorf("%w: a schema_version 1 file carries schema 2 link data", ErrInvalid)
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
	return nil
}

// checkRelayJTI: a revoked relay needs a jti to blacklist (R6, schema 2). Since v3.0.4 the jti of a
// relay link lives in link_tokens (the relay node carries none): a revoked relay without jti is valid
// when a link token names it (sub or aud); the revocation of that token is what checkLinks ties to
// the blacklist.
func (m *model) checkRelayJTI(k string, n RelayNode) error {
	if !n.Revoked || n.JTI != "" {
		return nil
	}
	for _, t := range m.LinkTokens {
		if t.Sub == k || t.Aud == k {
			return nil
		}
	}
	return fmt.Errorf("%w: revoked relay %q has no jti to blacklist", ErrInvalid, k)
}

// checkRevokedBlacklisted: a revoked relay whose token is still valid must have its jti in the
// blacklist. (An expired token needs no blacklist entry: the entry may have been purged.)
func (m *model) checkRevokedBlacklisted(relayID string, now time.Time) error {
	n, ok := m.RelayNodes[relayID]
	if !ok || !n.Revoked {
		return nil
	}
	if n.JTI == "" {
		return nil // the jti of its link is in link_tokens (checkRelayJTI), whose revocation checkLinks ties to the blacklist
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
	if err := m.checkSchemaOne(); err != nil {
		return err
	}
	if err := m.checkEntries(); err != nil {
		return err
	}
	if err := m.buildIndexes(); err != nil {
		return err
	}
	if err := m.checkLinks(now); err != nil {
		return err
	}
	for k, n := range m.RelayNodes {
		if err := m.checkRelayJTI(k, n); err != nil {
			return err
		}
		if err := m.checkRevokedBlacklisted(k, now); err != nil {
			return err
		}
	}
	return nil
}
