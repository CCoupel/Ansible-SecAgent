package state

import (
	"fmt"
	"log/slog"
	"strings"
	"time"
)

// Tx is the handle a mutation function receives. Every write goes through it: it is recorded in
// an undo log, so a mutation that returns an error (or violates an invariant) leaves NO trace in
// the batch it belongs to. Reads see the batch as built so far.
type Tx struct {
	m       *model
	undo    []func()
	relays  map[string]struct{} // relay ids touched (revocation invariant)
	opts    *Options
	started time.Time
}

func newTx(m *model, o *Options) *Tx {
	return &Tx{m: m, opts: o, relays: map[string]struct{}{}, started: o.now()}
}

func (t *Tx) rollback() {
	for i := len(t.undo) - 1; i >= 0; i-- {
		t.undo[i]()
	}
	t.undo = nil
}

// finish checks the cross-entity invariants of what this mutation touched.
func (t *Tx) finish() error {
	for id := range t.relays {
		if err := t.m.checkRevokedBlacklisted(id, t.started); err != nil {
			return err
		}
	}
	return nil
}

func put[V any](t *Tx, mp map[string]V, key string, v V) {
	old, had := mp[key]
	mp[key] = v
	t.undo = append(t.undo, func() {
		if had {
			mp[key] = old
		} else {
			delete(mp, key)
		}
	})
}

func del[V any](t *Tx, mp map[string]V, key string) {
	old, had := mp[key]
	if !had {
		return
	}
	delete(mp, key)
	t.undo = append(t.undo, func() { mp[key] = old })
}

// index helpers: idx maps a unique attribute to the owner key.
func idxSet(t *Tx, idx map[string]string, attr, owner string) {
	if attr == "" {
		return
	}
	put(t, idx, attr, owner)
}
func idxDel(t *Tx, idx map[string]string, attr string) {
	if attr == "" {
		return
	}
	del(t, idx, attr)
}

// ── agents ───────────────────────────────────────────────────────────────────

func (t *Tx) Agent(hostname string) (Agent, bool) {
	a, ok := t.m.Agents[hostname]
	return a.clone(), ok
}

func (t *Tx) PutAgent(a Agent) error {
	if a.Hostname == "" {
		return fmt.Errorf("%w: agent without hostname", ErrInvalid)
	}
	put(t, t.m.Agents, a.Hostname, a.clone())
	return nil
}

func (t *Tx) DeleteAgent(hostname string) bool {
	_, ok := t.m.Agents[hostname]
	del(t, t.m.Agents, hostname)
	return ok
}

// ── authorized keys ──────────────────────────────────────────────────────────

func (t *Tx) AuthorizedKey(hostname string) (AuthorizedKey, bool) {
	k, ok := t.m.AuthorizedKeys[hostname]
	return k, ok
}

func (t *Tx) PutAuthorizedKey(k AuthorizedKey) error {
	if k.Hostname == "" || k.PublicKeyPEM == "" {
		return fmt.Errorf("%w: authorized key needs hostname and public_key_pem", ErrInvalid)
	}
	put(t, t.m.AuthorizedKeys, k.Hostname, k)
	return nil
}

func (t *Tx) DeleteAuthorizedKey(hostname string) bool {
	_, ok := t.m.AuthorizedKeys[hostname]
	del(t, t.m.AuthorizedKeys, hostname)
	return ok
}

// ── enrollment tokens ────────────────────────────────────────────────────────

func (t *Tx) EnrollmentToken(id string) (EnrollmentToken, bool) {
	v, ok := t.m.EnrollmentTokens[id]
	return v.clone(), ok
}

func (t *Tx) EnrollmentTokenByHash(hash string) (EnrollmentToken, bool) {
	id, ok := t.m.enrollByHash[hash]
	if !ok {
		return EnrollmentToken{}, false
	}
	return t.EnrollmentToken(id)
}

func (t *Tx) PutEnrollmentToken(v EnrollmentToken) error {
	if err := checkEnrollmentToken(v.ID, v); err != nil {
		return err
	}
	if owner, dup := t.m.enrollByHash[v.TokenHash]; dup && owner != v.ID {
		return fmt.Errorf("%w: enrollment token_hash already used by %q", ErrDuplicate, owner)
	}
	if old, had := t.m.EnrollmentTokens[v.ID]; had && old.TokenHash != v.TokenHash {
		idxDel(t, t.m.enrollByHash, old.TokenHash)
	}
	idxSet(t, t.m.enrollByHash, v.TokenHash, v.ID)
	put(t, t.m.EnrollmentTokens, v.ID, v.clone())
	return nil
}

func (t *Tx) DeleteEnrollmentToken(id string) bool {
	old, ok := t.m.EnrollmentTokens[id]
	if !ok {
		return false
	}
	idxDel(t, t.m.enrollByHash, old.TokenHash)
	del(t, t.m.EnrollmentTokens, id)
	return true
}

// ── plugin tokens ────────────────────────────────────────────────────────────

func (t *Tx) PluginToken(id string) (PluginToken, bool) {
	v, ok := t.m.PluginTokens[id]
	return v.clone(), ok
}

func (t *Tx) PluginTokenByHash(hash string) (PluginToken, bool) {
	id, ok := t.m.pluginByHash[hash]
	if !ok {
		return PluginToken{}, false
	}
	return t.PluginToken(id)
}

func (t *Tx) PutPluginToken(v PluginToken) error {
	if err := checkPluginToken(v.ID, v); err != nil {
		return err
	}
	if owner, dup := t.m.pluginByHash[v.TokenHash]; dup && owner != v.ID {
		return fmt.Errorf("%w: plugin token_hash already used by %q", ErrDuplicate, owner)
	}
	if old, had := t.m.PluginTokens[v.ID]; had && old.TokenHash != v.TokenHash {
		idxDel(t, t.m.pluginByHash, old.TokenHash)
	}
	idxSet(t, t.m.pluginByHash, v.TokenHash, v.ID)
	put(t, t.m.PluginTokens, v.ID, v.clone())
	return nil
}

func (t *Tx) DeletePluginToken(id string) bool {
	old, ok := t.m.PluginTokens[id]
	if !ok {
		return false
	}
	idxDel(t, t.m.pluginByHash, old.TokenHash)
	del(t, t.m.PluginTokens, id)
	return true
}

// ── relay-parent tokens ──────────────────────────────────────────────────────

func (t *Tx) RelayParentToken(id string) (RelayParentToken, bool) {
	v, ok := t.m.RelayParentTokens[id]
	return v.clone(), ok
}

func (t *Tx) PutRelayParentToken(v RelayParentToken) error {
	if err := checkRelayParentToken(v.ID, v); err != nil {
		return err
	}
	if owner, dup := t.m.parentByJTI[v.JTI]; dup && owner != v.ID {
		return fmt.Errorf("%w: relay-parent jti already used by %q", ErrDuplicate, owner)
	}
	if old, had := t.m.RelayParentTokens[v.ID]; had && old.JTI != v.JTI {
		idxDel(t, t.m.parentByJTI, old.JTI)
	}
	idxSet(t, t.m.parentByJTI, v.JTI, v.ID)
	put(t, t.m.RelayParentTokens, v.ID, v.clone())
	return nil
}

func (t *Tx) DeleteRelayParentToken(id string) bool {
	old, ok := t.m.RelayParentTokens[id]
	if !ok {
		return false
	}
	idxDel(t, t.m.parentByJTI, old.JTI)
	del(t, t.m.RelayParentTokens, id)
	return true
}

// ── blacklist ────────────────────────────────────────────────────────────────

func (t *Tx) Blacklisted(jti string) bool { _, ok := t.m.Blacklist[jti]; return ok }

func (t *Tx) PutBlacklist(b BlacklistEntry) error {
	if err := checkBlacklist(b.JTI, b); err != nil {
		return err
	}
	put(t, t.m.Blacklist, b.JTI, b)
	return nil
}

// PurgeExpiredBlacklist drops the entries whose expiry is not after now (bounds the file size).
func (t *Tx) PurgeExpiredBlacklist(now time.Time) int {
	n := 0
	for jti, b := range t.m.Blacklist {
		if !b.ExpiresAt.After(now) {
			del(t, t.m.Blacklist, jti)
			n++
		}
	}
	return n
}

// ── relay nodes ──────────────────────────────────────────────────────────────

func (t *Tx) RelayNode(relayID string) (RelayNode, bool) {
	v, ok := t.m.RelayNodes[relayID]
	return v.clone(), ok
}

func (t *Tx) RelayNodeByID(id string) (RelayNode, bool) {
	rid, ok := t.m.relayByID[id]
	if !ok {
		return RelayNode{}, false
	}
	return t.RelayNode(rid)
}

func (t *Tx) PutRelayNode(v RelayNode) error {
	if err := checkRelayNode(v.RelayID, v); err != nil {
		return err
	}
	if owner, dup := t.m.relayByID[v.ID]; dup && owner != v.RelayID {
		return fmt.Errorf("%w: relay node id already used by %q", ErrDuplicate, owner)
	}
	if v.TokenHash != "" {
		if owner, dup := t.m.relayByTokHsh[v.TokenHash]; dup && owner != v.RelayID {
			return fmt.Errorf("%w: relay token_hash already used by %q", ErrDuplicate, owner)
		}
	}
	old, had := t.m.RelayNodes[v.RelayID]
	if !had && v.Mode == ModePull && v.TokenHash == "" {
		slog.Info(fmt.Sprintf("pull relay %q registered without token_hash — JWT-only auth", v.RelayID))
	}
	if had {
		if old.ID != v.ID {
			idxDel(t, t.m.relayByID, old.ID)
		}
		if old.TokenHash != v.TokenHash {
			idxDel(t, t.m.relayByTokHsh, old.TokenHash)
		}
	}
	idxSet(t, t.m.relayByID, v.ID, v.RelayID)
	idxSet(t, t.m.relayByTokHsh, v.TokenHash, v.RelayID)
	put(t, t.m.RelayNodes, v.RelayID, v.clone())
	t.relays[v.RelayID] = struct{}{}
	return nil
}

func (t *Tx) DeleteRelayNode(relayID string) bool {
	old, ok := t.m.RelayNodes[relayID]
	if !ok {
		return false
	}
	idxDel(t, t.m.relayByID, old.ID)
	idxDel(t, t.m.relayByTokHsh, old.TokenHash)
	del(t, t.m.RelayNodes, relayID)
	return true
}

// ── server config ────────────────────────────────────────────────────────────

func (t *Tx) Config(key string) (string, bool) { v, ok := t.m.ServerConfig[key]; return v, ok }

// SetConfig stores a server_config value. A secret key is refused unless its value is
// "enc:"-prefixed (clear values only in explicit test mode without a master key): the engine must
// never write a file it would refuse to load.
func (t *Tx) SetConfig(key, value string) error {
	if key == "" {
		return fmt.Errorf("%w: empty config key", ErrInvalid)
	}
	if !t.opts.clearSecretsAllowed() && secretConfigKeys[key] && value != "" && !strings.HasPrefix(value, EncPrefix) {
		return fmt.Errorf("%w: refusing to write %q in clear (secrets are stored encrypted; clear only in explicit test mode without a master key)", ErrInvalid, key)
	}
	put(t, t.m.ServerConfig, key, value)
	return nil
}

func (t *Tx) DeleteConfig(key string) { del(t, t.m.ServerConfig, key) }
