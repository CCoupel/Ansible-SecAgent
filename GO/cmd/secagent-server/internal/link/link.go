// Package link is the link-token authority of a relay (v3.0.4, #141/#146): on the ROOT it holds the
// Ed25519 signing key (generated lazily, stored sealed enc: in server_config), mints and revokes the
// link tokens, rotates the key and builds the frames sent down the tree; on any node it builds the
// verification trust of /ws/relay. The signed formats live in auth/linkjwt.go and are not redefined.
package link

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"

	"secagent-server/cmd/secagent-server/internal/auth"
	"secagent-server/cmd/secagent-server/internal/state"
	"secagent-server/cmd/secagent-server/internal/storage"
)

// Errors mapped to HTTP statuses by the handlers.
var (
	ErrNotRoot        = errors.New("not_root")             // 409: this node has a parent
	ErrMasterKey      = errors.New("master_key_required")  // 503: no RSA_MASTER_KEY
	ErrNoTrust        = errors.New("link_trust_missing")   // no anchor to verify with
	ErrUnconfirmed    = errors.New("rotation_unconfirmed") // retire refused (R2)
	ErrPreviousOpen   = errors.New("previous_key_not_retired")
	ErrNoPrevious     = errors.New("no_previous_key")
	ErrInvalidRequest = errors.New("invalid_request")
)

// DefaultTTL is the default lifetime of a link token; MaxTTL its ceiling.
const (
	DefaultTTL = 720 * time.Hour
	MaxTTL     = 365 * 24 * time.Hour
)

// Manager is the link authority of one node.
type Manager struct {
	Store     *storage.Store
	MasterKey func() (string, bool) // RSA_MASTER_KEY
	LocalID   func() string         // relay_id of this node ("" = not configured)
	IsRoot    func() bool           // no REPEATER_UPSTREAM_URL
	// Broadcast sends a link frame to the connected children; CloseByJTI closes the local links of a
	// revoked token (4010); States returns the confirmations (link_state); Known lists the relays below.
	Broadcast  func(frame []byte)
	CloseByJTI func(jti string) int
	States     func() map[string]ConfirmedState
	Known      func() []string

	mu    sync.Mutex // serializes key operations and the emission of frames (ordered by seq)
	cache struct {
		sealed string
		priv   ed25519.PrivateKey
	}
	cacheP struct {
		sealed string
		priv   ed25519.PrivateKey
	}
}

// ConfirmedState is a relay's last reported link_state.
type ConfirmedState struct {
	Seq uint64
	KID string
}

func (m *Manager) root() bool { return m.IsRoot == nil || m.IsRoot() }

// open decrypts a sealed signing key (enc:, AAD = field name).
func (m *Manager) open(field, sealed string, c *struct {
	sealed string
	priv   ed25519.PrivateKey
}) (ed25519.PrivateKey, error) {
	if sealed == "" {
		return nil, nil
	}
	if c.sealed == sealed && c.priv != nil {
		return c.priv, nil
	}
	mk, ok := m.MasterKey()
	if !ok {
		return nil, ErrMasterKey
	}
	plain, err := state.OpenSecret(sealed, mk, state.ConfigAAD(field))
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", field, err) // never the value
	}
	raw, err := base64.RawURLEncoding.DecodeString(plain)
	if err != nil || len(raw) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%s is not an Ed25519 private key", field)
	}
	c.sealed, c.priv = sealed, ed25519.PrivateKey(raw)
	return c.priv, nil
}

func (m *Manager) seal(field string, priv ed25519.PrivateKey) (string, error) {
	mk, ok := m.MasterKey()
	if !ok {
		return "", ErrMasterKey
	}
	return state.SealSecret(base64.RawURLEncoding.EncodeToString(priv), mk, state.ConfigAAD(field))
}

// keys returns the signing keys (current, previous), generating the current one when absent and
// create is true. Root only; fail closed without master key.
func (m *Manager) keys(create bool) (cur, prev ed25519.PrivateKey, err error) {
	if !m.root() {
		return nil, nil, ErrNotRoot
	}
	if _, ok := m.MasterKey(); !ok {
		log.Printf("[SECURITY WARNING] link key operation refused: RSA_MASTER_KEY is not set")
		return nil, nil, ErrMasterKey
	}
	sc, sp := m.Store.LinkSigningKeys()
	if sc == "" && create {
		_, priv, gerr := auth.GenerateLinkKey()
		if gerr != nil {
			return nil, nil, gerr
		}
		sealed, serr := m.seal(state.ConfigLinkSigningKeyCurrent, priv)
		if serr != nil {
			return nil, nil, serr
		}
		if werr := m.Store.SetLinkSigningKeyIfAbsent(sealed); werr != nil && !errors.Is(werr, storage.ErrLinkKeyExists) {
			return nil, nil, werr
		}
		log.Printf("link signing key generated: kid=%s", auth.LinkKID(priv.Public().(ed25519.PublicKey)))
		sc, sp = m.Store.LinkSigningKeys()
	}
	if cur, err = m.open(state.ConfigLinkSigningKeyCurrent, sc, &m.cache); err != nil {
		return nil, nil, err
	}
	if prev, err = m.open(state.ConfigLinkSigningKeyPrevious, sp, &m.cacheP); err != nil {
		return nil, nil, err
	}
	return cur, prev, nil
}

func pub(priv ed25519.PrivateKey) ed25519.PublicKey {
	if priv == nil {
		return nil
	}
	return priv.Public().(ed25519.PublicKey)
}

// PubInfo is the public view of the link keys.
type PubInfo struct {
	RootID      string `json:"root_id"`
	CurrentKID  string `json:"current_kid"`
	CurrentPEM  string `json:"current_pub_pem"`
	PreviousKID string `json:"previous_kid,omitempty"`
	Seq         uint64 `json:"seq"`
}

// PEM encodes an Ed25519 public key as a PKIX "PUBLIC KEY" block.
func PEM(p ed25519.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(p)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), nil
}

// PublicInfo returns the public keys (generating the key on first use). Never a private key.
func (m *Manager) PublicInfo() (PubInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, prev, err := m.keys(true)
	if err != nil {
		return PubInfo{}, err
	}
	p, err := PEM(pub(cur))
	if err != nil {
		return PubInfo{}, err
	}
	seq, _ := m.Store.LinkSeq()
	info := PubInfo{RootID: m.LocalID(), CurrentKID: auth.LinkKID(pub(cur)), CurrentPEM: p, Seq: seq}
	if prev != nil {
		info.PreviousKID = auth.LinkKID(pub(prev))
	}
	return info, nil
}

// MintRequest describes a link token to mint.
type MintRequest struct {
	Role, Sub, Aud, Description, CreatedBy string
	TTL                                    time.Duration
}

// Minted is the result of Mint. Token is shown ONCE and never stored or logged.
type Minted struct {
	Token string
	Rec   storage.LinkToken
}

// Mint signs and registers a link token (root only).
func (m *Manager) Mint(ctx context.Context, r MintRequest) (*Minted, error) {
	if r.TTL <= 0 || r.TTL > MaxTTL || (r.Role != auth.RoleRelayChild && r.Role != auth.RoleRelayParent) ||
		r.Sub == "" || r.Aud == "" || r.Sub == r.Aud {
		return nil, ErrInvalidRequest
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, _, err := m.keys(true)
	if err != nil {
		return nil, err
	}
	rootID := m.LocalID()
	if rootID == "" {
		return nil, fmt.Errorf("%w: the root has no relay_id (set REPEATER_ID)", ErrInvalidRequest)
	}
	token, jti, err := auth.SignLinkToken(cur, rootID, r.Sub, r.Aud, r.Role, r.TTL)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC().Truncate(time.Second)
	rec := storage.LinkToken{ID: uuid.New().String(), JTI: jti, Role: r.Role, Sub: r.Sub, Aud: r.Aud,
		KID: auth.LinkKID(pub(cur)), CreatedAt: now, ExpiresAt: now.Add(r.TTL), CreatedBy: r.CreatedBy, Description: r.Description}
	if err := m.Store.CreateLinkToken(ctx, rec); err != nil {
		return nil, err
	}
	return &Minted{Token: token, Rec: rec}, nil
}

// Revoke revokes a link token: registry + blacklist + seq in one mutation, then closes the local
// links of that token (4010) and pushes link_revocations down. found=false: unknown id.
func (m *Manager) Revoke(ctx context.Context, id string) (rec storage.LinkToken, seq uint64, closed int, found bool, err error) {
	if !m.root() {
		return rec, 0, 0, false, ErrNotRoot
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, found, seq, err = m.Store.RevokeLinkToken(ctx, id)
	if err != nil || !found {
		return rec, seq, 0, found, err
	}
	// the frame goes down first: the revoked child (and the relays below it) learn the revocation, then its link is cut
	if frame, ferr := m.revocationFrame(seq, []storage.LinkRevocation{{JTI: rec.JTI, Exp: rec.ExpiresAt.Unix()}}); ferr != nil {
		log.Printf("link_revocations not sent: %v", ferr)
	} else if m.Broadcast != nil {
		m.Broadcast(frame)
	}
	if m.CloseByJTI != nil {
		closed = m.CloseByJTI(rec.JTI)
	}
	return rec, seq, closed, true, nil
}

func (m *Manager) revocationFrame(seq uint64, entries []storage.LinkRevocation) ([]byte, error) {
	cur, _, err := m.keys(false)
	if err != nil || cur == nil {
		return nil, fmt.Errorf("no signing key: %v", err)
	}
	es := make([]auth.LinkRevocation, 0, len(entries))
	for _, e := range entries {
		es = append(es, auth.LinkRevocation{JTI: e.JTI, Exp: e.Exp})
	}
	msg, err := auth.SignLinkRevocations(cur, seq, es)
	if err != nil {
		return nil, err
	}
	return withType(msg, "link_revocations")
}

func withType(msg []byte, typ string) ([]byte, error) {
	var mm map[string]json.RawMessage
	if err := json.Unmarshal(msg, &mm); err != nil {
		return nil, err
	}
	t, _ := json.Marshal(typ)
	mm["type"] = t
	return json.Marshal(mm)
}

// Rotate: current -> previous, new current; seq++; link_keys signed by the OLD current key is pushed.
func (m *Manager) Rotate(ctx context.Context) (curKID, prevKID string, seq uint64, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	oldPriv, prev, err := m.keys(true)
	if err != nil {
		return "", "", 0, err
	}
	if prev != nil {
		return "", "", 0, ErrPreviousOpen
	}
	sc, _ := m.Store.LinkSigningKeys()
	_, newPriv, err := auth.GenerateLinkKey()
	if err != nil {
		return "", "", 0, err
	}
	sealed, err := m.seal(state.ConfigLinkSigningKeyCurrent, newPriv)
	if err != nil {
		return "", "", 0, err
	}
	prevSealed, err := m.seal(state.ConfigLinkSigningKeyPrevious, oldPriv) // new AAD: the field changes
	if err != nil {
		return "", "", 0, err
	}
	seq, err = m.Store.RotateLinkKey(sealed, prevSealed, sc)
	if err != nil {
		if errors.Is(err, storage.ErrPreviousNotRetired) {
			return "", "", 0, ErrPreviousOpen
		}
		return "", "", 0, err
	}
	msg, serr := auth.SignLinkKeys(oldPriv, pub(newPriv), pub(oldPriv), seq)
	if serr == nil {
		var frame []byte
		if frame, serr = withType(msg, "link_keys"); serr == nil && m.Broadcast != nil {
			m.Broadcast(frame)
		}
	}
	if serr != nil {
		log.Printf("link_keys not sent: %v", serr)
	}
	log.Printf("[SECURITY] link key rotated: kid=%s previous=%s seq=%d", auth.LinkKID(pub(newPriv)), auth.LinkKID(pub(oldPriv)), seq)
	return auth.LinkKID(pub(newPriv)), auth.LinkKID(pub(oldPriv)), seq, nil
}

// RelayStatus is the confirmation of one relay (R2).
type RelayStatus struct {
	RelayID   string `json:"relay_id"`
	LinkSeq   uint64 `json:"link_seq"`
	LinkKID   string `json:"link_kid,omitempty"`
	Confirmed bool   `json:"confirmed"`
}

// Status describes the link keys and the confirmation of the rotation by the relays below.
type Status struct {
	RootID      string        `json:"root_id"`
	Seq         uint64        `json:"seq"`
	RotationSeq uint64        `json:"rotation_seq,omitempty"`
	CurrentKID  string        `json:"current_kid,omitempty"`
	PreviousKID string        `json:"previous_kid,omitempty"`
	Relays      []RelayStatus `json:"relays"`
}

// Status builds the status; a relay is confirmed when its reported seq reached the rotation seq and
// it knows the current kid. Without an open window every known relay is confirmed.
func (m *Manager) Status() (Status, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, prev, err := m.keys(false)
	if err != nil {
		return Status{}, err
	}
	seq, rot := m.Store.LinkSeq()
	st := Status{RootID: m.LocalID(), Seq: seq, RotationSeq: rot, Relays: []RelayStatus{}}
	if cur != nil {
		st.CurrentKID = auth.LinkKID(pub(cur))
	}
	if prev != nil {
		st.PreviousKID = auth.LinkKID(pub(prev))
	}
	var states map[string]ConfirmedState
	if m.States != nil {
		states = m.States()
	}
	var known []string
	if m.Known != nil {
		known = m.Known()
	}
	set := map[string]struct{}{}
	for _, id := range known {
		set[id] = struct{}{}
	}
	if nodes, nerr := m.Store.ListRelayNodes(); nerr == nil {
		for _, n := range nodes {
			set[n.RelayID] = struct{}{}
		}
	}
	for id := range states {
		set[id] = struct{}{}
	}
	ids := make([]string, 0, len(set))
	for id := range set {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		s := states[id]
		ok := prev == nil || (s.Seq >= rot && s.KID == st.CurrentKID)
		st.Relays = append(st.Relays, RelayStatus{RelayID: id, LinkSeq: s.Seq, LinkKID: s.KID, Confirmed: ok})
	}
	return st, nil
}

// Retire closes the double-acceptation window. Refused (ErrUnconfirmed, with the relays) while relays
// below have not confirmed the rotation, unless force (then a [SECURITY WARNING] lists them) (R2).
func (m *Manager) Retire(ctx context.Context, force bool) (seq uint64, unconfirmed []string, err error) {
	st, err := m.Status()
	if err != nil {
		return 0, nil, err
	}
	if st.PreviousKID == "" {
		return 0, nil, ErrNoPrevious
	}
	for _, r := range st.Relays {
		if !r.Confirmed {
			unconfirmed = append(unconfirmed, r.RelayID)
		}
	}
	if len(unconfirmed) > 0 {
		if !force {
			return 0, unconfirmed, ErrUnconfirmed
		}
		log.Printf("[SECURITY WARNING] retire-link-previous FORCED while relays have not confirmed the rotation: %v (they will be refused until their trust anchor is re-pinned)", unconfirmed)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, _, err := m.keys(false)
	if err != nil || cur == nil {
		return 0, nil, fmt.Errorf("no signing key: %v", err)
	}
	seq, err = m.Store.RetireLinkPrevious()
	if err != nil {
		if errors.Is(err, storage.ErrNoPreviousKey) {
			return 0, nil, ErrNoPrevious
		}
		return 0, nil, err
	}
	if msg, serr := auth.SignLinkKeys(cur, pub(cur), nil, seq); serr == nil {
		if frame, terr := withType(msg, "link_keys"); terr == nil && m.Broadcast != nil {
			m.Broadcast(frame)
		}
	} else {
		log.Printf("link_keys (retire) not sent: %v", serr)
	}
	log.Printf("[SECURITY] link previous key retired: seq=%d", seq)
	return seq, unconfirmed, nil
}

// SyncFrames (root) returns the frames of a freshly established child link, in order: link_keys while
// a rotation window is open (re-signed by the previous key: Ed25519 is deterministic), then
// link_revocations with the FULL list at the current seq (omitted while seq = 0).
func (m *Manager) SyncFrames() [][]byte {
	if !m.root() {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, prev, err := m.keys(false)
	if err != nil || cur == nil {
		return nil
	}
	seq, rot := m.Store.LinkSeq()
	var out [][]byte
	if prev != nil && rot > 0 {
		if msg, serr := auth.SignLinkKeys(prev, pub(cur), pub(prev), rot); serr == nil {
			if f, terr := withType(msg, "link_keys"); terr == nil {
				out = append(out, f)
			}
		}
	}
	if seq > 0 {
		if f, ferr := m.revocationFrame(seq, m.Store.LinkRevocations(time.Now())); ferr == nil {
			out = append(out, f)
		}
	}
	return out
}

// Trust builds what /ws/relay verifies against, and the expected root relay_id. The root trusts its
// own keys; any other relay its pinned anchor (link_trust). ErrNoTrust when there is nothing.
func (m *Manager) Trust() (auth.LinkTrust, string, error) {
	if m.root() {
		m.mu.Lock()
		defer m.mu.Unlock()
		cur, prev, err := m.keys(false)
		if err != nil {
			return auth.LinkTrust{}, "", err
		}
		if cur == nil {
			return auth.LinkTrust{}, "", ErrNoTrust
		}
		return auth.LinkTrust{Current: pub(cur), Previous: pub(prev)}, m.LocalID(), nil
	}
	lt := m.Store.LinkTrust()
	if lt.CurrentPub == "" || lt.RootID == "" {
		return auth.LinkTrust{}, "", ErrNoTrust
	}
	c, err := base64.RawURLEncoding.DecodeString(lt.CurrentPub)
	if err != nil || len(c) != ed25519.PublicKeySize {
		return auth.LinkTrust{}, "", ErrNoTrust
	}
	t := auth.LinkTrust{Current: c, LastSeq: lt.Seq}
	if lt.PreviousPub != "" {
		if p, perr := base64.RawURLEncoding.DecodeString(lt.PreviousPub); perr == nil && len(p) == ed25519.PublicKeySize {
			t.Previous = p
		}
	}
	return t, lt.RootID, nil
}
