package repeater

// Link trust of a NON-ROOT relay (#141 hybrid, L1e): the root public key pinned at deployment
// (the anchor), its rotation received through the link (link_keys), and the revocation lists
// (link_revocations) received from the parent. The wire format and every signature check live in
// auth/linkjwt.go (auth.ApplyLinkKeys, auth.VerifyLinkRevocations, auth.VerifyLinkToken): nothing
// is redefined here. This type only decides WHEN to apply a frame, persists the result, feeds
// the blacklist, and hands the verified frames over for retransmission to the children.
//
// Fail closed: without an anchor (no pinned key and nothing persisted) Anchored() is false and
// VerifyToken refuses every token (link_trust_missing): the caller must refuse every incoming link.
// Nothing here logs a key, a token or a signature.

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"secagent-server/cmd/secagent-server/internal/auth"
)

// errUnverifiableKnownKey: a link_keys frame that cannot be authenticated but only repeats the key we
// already trust. Ignored without a security warning (it is the nominal case of a relay anchored on the
// new key), and never relayed, remembered nor confirmed.
var errUnverifiableKnownKey = errors.New("link_keys frame announcing the already trusted key cannot be verified")

// ErrAnchorMismatch: the pinned root key disagrees with the persisted link_trust outside a valid
// rotation chain, or the root identity differs. The relay must refuse to start.
var ErrAnchorMismatch = errors.New("pinned root link key disagrees with the persisted link_trust (outside a valid rotation chain)")

// TrustRecord is the persisted link trust. Keys are base64url without padding (32 raw bytes).
type TrustRecord struct {
	RootID      string
	CurrentPub  string
	CurrentKID  string
	PreviousPub string
	PreviousKID string
	Seq         uint64 // last accepted link_keys / link_revocations seq
}

// IsZero reports whether nothing is recorded.
func (r TrustRecord) IsZero() bool { return r == TrustRecord{} }

// TrustStore persists the trust (one atomic write per change).
type TrustStore interface {
	LoadLinkTrust() (TrustRecord, error)
	SaveLinkTrust(TrustRecord) error
}

// RevocationSink is the local blacklist of link-token JTIs.
type RevocationSink interface {
	// BlacklistLinkJTI records a revoked link token until exp (idempotent).
	BlacklistLinkJTI(jti string, exp time.Time) error
	IsLinkJTIBlacklisted(jti string) bool
}

// LinkTrustConfig builds a LinkTrust.
type LinkTrustConfig struct {
	RootID    string            // REPEATER_ROOT_ID: the expected `iss` of every link token
	Anchor    ed25519.PublicKey // pinned root public key (REPEATER_ROOT_LINK_KEY_FILE), may be nil
	Store     TrustStore
	Blacklist RevocationSink
}

// FrameResult describes what HandleFrame did.
type FrameResult struct {
	Type    string   // link_keys | link_revocations
	Applied bool     // true when the trust / blacklist changed or was re-synchronised
	Confirm bool     // true when the relay is already on the announced state: send link_state, nothing written
	Seq     uint64   // last accepted seq after the frame
	KID     string   // current kid after the frame
	Revoked []string // JTI newly blacklisted by this frame
}

// LinkTrust is safe for concurrent use. The callbacks must not call back into it.
type LinkTrust struct {
	rootID string
	store  TrustStore
	bl     RevocationSink

	mu       sync.Mutex
	trust    auth.LinkTrust
	anchored bool
	revs     [][]byte // verified link_revocations frames since the parent link was established
	keys     []byte   // last verified link_keys frame (rotation open) — replayed to new children

	forward   func(raw []byte)
	onRevoked []func(jti string)
}

// NewLinkTrust loads the persisted trust and reconciles it with the pinned anchor.
//   - no anchor and nothing persisted: unanchored (fail closed, not an error);
//   - anchor and nothing persisted: persisted as the initial trust;
//   - anchor equal to the persisted current key, or to the persisted previous key (the file predates
//     the last rotation: a valid chain): the persisted trust wins;
//   - anything else (other key, other root id): ErrAnchorMismatch, the relay must not start.
func NewLinkTrust(cfg LinkTrustConfig) (*LinkTrust, error) {
	if cfg.Store == nil || cfg.Blacklist == nil {
		return nil, errors.New("link trust: store and blacklist are required")
	}
	m := &LinkTrust{rootID: cfg.RootID, store: cfg.Store, bl: cfg.Blacklist}
	rec, err := cfg.Store.LoadLinkTrust()
	if err != nil {
		return nil, fmt.Errorf("link trust: load: %w", err)
	}
	if cfg.Anchor != nil && len(cfg.Anchor) != ed25519.PublicKeySize {
		return nil, errors.New("link trust: pinned key is not an Ed25519 public key")
	}

	if !rec.IsZero() {
		cur, prev, derr := decodeRecordKeys(rec)
		if derr != nil {
			return nil, fmt.Errorf("link trust: persisted state is invalid: %w", derr)
		}
		if cfg.RootID != "" && rec.RootID != "" && cfg.RootID != rec.RootID {
			return nil, fmt.Errorf("%w: root id differs", ErrAnchorMismatch)
		}
		if cfg.Anchor != nil && !cfg.Anchor.Equal(cur) && (prev == nil || !cfg.Anchor.Equal(prev)) {
			return nil, ErrAnchorMismatch
		}
		if m.rootID == "" {
			m.rootID = rec.RootID
		}
		m.trust = auth.LinkTrust{Current: cur, Previous: prev, LastSeq: rec.Seq}
		m.anchored = m.rootID != ""
	} else if cfg.Anchor != nil {
		if cfg.RootID == "" {
			return nil, errors.New("link trust: a pinned key needs the root id (REPEATER_ROOT_ID)")
		}
		rec = TrustRecord{RootID: cfg.RootID, CurrentPub: b64(cfg.Anchor), CurrentKID: auth.LinkKID(cfg.Anchor)}
		if err := cfg.Store.SaveLinkTrust(rec); err != nil {
			return nil, fmt.Errorf("link trust: persist the anchor: %w", err)
		}
		m.trust = auth.LinkTrust{Current: cfg.Anchor}
		m.anchored = true
	}
	m.trust.Blacklisted = m.bl.IsLinkJTIBlacklisted
	if !m.anchored {
		log.Printf("[SECURITY WARNING] link trust: no pinned root key (REPEATER_ROOT_LINK_KEY_FILE) and nothing persisted: every incoming link is refused")
	}
	return m, nil
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func decodeRecordKeys(r TrustRecord) (cur, prev ed25519.PublicKey, err error) {
	c, e := base64.RawURLEncoding.DecodeString(r.CurrentPub)
	if e != nil || len(c) != ed25519.PublicKeySize || r.CurrentKID != auth.LinkKID(c) {
		return nil, nil, errors.New("current key")
	}
	cur = c
	if r.PreviousPub != "" {
		p, e := base64.RawURLEncoding.DecodeString(r.PreviousPub)
		if e != nil || len(p) != ed25519.PublicKeySize || r.PreviousKID != auth.LinkKID(p) {
			return nil, nil, errors.New("previous key")
		}
		prev = p
	}
	return cur, prev, nil
}

// Anchored reports whether a trust anchor and the root identity are known.
func (m *LinkTrust) Anchored() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.anchored
}

// RootID is the expected `iss` of the link tokens.
func (m *LinkTrust) RootID() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.rootID
}

// State returns the last accepted seq and the current kid ("" when unanchored).
func (m *LinkTrust) State() (seq uint64, kid string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.anchored {
		return 0, ""
	}
	return m.trust.LastSeq, auth.LinkKID(m.trust.Current)
}

// Trust returns a snapshot of the trust for auth.VerifyLinkToken (zero Current when unanchored).
func (m *LinkTrust) Trust() auth.LinkTrust {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.anchored {
		return auth.LinkTrust{}
	}
	return m.trust
}

// VerifyToken verifies a link token presented to this relay (localID = this relay's id, role =
// auth.RoleRelayChild when the peer is our child, auth.RoleRelayParent when the peer is our
// parent). An unanchored relay refuses everything (link_trust_missing).
func (m *LinkTrust) VerifyToken(token, localID, role string, now time.Time) (*auth.LinkClaims, error) {
	t, root := m.Trust(), m.RootID()
	return auth.VerifyLinkToken(t, token, auth.LinkWant{LocalID: localID, RootID: root, Role: role}, now)
}

// OnForward registers the retransmission of a verified frame to the children (bytes unchanged).
func (m *LinkTrust) OnForward(fn func(raw []byte)) {
	m.mu.Lock()
	m.forward = fn
	m.mu.Unlock()
}

// OnRevoked registers a listener called with every newly revoked JTI (to close the matching link).
func (m *LinkTrust) OnRevoked(fn func(jti string)) {
	m.mu.Lock()
	m.onRevoked = append(m.onRevoked, fn)
	m.mu.Unlock()
}

// ResetFrames forgets the revocation frames kept for replay: call it when the link to the parent
// is (re)established, the parent then re-sends its full state.
func (m *LinkTrust) ResetFrames() {
	m.mu.Lock()
	m.revs = nil
	m.mu.Unlock()
}

// Replay returns the verified frames to send to a child that just connected: the open rotation
// (link_keys) then the revocation frames received since the parent link was established.
func (m *LinkTrust) Replay() [][]byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out [][]byte
	if m.keys != nil {
		out = append(out, append([]byte(nil), m.keys...))
	}
	for _, f := range m.revs {
		out = append(out, append([]byte(nil), f...))
	}
	return out
}

const (
	maxReplayFrames = 256
	// maxLinkFrameLen bounds a link_keys / link_revocations frame (a full list of 10000 entries is
	// under 1 MiB); the check is made on the raw bytes, before any decoding.
	maxLinkFrameLen = 1 << 20
)

// HandleFrame verifies and applies a link_keys / link_revocations frame received from the parent.
// An invalid frame is ignored with a [SECURITY WARNING] and the trust is left unchanged (the link
// stays open); link_message_seq_replay is benign. The error is non-nil only for a refused frame.
func (m *LinkTrust) HandleFrame(raw []byte) (FrameResult, error) {
	if len(raw) > maxLinkFrameLen { // before any decode or allocation
		log.Printf("[SECURITY WARNING] link frame refused: %d bytes exceed the limit", len(raw))
		return FrameResult{}, errors.New("link frame: too large")
	}
	var env struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return FrameResult{}, errors.New("link frame: not JSON")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.anchored {
		log.Printf("[SECURITY WARNING] link trust: %s frame ignored: no trust anchor", sanitizeText(env.Type))
		return FrameResult{Type: env.Type}, &auth.LinkError{Code: auth.LinkErrNoTrust}
	}
	var res FrameResult
	var err error
	switch env.Type {
	case "link_keys":
		res, err = m.applyKeys(raw)
	case "link_revocations":
		res, err = m.applyRevocations(raw)
	default:
		return FrameResult{Type: env.Type}, fmt.Errorf("link frame: unsupported type %q", sanitizeText(env.Type))
	}
	if err != nil {
		if errors.Is(err, errUnverifiableKnownKey) {
			log.Printf("[LINK] link_keys ignored: announces the key already trusted but cannot be verified (nothing relayed, remembered or confirmed)")
			return res, nil
		}
		var le *auth.LinkError
		if errors.As(err, &le) && le.Code == auth.LinkErrMsgSeq {
			// not an error for the link, nothing is persisted, the link stays open: equal seq =
			// idempotent re-send on reconnection (INFO), lower seq = replay of an older state (WARNING)
			var s struct {
				Seq uint64 `json:"seq"`
			}
			if json.Unmarshal(raw, &s) == nil && s.Seq == m.trust.LastSeq {
				log.Printf("[LINK] %s seq=%d already applied: no-op", env.Type, s.Seq)
			} else {
				log.Printf("[WARNING] link trust: %s replay refused (seq older than the last accepted %d)", env.Type, m.trust.LastSeq)
			}
			return res, nil
		}
		log.Printf("[SECURITY WARNING] link trust: %s frame refused (%s): trust unchanged", env.Type, sanitizeText(err.Error()))
		return res, err
	}
	return res, nil
}

func (m *LinkTrust) record() TrustRecord {
	r := TrustRecord{RootID: m.rootID, CurrentPub: b64(m.trust.Current), CurrentKID: auth.LinkKID(m.trust.Current), Seq: m.trust.LastSeq}
	if m.trust.Previous != nil {
		r.PreviousPub, r.PreviousKID = b64(m.trust.Previous), auth.LinkKID(m.trust.Previous)
	}
	return r
}

func (m *LinkTrust) applyKeys(raw []byte) (FrameResult, error) {
	res := FrameResult{Type: "link_keys", Seq: m.trust.LastSeq, KID: auth.LinkKID(m.trust.Current)}
	nt, err := auth.ApplyLinkKeys(m.trust, raw)
	if err != nil {
		// A re-send of the keys we ALREADY trust is accepted only when its signature verifies with a key
		// we already trust (auth.VerifyLinkKeysReplay: Previous for an open rotation, Current once the
		// window is closed): authenticated, idempotent, nothing written. The seq confirmed afterwards is
		// ours (authenticated), never the one read in the frame.
		if _, verr := auth.VerifyLinkKeysReplay(m.trust, raw); verr == nil {
			res.Confirm = true
			if m.trust.Previous != nil {
				m.keys = append([]byte(nil), raw...)
			} else {
				m.keys = nil
			}
			log.Printf("[LINK] link_keys re-sent and verified (kid=%s): confirmed, nothing written", res.KID)
			m.fanOut(raw)
			return res, nil
		}
		var le *auth.LinkError
		if errors.As(err, &le) && le.Code == auth.LinkErrMsgChain && m.announcesCurrent(raw) {
			// Cannot be verified (e.g. a relay anchored on the NEW key, which holds no key able to verify
			// the rotation signed by the old one) and announces what we already trust: ignored, NOT
			// relayed, NOT remembered, NOT confirmed. Our confirmation comes from the verified
			// link_revocations that follows, whose seq is authenticated by the current key.
			return res, errUnverifiableKnownKey
		}
		return res, err
	}
	old := m.trust
	m.trust = nt
	m.trust.Blacklisted = m.bl.IsLinkJTIBlacklisted
	if err := m.store.SaveLinkTrust(m.record()); err != nil { // fail closed: keep the old trust
		m.trust = old
		return res, fmt.Errorf("persist link_trust: %w", err)
	}
	if nt.Previous != nil {
		m.keys = append([]byte(nil), raw...)
	} else {
		m.keys = nil // window closed: nothing to replay
	}
	res.Applied, res.Confirm, res.Seq, res.KID = true, true, nt.LastSeq, auth.LinkKID(nt.Current)
	log.Printf("[LINK] root link keys updated: kid=%s seq=%d previous=%t", res.KID, res.Seq, nt.Previous != nil)
	m.fanOut(raw)
	return res, nil
}

// announcesCurrent reports whether a link_keys frame announces the key we already trust as current.
func (m *LinkTrust) announcesCurrent(raw []byte) bool {
	var k struct {
		CurrentPub string `json:"current_pub"`
		CurrentKID string `json:"current_kid"`
	}
	if json.Unmarshal(raw, &k) != nil || k.CurrentPub != b64(m.trust.Current) {
		return false
	}
	return k.CurrentKID == "" || k.CurrentKID == auth.LinkKID(m.trust.Current)
}

func (m *LinkTrust) applyRevocations(raw []byte) (FrameResult, error) {
	res := FrameResult{Type: "link_revocations", Seq: m.trust.LastSeq, KID: auth.LinkKID(m.trust.Current)}
	seq, entries, err := auth.VerifyLinkRevocations(m.trust, raw)
	resync := false
	if err != nil {
		var le *auth.LinkError
		if !errors.As(err, &le) || le.Code != auth.LinkErrMsgSeq {
			return res, err
		}
		// The signature is valid (checked before the seq): a list at the SAME seq is the parent
		// re-sending its state (full list on reconnection, or the rotation and the list share a
		// seq). Applying it again only adds blacklist entries; a lower seq is a rollback: ignored.
		var s struct {
			Seq uint64 `json:"seq"`
		}
		if json.Unmarshal(raw, &s) != nil || s.Seq != m.trust.LastSeq {
			return res, err
		}
		seq, resync = s.Seq, true
		log.Printf("[LINK] link_revocations seq=%d already applied: only entries not yet blacklisted are added", seq)
		_, entries, _ = parseRevocationEntries(raw)
	}
	now := time.Now()
	for _, e := range entries {
		exp := time.Unix(e.Exp, 0)
		if !exp.After(now) {
			continue // expired token: nothing to blacklist
		}
		if m.bl.IsLinkJTIBlacklisted(e.JTI) {
			continue
		}
		if err := m.bl.BlacklistLinkJTI(e.JTI, exp); err != nil { // fail closed: seq not advanced
			return res, fmt.Errorf("blacklist: %w", err)
		}
		res.Revoked = append(res.Revoked, e.JTI)
	}
	if !resync {
		old := m.trust
		m.trust.LastSeq = seq
		if err := m.store.SaveLinkTrust(m.record()); err != nil {
			m.trust = old
			return res, fmt.Errorf("persist link_trust: %w", err)
		}
	}
	if len(m.revs) >= maxReplayFrames {
		m.revs = m.revs[len(m.revs)-maxReplayFrames+1:]
	}
	m.revs = append(m.revs, append([]byte(nil), raw...))
	res.Applied, res.Seq = true, m.trust.LastSeq
	for _, jti := range res.Revoked {
		for _, fn := range m.onRevoked {
			fn(jti)
		}
	}
	m.fanOut(raw)
	return res, nil
}

func parseRevocationEntries(raw []byte) (uint64, []auth.LinkRevocation, error) {
	var m struct {
		Seq     uint64                `json:"seq"`
		Entries []auth.LinkRevocation `json:"entries"`
	}
	err := json.Unmarshal(raw, &m)
	return m.Seq, m.Entries, err
}

func (m *LinkTrust) fanOut(raw []byte) {
	if m.forward != nil {
		m.forward(append([]byte(nil), raw...))
	}
}
