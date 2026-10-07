package auth

// Inter-relay link tokens and their companion messages (#141 hybrid, #146).
//
// This file is a verifier SEPARATE from the HS256 path (jwt.go, ws/jwt.go): link
// tokens are Ed25519 (alg=EdDSA) signed by the root relay, and nothing here ever
// calls the HMAC code, so an algorithm-confusion token (HS256 keyed with the public
// key, alg none, RS256...) has no verification path at all.
//
// Library only: no server wiring, no logging (callers must never log a token).

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Link token roles. The pre-v3.0.4 role "relay" is gone and refused (RoleRelayLegacy).
const (
	RoleRelayChild  = "relay-child"  // presented by the child to its parent (pull link)
	RoleRelayParent = "relay-parent" // presented by the parent to its child (push link)
	RoleRelayLegacy = "relay"        // v3.0.3 HS256 role, refused with a permanent error

	linkAlg           = "EdDSA"
	linkIATLeeway     = 60 * time.Second
	maxLinkEntries    = 10000
	maxLinkMessageLen = 2 << 20 // 2 MiB
)

// Error codes of LinkError.
const (
	LinkErrMalformed     = "link_token_malformed"
	LinkErrAlg           = "link_alg_not_allowed"
	LinkErrKID           = "link_kid_unknown"
	LinkErrSignature     = "link_signature_invalid"
	LinkErrExpired       = "link_token_expired"
	LinkErrClaims        = "link_claims_invalid"
	LinkErrAudience      = "link_audience_mismatch"
	LinkErrRole          = "link_role_mismatch"
	LinkErrLegacyRole    = "link_role_legacy"
	LinkErrRevoked       = "link_token_revoked"
	LinkErrNoTrust       = "link_trust_missing"
	LinkErrMsgInvalid    = "link_message_invalid"
	LinkErrMsgSignature  = "link_message_signature_invalid"
	LinkErrMsgSeq        = "link_message_seq_replay"
	LinkErrMsgChain      = "link_keys_chain_broken"
	linkSignDomainRevoke = "ansible-secagent/link_revocations/v1\n"
	linkSignDomainKeys   = "ansible-secagent/link_keys/v1\n"
)

// ErrLinkSeqReplay is returned (wrapped in a LinkError) when a link_revocations /
// link_keys message carries a seq that is not strictly greater than the last
// accepted one. Callers may treat it as benign when re-receiving a full state.
var ErrLinkSeqReplay = errors.New("link message seq is not newer than the last accepted one")

// LinkError is a refusal. Permanent=true means the presenter must NOT retry with
// the same credential (bad signature, wrong role/audience, revoked, expired...).
// Only a local misconfiguration (no trust anchor yet) is retryable.
type LinkError struct {
	Code      string
	Permanent bool
	cause     error
}

func (e *LinkError) Error() string {
	if e.cause != nil {
		return e.Code + ": " + e.cause.Error()
	}
	return e.Code
}
func (e *LinkError) Unwrap() error { return e.cause }

func linkErr(code string, permanent bool, cause error) *LinkError {
	return &LinkError{Code: code, Permanent: permanent, cause: cause}
}

// LinkTrust is what a relay trusts: the root public keys (anchor + rotation) and
// its blacklist. A nil Previous means the double-acceptation window is over.
type LinkTrust struct {
	Current     ed25519.PublicKey
	Previous    ed25519.PublicKey
	Blacklisted func(jti string) bool // nil = nothing blacklisted
	LastSeq     uint64                // last accepted link_revocations / link_keys seq
}

// LinkWant is what the local relay expects from the presenter.
type LinkWant struct {
	LocalID string // "aud" must equal this
	Role    string // RoleRelayChild (we are the parent) or RoleRelayParent (we are the child)
}

// LinkClaims are the verified claims of a link token.
type LinkClaims struct {
	Issuer, Subject, Audience, Role, JTI string
	IssuedAt, ExpiresAt                  time.Time
	KID                                  string
}

// GenerateLinkKey creates a new Ed25519 root signing key pair.
func GenerateLinkKey() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate link key: %w", err)
	}
	return pub, priv, nil
}

// LinkKID is the `kid` of a root public key: base64url (no padding) of the first
// 16 bytes of its SHA-256.
func LinkKID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return base64.RawURLEncoding.EncodeToString(sum[:16])
}

func validLinkRole(r string) bool { return r == RoleRelayChild || r == RoleRelayParent }

// SignLinkToken mints a link token signed by the root private key. ttl must be positive.
func SignLinkToken(priv ed25519.PrivateKey, iss, sub, aud, role string, ttl time.Duration) (token, jti string, err error) {
	if len(priv) != ed25519.PrivateKeySize {
		return "", "", errors.New("link_signing_key_invalid")
	}
	if iss == "" || sub == "" || aud == "" {
		return "", "", errors.New("link_token_requires_iss_sub_aud")
	}
	if !validLinkRole(role) {
		return "", "", errors.New("link_token_invalid_role")
	}
	if ttl <= 0 {
		return "", "", errors.New("link_token_requires_expiry")
	}
	jti = uuid.New().String()
	now := time.Now()
	t := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwt.MapClaims{
		"iss": iss, "sub": sub, "aud": aud, "role": role, "jti": jti,
		"iat": now.Unix(), "exp": now.Add(ttl).Unix(),
	})
	t.Header["kid"] = LinkKID(priv.Public().(ed25519.PublicKey))
	token, err = t.SignedString(priv)
	if err != nil {
		return "", "", fmt.Errorf("sign link token: %w", err)
	}
	return token, jti, nil
}

// VerifyLinkToken strictly verifies a link token against the trust and the local
// expectation. Every refusal is a *LinkError.
func VerifyLinkToken(trust LinkTrust, tokenStr string, want LinkWant, now time.Time) (*LinkClaims, error) {
	if len(trust.Current) != ed25519.PublicKeySize {
		return nil, linkErr(LinkErrNoTrust, false, nil) // fail closed, retryable once anchored
	}
	if !validLinkRole(want.Role) || want.LocalID == "" {
		return nil, linkErr(LinkErrClaims, true, errors.New("local expectation is not set"))
	}

	// Pre-check the header: alg must be EdDSA, kid must name a trusted key.
	unverified, _, err := jwt.NewParser().ParseUnverified(tokenStr, jwt.MapClaims{})
	if err != nil {
		return nil, linkErr(LinkErrMalformed, true, nil)
	}
	if alg, _ := unverified.Header["alg"].(string); alg != linkAlg {
		return nil, linkErr(LinkErrAlg, true, nil)
	}

	keyfunc := func(t *jwt.Token) (interface{}, error) {
		if t.Method != jwt.SigningMethodEdDSA {
			return nil, linkErr(LinkErrAlg, true, nil)
		}
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, linkErr(LinkErrKID, true, nil)
		}
		if kid == LinkKID(trust.Current) {
			return trust.Current, nil
		}
		if len(trust.Previous) == ed25519.PublicKeySize && kid == LinkKID(trust.Previous) {
			return trust.Previous, nil
		}
		return nil, linkErr(LinkErrKID, true, nil)
	}
	p := jwt.NewParser(
		jwt.WithValidMethods([]string{linkAlg}),
		jwt.WithTimeFunc(func() time.Time { return now }),
	)
	tok, err := p.Parse(tokenStr, keyfunc)
	if err != nil {
		var le *LinkError
		switch {
		case errors.As(err, &le):
			return nil, le
		case errors.Is(err, jwt.ErrTokenExpired):
			return nil, linkErr(LinkErrExpired, true, nil)
		case errors.Is(err, jwt.ErrTokenSignatureInvalid):
			return nil, linkErr(LinkErrSignature, true, nil)
		}
		return nil, linkErr(LinkErrMalformed, true, nil)
	}
	mc, ok := tok.Claims.(jwt.MapClaims)
	if !ok || !tok.Valid {
		return nil, linkErr(LinkErrMalformed, true, nil)
	}

	str := func(k string) string { s, _ := mc[k].(string); return s }
	c := &LinkClaims{Issuer: str("iss"), Subject: str("sub"), Role: str("role"), JTI: str("jti")}
	c.KID, _ = tok.Header["kid"].(string)
	if c.Issuer == "" || c.Subject == "" || c.JTI == "" || c.Role == "" {
		return nil, linkErr(LinkErrClaims, true, nil)
	}
	aud, err := mc.GetAudience()
	if err != nil || len(aud) != 1 || aud[0] == "" {
		return nil, linkErr(LinkErrAudience, true, nil) // missing, empty or multiple
	}
	c.Audience = aud[0]
	if c.Audience != want.LocalID {
		return nil, linkErr(LinkErrAudience, true, nil)
	}
	switch {
	case c.Role == RoleRelayLegacy:
		return nil, linkErr(LinkErrLegacyRole, true, nil)
	case !validLinkRole(c.Role) || c.Role != want.Role:
		return nil, linkErr(LinkErrRole, true, nil)
	}
	iat, err := mc.GetIssuedAt()
	if err != nil || iat == nil || iat.Time.After(now.Add(linkIATLeeway)) {
		return nil, linkErr(LinkErrClaims, true, nil)
	}
	exp, err := mc.GetExpirationTime()
	if err != nil || exp == nil || !exp.Time.After(iat.Time) {
		return nil, linkErr(LinkErrClaims, true, nil)
	}
	c.IssuedAt, c.ExpiresAt = iat.Time, exp.Time
	if trust.Blacklisted != nil && trust.Blacklisted(c.JTI) {
		return nil, linkErr(LinkErrRevoked, true, nil)
	}
	return c, nil
}

// ---- link_revocations -------------------------------------------------------

// LinkRevocation is one revoked link token (its JTI and the token expiry, unix seconds).
type LinkRevocation struct {
	JTI string `json:"jti"`
	Exp int64  `json:"exp"`
}

type linkRevocationsMsg struct {
	Seq     uint64           `json:"seq"`
	Entries []LinkRevocation `json:"entries"`
	Sig     string           `json:"sig"`
}

func revocationsSigInput(seq uint64, entries []LinkRevocation) []byte {
	b := []byte(linkSignDomainRevoke)
	b = strconv.AppendUint(b, seq, 10)
	b = append(b, '\n')
	for _, e := range entries {
		b = strconv.AppendInt(b, int64(len(e.JTI)), 10) // length prefix: no ambiguity
		b = append(b, ':')
		b = append(b, e.JTI...)
		b = strconv.AppendInt(b, e.Exp, 10)
		b = append(b, '\n')
	}
	return b
}

func checkEntries(entries []LinkRevocation) error {
	if len(entries) > maxLinkEntries {
		return errors.New("too many entries")
	}
	for _, e := range entries {
		if e.JTI == "" || len(e.JTI) > 128 {
			return errors.New("invalid jti")
		}
	}
	return nil
}

// SignLinkRevocations builds a link_revocations message signed by the root `current` key.
func SignLinkRevocations(priv ed25519.PrivateKey, seq uint64, entries []LinkRevocation) ([]byte, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, errors.New("link_signing_key_invalid")
	}
	if err := checkEntries(entries); err != nil {
		return nil, fmt.Errorf("link_revocations: %w", err)
	}
	if entries == nil {
		entries = []LinkRevocation{}
	}
	sig := ed25519.Sign(priv, revocationsSigInput(seq, entries))
	return json.Marshal(linkRevocationsMsg{Seq: seq, Entries: entries, Sig: base64.RawURLEncoding.EncodeToString(sig)})
}

// VerifyLinkRevocations verifies signature (root `current` key only) and anti-replay
// (seq strictly greater than trust.LastSeq). The caller persists seq and blacklists the entries.
func VerifyLinkRevocations(trust LinkTrust, msg []byte) (uint64, []LinkRevocation, error) {
	if len(trust.Current) != ed25519.PublicKeySize {
		return 0, nil, linkErr(LinkErrNoTrust, false, nil)
	}
	if len(msg) > maxLinkMessageLen {
		return 0, nil, linkErr(LinkErrMsgInvalid, true, errors.New("message too large"))
	}
	var m linkRevocationsMsg
	if err := json.Unmarshal(msg, &m); err != nil || m.Sig == "" {
		return 0, nil, linkErr(LinkErrMsgInvalid, true, nil)
	}
	if err := checkEntries(m.Entries); err != nil {
		return 0, nil, linkErr(LinkErrMsgInvalid, true, err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(m.Sig)
	if err != nil || len(sig) != ed25519.SignatureSize ||
		!ed25519.Verify(trust.Current, revocationsSigInput(m.Seq, m.Entries), sig) {
		return 0, nil, linkErr(LinkErrMsgSignature, true, nil)
	}
	if m.Seq <= trust.LastSeq {
		return 0, nil, linkErr(LinkErrMsgSeq, true, ErrLinkSeqReplay)
	}
	return m.Seq, m.Entries, nil
}

// ---- link_keys --------------------------------------------------------------

type linkKeysMsg struct {
	CurrentPub  string `json:"current_pub"`
	CurrentKID  string `json:"current_kid"`
	PreviousPub string `json:"previous_pub,omitempty"`
	PreviousKID string `json:"previous_kid,omitempty"`
	Seq         uint64 `json:"seq"`
	Sig         string `json:"sig"`
}

func linkKeysSigInput(newCurrent, previous ed25519.PublicKey, seq uint64) []byte {
	b := []byte(linkSignDomainKeys)
	b = strconv.AppendUint(b, seq, 10)
	b = append(b, '\n')
	b = append(b, newCurrent...) // fixed 32 bytes
	b = binary.BigEndian.AppendUint16(b, uint16(len(previous)))
	b = append(b, previous...)
	return b
}

// SignLinkKeys builds a link_keys rotation message: the new current key (and the
// previous one, nil when the window is closed) signed by the OLD current key.
func SignLinkKeys(oldPriv ed25519.PrivateKey, newCurrent, previous ed25519.PublicKey, seq uint64) ([]byte, error) {
	if len(oldPriv) != ed25519.PrivateKeySize || len(newCurrent) != ed25519.PublicKeySize ||
		(len(previous) != 0 && len(previous) != ed25519.PublicKeySize) {
		return nil, errors.New("link_keys: invalid key")
	}
	m := linkKeysMsg{
		CurrentPub: base64.RawURLEncoding.EncodeToString(newCurrent),
		CurrentKID: LinkKID(newCurrent),
		Seq:        seq,
		Sig:        base64.RawURLEncoding.EncodeToString(ed25519.Sign(oldPriv, linkKeysSigInput(newCurrent, previous, seq))),
	}
	if len(previous) != 0 {
		m.PreviousPub = base64.RawURLEncoding.EncodeToString(previous)
		m.PreviousKID = LinkKID(previous)
	}
	return json.Marshal(m)
}

// ApplyLinkKeys verifies a link_keys message against the trust and returns the new
// trust (Current/Previous/LastSeq updated, Blacklisted kept). The message must chain
// back to the trust anchor: it is signed by the key we currently trust, its seq is
// strictly newer, and `previous` is either our current key (rotation) or absent with
// an unchanged current key (retire of the previous key). Any failure leaves the
// input trust unchanged (the returned trust is then the zero value).
func ApplyLinkKeys(trust LinkTrust, msg []byte) (LinkTrust, error) {
	if len(trust.Current) != ed25519.PublicKeySize {
		return LinkTrust{}, linkErr(LinkErrNoTrust, false, nil)
	}
	if len(msg) > maxLinkMessageLen {
		return LinkTrust{}, linkErr(LinkErrMsgInvalid, true, errors.New("message too large"))
	}
	var m linkKeysMsg
	if err := json.Unmarshal(msg, &m); err != nil {
		return LinkTrust{}, linkErr(LinkErrMsgInvalid, true, nil)
	}
	newCur, err1 := base64.RawURLEncoding.DecodeString(m.CurrentPub)
	var prev []byte
	var err2 error
	if m.PreviousPub != "" {
		prev, err2 = base64.RawURLEncoding.DecodeString(m.PreviousPub)
	}
	sig, err3 := base64.RawURLEncoding.DecodeString(m.Sig)
	if err1 != nil || err2 != nil || err3 != nil || len(newCur) != ed25519.PublicKeySize ||
		(len(prev) != 0 && len(prev) != ed25519.PublicKeySize) || len(sig) != ed25519.SignatureSize {
		return LinkTrust{}, linkErr(LinkErrMsgInvalid, true, nil)
	}
	if (m.CurrentKID != "" && m.CurrentKID != LinkKID(newCur)) ||
		(len(prev) != 0 && m.PreviousKID != "" && m.PreviousKID != LinkKID(prev)) {
		return LinkTrust{}, linkErr(LinkErrMsgInvalid, true, errors.New("kid does not match key"))
	}
	// seq first: a message we already applied (full state re-sent on reconnect) is
	// signed by a key that is no longer our current one, so it must be reported as a
	// replay, not as a broken chain.
	if m.Seq <= trust.LastSeq {
		return LinkTrust{}, linkErr(LinkErrMsgSeq, true, ErrLinkSeqReplay)
	}
	if !ed25519.Verify(trust.Current, linkKeysSigInput(newCur, prev, m.Seq), sig) {
		return LinkTrust{}, linkErr(LinkErrMsgChain, true, nil)
	}
	cur := ed25519.PublicKey(newCur)
	switch {
	case len(prev) != 0 && string(prev) == string(trust.Current) && string(cur) != string(trust.Current):
		// rotation: old current becomes previous
	case len(prev) == 0 && string(cur) == string(trust.Current):
		// retire-link-previous announcement: window closed
	default:
		return LinkTrust{}, linkErr(LinkErrMsgChain, true, errors.New("previous key is not the trusted current key"))
	}
	out := trust
	out.Current = cur
	out.Previous = nil
	if len(prev) != 0 {
		out.Previous = ed25519.PublicKey(prev)
	}
	out.LastSeq = m.Seq
	return out, nil
}

// IsLinkRole reports whether role is exactly one of the two link roles.
func IsLinkRole(role string) bool {
	return validLinkRole(strings.TrimSpace(role)) && role == strings.TrimSpace(role)
}
