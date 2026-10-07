package auth

// #141 / #146 (L1c) — SPECIFICATION tests of the inter-relay link tokens: the single wiring point.
//
// The tests of this lot (linkjwt_spec_*_test.go) forge their tokens and messages THEMSELVES, with
// golang-jwt and crypto/ed25519 (they do not trust the signer under test), then ask the verifier
// under test for a verdict through the specLinkImpl below. The implementation of L1c (auth/linkjwt.go,
// dev-agent) is plugged in by ONE file, which the dev creates and owns:
//
//	// linkjwt_spec_wire_test.go
//	func init() { specLinkImplUnderTest = &specLinkImpl{ ... } }
//
// Until that file exists, every test that needs the real verifier is SKIPPED (it is not passing
// artificially: the report lists them as "pending L1c"). The oracle tests (linkjwt_spec_oracle_test.go)
// run today: they prove that the checks accept a correct verifier and kill the mutants
// "aud not verified", "previous kid always accepted" and "seq not verified".
//
// Wire format (plan rev2 §1.2, §1.6, §1.7), the contract the verifier must honour:
//   - link token: JWT, header alg=EdDSA (the ONLY accepted alg) and kid = fingerprint of the root
//     public key; claims iss (root relay_id), sub (presenter), aud (verifier), role
//     ("relay-child" pull / "relay-parent" push), jti, iat, exp (all mandatory);
//   - the verifier accepts kid ∈ {current, previous} of the trust anchor, aud == local relay id, the
//     role expected for the direction, a non expired token and a JTI that is not blacklisted;
//   - link_revocations: {seq, entries:[{jti,exp}], sig}, signed by the root `current` key, accepted
//     only if seq is strictly greater than the last accepted seq;
//   - link_keys: {current_pub, previous_pub, seq, sig}: the new current key signed by the OLD current
//     key, it must chain back to the anchor, otherwise the trust is left unchanged.

import (
	"crypto/ed25519"
	"time"
)

// specLinkTrust is what a relay trusts: the root public keys (anchor + rotation) and its blacklist.
// A nil Previous = the double acceptation window is over (retire-link-previous).
type specLinkTrust struct {
	Current     ed25519.PublicKey
	Previous    ed25519.PublicKey
	Blacklisted func(jti string) bool // nil = nothing blacklisted
	LastSeq     uint64                // last accepted link_revocations / link_keys seq
}

// specLinkWant is what the local relay expects from the presenter.
type specLinkWant struct {
	LocalID string // aud must equal this
	Role    string // "relay-child" (we are the parent, pull link) or "relay-parent" (we are the child, push link)
}

// specRevEntry is one revoked link token.
type specRevEntry struct {
	JTI string `json:"jti"`
	Exp int64  `json:"exp"`
}

// specLinkImpl is the surface of the L1c implementation used by the spec tests. Every field must be
// set by the wiring file. The functions take and return plain types so the dev picks the real API.
type specLinkImpl struct {
	// KidOf returns the `kid` header the implementation expects for a root public key.
	KidOf func(pub ed25519.PublicKey) string

	// VerifyToken returns nil when the link token is accepted. permanent=true means the refusal must
	// never be retried by the child (wrong role, legacy role, wrong audience, bad signature...).
	VerifyToken func(trust specLinkTrust, token string, want specLinkWant, now time.Time) (permanent bool, err error)

	// SignToken mints a link token with the real signer (used for the round trip checks only).
	SignToken func(priv ed25519.PrivateKey, iss, sub, aud, role string, ttl time.Duration) (token, jti string, err error)

	// SignRevocations / VerifyRevocations: the link_revocations message, opaque to the test.
	SignRevocations   func(priv ed25519.PrivateKey, seq uint64, entries []specRevEntry) (msg []byte, err error)
	VerifyRevocations func(trust specLinkTrust, msg []byte) (seq uint64, entries []specRevEntry, err error)

	// SignLinkKeys / ApplyLinkKeys: the link_keys rotation message. oldPriv is the OLD current key.
	SignLinkKeys  func(oldPriv ed25519.PrivateKey, newCurrent, previous ed25519.PublicKey, seq uint64) (msg []byte, err error)
	ApplyLinkKeys func(trust specLinkTrust, msg []byte) (specLinkTrust, error)
}

// specLinkImplUnderTest is set by linkjwt_spec_wire_test.go (dev-agent, L1c). nil = pending L1c.
var specLinkImplUnderTest *specLinkImpl
