package auth

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type linkFixture struct {
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
	now  time.Time
}

func newLinkFixture(t *testing.T) *linkFixture {
	t.Helper()
	pub, priv, err := GenerateLinkKey()
	if err != nil {
		t.Fatal(err)
	}
	return &linkFixture{pub: pub, priv: priv, now: time.Now()}
}

func (f *linkFixture) trust() LinkTrust { return LinkTrust{Current: f.pub} }

func (f *linkFixture) mint(t *testing.T, sub, aud, role string) string {
	t.Helper()
	tok, _, err := SignLinkToken(f.priv, "root", sub, aud, role, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// forge signs arbitrary claims/headers with the given method and key.
func forge(t *testing.T, m jwt.SigningMethod, key any, kid string, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(m, claims)
	if kid != "" {
		tok.Header["kid"] = kid
	}
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func goodClaims(now time.Time) jwt.MapClaims {
	return jwt.MapClaims{"iss": "root", "sub": "child", "aud": "parent", "role": RoleRelayChild,
		"jti": "j1", "iat": now.Unix(), "exp": now.Add(time.Hour).Unix()}
}

func wantCode(t *testing.T, err error, code string, permanent bool) {
	t.Helper()
	var le *LinkError
	if !errors.As(err, &le) {
		t.Fatalf("want LinkError %s, got %v", code, err)
	}
	if le.Code != code || le.Permanent != permanent {
		t.Fatalf("want %s permanent=%v, got %s permanent=%v", code, permanent, le.Code, le.Permanent)
	}
}

func TestLinkJWT_RoundTrip(t *testing.T) {
	f := newLinkFixture(t)
	tok := f.mint(t, "child", "parent", RoleRelayChild)
	c, err := VerifyLinkToken(f.trust(), tok, LinkWant{LocalID: "parent", RootID: "root", Role: RoleRelayChild}, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if c.Issuer != "root" || c.Subject != "child" || c.Audience != "parent" || c.Role != RoleRelayChild ||
		c.JTI == "" || c.KID != LinkKID(f.pub) {
		t.Fatalf("claims = %+v", c)
	}
	// the push direction
	tok = f.mint(t, "parent", "child", RoleRelayParent)
	if _, err = VerifyLinkToken(f.trust(), tok, LinkWant{LocalID: "child", RootID: "root", Role: RoleRelayParent}, f.now); err != nil {
		t.Fatal(err)
	}
}

func TestLinkJWT_Refusals(t *testing.T) {
	f := newLinkFixture(t)
	other, otherPriv, _ := GenerateLinkKey()
	_ = other
	want := LinkWant{LocalID: "parent", RootID: "root", Role: RoleRelayChild}
	kid := LinkKID(f.pub)

	tests := []struct {
		name      string
		token     string
		trust     LinkTrust
		code      string
		permanent bool
	}{
		{"wrong signer, right kid", forge(t, jwt.SigningMethodEdDSA, otherPriv, kid, goodClaims(f.now)), f.trust(), LinkErrSignature, true},
		{"unknown kid", forge(t, jwt.SigningMethodEdDSA, f.priv, "nope", goodClaims(f.now)), f.trust(), LinkErrKID, true},
		{"kid absent", forge(t, jwt.SigningMethodEdDSA, f.priv, "", goodClaims(f.now)), f.trust(), LinkErrMissingKID, true},
		{"iss absent", forge(t, jwt.SigningMethodEdDSA, f.priv, kid, func() jwt.MapClaims { c := goodClaims(f.now); delete(c, "iss"); return c }()), f.trust(), LinkErrIssuer, true},
		{"iss other relay", forge(t, jwt.SigningMethodEdDSA, f.priv, kid, func() jwt.MapClaims { c := goodClaims(f.now); c["iss"] = "evil"; return c }()), f.trust(), LinkErrIssuer, true},
		{"aud absent", forge(t, jwt.SigningMethodEdDSA, f.priv, kid, func() jwt.MapClaims { c := goodClaims(f.now); delete(c, "aud"); return c }()), f.trust(), LinkErrMissingAud, true},
		{"aud other relay", forge(t, jwt.SigningMethodEdDSA, f.priv, kid, func() jwt.MapClaims { c := goodClaims(f.now); c["aud"] = "Q"; return c }()), f.trust(), LinkErrAudience, true},
		{"aud multiple", forge(t, jwt.SigningMethodEdDSA, f.priv, kid, func() jwt.MapClaims { c := goodClaims(f.now); c["aud"] = []string{"parent", "Q"}; return c }()), f.trust(), LinkErrAudience, true},
		{"role push presented on pull", forge(t, jwt.SigningMethodEdDSA, f.priv, kid, func() jwt.MapClaims { c := goodClaims(f.now); c["role"] = RoleRelayParent; return c }()), f.trust(), LinkErrRole, true},
		{"role agent", forge(t, jwt.SigningMethodEdDSA, f.priv, kid, func() jwt.MapClaims { c := goodClaims(f.now); c["role"] = "agent"; return c }()), f.trust(), LinkErrRole, true},
		{"legacy role relay", forge(t, jwt.SigningMethodEdDSA, f.priv, kid, func() jwt.MapClaims { c := goodClaims(f.now); c["role"] = RoleRelayLegacy; return c }()), f.trust(), LinkErrLegacyRole, true},
		{"expired", forge(t, jwt.SigningMethodEdDSA, f.priv, kid, func() jwt.MapClaims {
			c := goodClaims(f.now)
			c["iat"], c["exp"] = f.now.Add(-2*time.Hour).Unix(), f.now.Add(-time.Hour).Unix()
			return c
		}()), f.trust(), LinkErrExpired, true},
		{"exp absent", forge(t, jwt.SigningMethodEdDSA, f.priv, kid, func() jwt.MapClaims { c := goodClaims(f.now); delete(c, "exp"); return c }()), f.trust(), LinkErrClaims, true},
		{"jti absent", forge(t, jwt.SigningMethodEdDSA, f.priv, kid, func() jwt.MapClaims { c := goodClaims(f.now); delete(c, "jti"); return c }()), f.trust(), LinkErrClaims, true},
		{"iat in the future", forge(t, jwt.SigningMethodEdDSA, f.priv, kid, func() jwt.MapClaims { c := goodClaims(f.now); c["iat"] = f.now.Add(time.Hour).Unix(); return c }()), f.trust(), LinkErrClaims, true},
		{"blacklisted jti", forge(t, jwt.SigningMethodEdDSA, f.priv, kid, goodClaims(f.now)),
			LinkTrust{Current: f.pub, Blacklisted: func(j string) bool { return j == "j1" }}, LinkErrRevoked, true},
		{"garbage", "not.a.jwt", f.trust(), LinkErrMalformed, true},
		{"empty", "", f.trust(), LinkErrMalformed, true},
		{"no trust anchor yet", forge(t, jwt.SigningMethodEdDSA, f.priv, kid, goodClaims(f.now)), LinkTrust{}, LinkErrNoTrust, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := VerifyLinkToken(tt.trust, tt.token, want, f.now)
			wantCode(t, err, tt.code, tt.permanent)
		})
	}
}

// Algorithm confusion: none of these has a verification path.
func TestLinkJWT_AlgorithmConfusion(t *testing.T) {
	f := newLinkFixture(t)
	want := LinkWant{LocalID: "parent", RootID: "root", Role: RoleRelayChild}
	kid := LinkKID(f.pub)
	c := goodClaims(f.now)

	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tokens := map[string]string{
		"HS256 keyed with the public key":     forge(t, jwt.SigningMethodHS256, []byte(f.pub), kid, c),
		"HS512 keyed with the public key":     forge(t, jwt.SigningMethodHS512, []byte(f.pub), kid, c),
		"alg none":                            forge(t, jwt.SigningMethodNone, jwt.UnsafeAllowNoneSignatureType, kid, c),
		"RS256":                               forge(t, jwt.SigningMethodRS256, rsaKey, kid, c),
		"ES256":                               forge(t, jwt.SigningMethodES256, ecKey, kid, c),
		"HS256 with the v3.0.3 shared secret": forge(t, jwt.SigningMethodHS256, []byte("test"), kid, c),
	}
	for name, tok := range tokens {
		t.Run(name, func(t *testing.T) {
			_, err := VerifyLinkToken(f.trust(), tok, want, f.now)
			wantCode(t, err, LinkErrAlg, true)
		})
	}
	// "none" with the signature stripped to nothing, hand-built
	hand := strings.Join([]string{"eyJhbGciOiJub25lIiwia2lkIjoi" + "In0", "e30", ""}, ".")
	if _, err := VerifyLinkToken(f.trust(), hand, want, f.now); err == nil {
		t.Fatal("unsigned token accepted")
	}
	// the HS256 service must not mint something the link verifier accepts
	raw, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": "parent", "role": "relay-parent", "jti": "j",
		"iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix()}).SignedString([]byte("secret"))
	if _, err := VerifyLinkToken(f.trust(), raw, want, f.now); err == nil {
		t.Fatal("HS256 relay token accepted by the link verifier")
	}
}

func TestLinkJWT_Rotation(t *testing.T) {
	f := newLinkFixture(t)
	newPub, newPriv, _ := GenerateLinkKey()
	want := LinkWant{LocalID: "parent", RootID: "root", Role: RoleRelayChild}
	oldTok := f.mint(t, "child", "parent", RoleRelayChild)
	newTok, _, _ := SignLinkToken(newPriv, "root", "child", "parent", RoleRelayChild, time.Hour)

	during := LinkTrust{Current: newPub, Previous: f.pub}
	for name, tok := range map[string]string{"old key": oldTok, "new key": newTok} {
		if _, err := VerifyLinkToken(during, tok, want, f.now); err != nil {
			t.Fatalf("%s during the window: %v", name, err)
		}
	}
	after := LinkTrust{Current: newPub} // retire-link-previous
	_, err := VerifyLinkToken(after, oldTok, want, f.now)
	wantCode(t, err, LinkErrKID, true) // mutation "previous kid always accepted" dies here
	if _, err = VerifyLinkToken(after, newTok, want, f.now); err != nil {
		t.Fatal(err)
	}
}

func TestLinkJWT_SignRefusals(t *testing.T) {
	f := newLinkFixture(t)
	if _, _, err := SignLinkToken(f.priv, "root", "c", "p", RoleRelayLegacy, time.Hour); err == nil {
		t.Fatal("legacy role minted")
	}
	if _, _, err := SignLinkToken(f.priv, "root", "c", "p", RoleRelayChild, 0); err == nil {
		t.Fatal("token without expiry minted")
	}
	if _, _, err := SignLinkToken(f.priv, "root", "c", "", RoleRelayChild, time.Hour); err == nil {
		t.Fatal("token without aud minted")
	}
	if _, _, err := SignLinkToken(nil, "root", "c", "p", RoleRelayChild, time.Hour); err == nil {
		t.Fatal("token minted without key")
	}
}

func TestLinkJWT_Revocations(t *testing.T) {
	f := newLinkFixture(t)
	_, otherPriv, _ := GenerateLinkKey()
	entries := []LinkRevocation{{JTI: "a", Exp: 100}, {JTI: "b", Exp: 200}}
	msg, err := SignLinkRevocations(f.priv, 5, entries)
	if err != nil {
		t.Fatal(err)
	}
	seq, got, err := VerifyLinkRevocations(LinkTrust{Current: f.pub, LastSeq: 4}, msg)
	if err != nil || seq != 5 || len(got) != 2 || got[1].JTI != "b" {
		t.Fatalf("got %d %v %v", seq, got, err)
	}
	// replay: seq == last and seq < last (mutation "seq not verified" dies here)
	for _, last := range []uint64{5, 9} {
		_, _, err = VerifyLinkRevocations(LinkTrust{Current: f.pub, LastSeq: last}, msg)
		wantCode(t, err, LinkErrMsgSeq, true)
		if !errors.Is(err, ErrLinkSeqReplay) {
			t.Fatal("ErrLinkSeqReplay not wrapped")
		}
	}
	// wrong signer
	bad, _ := SignLinkRevocations(otherPriv, 6, entries)
	_, _, err = VerifyLinkRevocations(LinkTrust{Current: f.pub}, bad)
	wantCode(t, err, LinkErrMsgSignature, true)
	// tampered entries / seq
	tampered := strings.Replace(string(msg), `"jti":"a"`, `"jti":"z"`, 1)
	_, _, err = VerifyLinkRevocations(LinkTrust{Current: f.pub}, []byte(tampered))
	wantCode(t, err, LinkErrMsgSignature, true)
	tampered = strings.Replace(string(msg), `"seq":5`, `"seq":50`, 1)
	_, _, err = VerifyLinkRevocations(LinkTrust{Current: f.pub}, []byte(tampered))
	wantCode(t, err, LinkErrMsgSignature, true)
	// the previous key cannot sign revocations
	newPub, _, _ := GenerateLinkKey()
	_, _, err = VerifyLinkRevocations(LinkTrust{Current: newPub, Previous: f.pub}, msg)
	wantCode(t, err, LinkErrMsgSignature, true)
	// malformed
	_, _, err = VerifyLinkRevocations(LinkTrust{Current: f.pub}, []byte(`{"seq":1}`))
	wantCode(t, err, LinkErrMsgInvalid, true)
	_, _, err = VerifyLinkRevocations(LinkTrust{Current: f.pub}, []byte(`nope`))
	wantCode(t, err, LinkErrMsgInvalid, true)
	// empty list is valid (full state with nothing revoked)
	empty, _ := SignLinkRevocations(f.priv, 1, nil)
	if _, es, err := VerifyLinkRevocations(LinkTrust{Current: f.pub}, empty); err != nil || len(es) != 0 {
		t.Fatalf("empty list: %v %v", es, err)
	}
}

func TestLinkJWT_LinkKeys(t *testing.T) {
	f := newLinkFixture(t)
	newPub, newPriv, _ := GenerateLinkKey()
	_, evilPriv, _ := GenerateLinkKey()
	evilPub := evilPriv.Public().(ed25519.PublicKey)
	anchor := LinkTrust{Current: f.pub, LastSeq: 2, Blacklisted: func(string) bool { return false }}

	msg, err := SignLinkKeys(f.priv, newPub, f.pub, 3)
	if err != nil {
		t.Fatal(err)
	}
	nt, err := ApplyLinkKeys(anchor, msg)
	if err != nil {
		t.Fatal(err)
	}
	if !nt.Current.Equal(newPub) || !nt.Previous.Equal(f.pub) || nt.LastSeq != 3 || nt.Blacklisted == nil {
		t.Fatalf("trust = %+v", nt)
	}
	// replay of the same message: seq no longer newer
	_, err = ApplyLinkKeys(nt, msg)
	wantCode(t, err, LinkErrMsgSeq, true)
	// a compromised parent signing its own key does not chain to the anchor
	forged, _ := SignLinkKeys(evilPriv, evilPub, f.pub, 3)
	_, err = ApplyLinkKeys(anchor, forged)
	wantCode(t, err, LinkErrMsgChain, true)
	// signed by the anchor but previous != our current key
	odd, _ := SignLinkKeys(f.priv, newPub, evilPub, 3)
	_, err = ApplyLinkKeys(anchor, odd)
	wantCode(t, err, LinkErrMsgChain, true)
	// key swap without previous
	swap, _ := SignLinkKeys(f.priv, newPub, nil, 3)
	_, err = ApplyLinkKeys(anchor, swap)
	wantCode(t, err, LinkErrMsgChain, true)
	// tampered current key
	tampered := strings.Replace(string(msg), `"current_pub":"`, `"current_pub":"A`, 1)
	if _, err = ApplyLinkKeys(anchor, []byte(tampered)); err == nil {
		t.Fatal("tampered link_keys accepted")
	}
	// retire announcement: same current, no previous, signed by current
	retire, _ := SignLinkKeys(newPriv, newPub, nil, 4)
	rt, err := ApplyLinkKeys(nt, retire)
	if err != nil || rt.Previous != nil || !rt.Current.Equal(newPub) || rt.LastSeq != 4 {
		t.Fatalf("retire: %+v %v", rt, err)
	}
	// a token of the old key no longer verifies after the retire
	old := f.mint(t, "c", "p", RoleRelayChild)
	_, err = VerifyLinkToken(rt, old, LinkWant{LocalID: "p", RootID: "root", Role: RoleRelayChild}, f.now)
	wantCode(t, err, LinkErrKID, true)
	// failure leaves the trust unchanged (zero value returned, caller keeps its own)
	got, err := ApplyLinkKeys(anchor, forged)
	if err == nil || got.Current != nil {
		t.Fatal("failed apply returned a trust")
	}
	// no anchor
	_, err = ApplyLinkKeys(LinkTrust{}, msg)
	wantCode(t, err, LinkErrNoTrust, false)
}

var _ crypto.Signer = ed25519.PrivateKey(nil)

func TestLinkJWT_SubEqualToAudIsRefused(t *testing.T) {
	f := newLinkFixture(t)
	kid := LinkKID(f.pub)
	c := goodClaims(f.now)
	c["sub"], c["aud"] = "parent", "parent"
	tok := forge(t, jwt.SigningMethodEdDSA, f.priv, kid, c)
	_, err := VerifyLinkToken(f.trust(), tok, LinkWant{LocalID: "parent", RootID: "root", Role: RoleRelayChild}, f.now)
	wantCode(t, err, LinkErrClaims, true)
}

func TestLinkJWT_SignRefusesATTLAboveTheMaximum(t *testing.T) {
	f := newLinkFixture(t)
	if _, _, err := SignLinkToken(f.priv, "root", "c", "p", RoleRelayChild, MaxLinkTTL); err != nil {
		t.Fatalf("the maximum itself must be accepted: %v", err)
	}
	if _, _, err := SignLinkToken(f.priv, "root", "c", "p", RoleRelayChild, MaxLinkTTL+time.Second); err == nil {
		t.Fatal("ttl above the maximum accepted")
	}
	if _, _, err := SignLinkToken(f.priv, "root", "c", "p", RoleRelayChild, 100*365*24*time.Hour); err == nil {
		t.Fatal("100 years accepted")
	}
}

func TestLinkJWT_ValidLinkKIDIsStrict(t *testing.T) {
	f := newLinkFixture(t)
	if !ValidLinkKID(LinkKID(f.pub)) {
		t.Fatal("a real kid must be valid")
	}
	for name, s := range map[string]string{
		"empty": "", "too short": "AAAA", "too long": strings.Repeat("A", 23), "huge": strings.Repeat("A", 1<<20),
		"bad alphabet": "AAAAAAAAAAAAAAAAAAAA+/", "padding": "AAAAAAAAAAAAAAAAAAAAA=", "non canonical last char": "AAAAAAAAAAAAAAAAAAAAAB",
		"space": "AAAAAAAAAAAAAAAAAAAA A", "newline": "AAAAAAAAAAAAAAAAAAAAA\n", "unicode": "AAAAAAAAAAAAAAAAAAAAé",
	} {
		if ValidLinkKID(s) {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestLinkJWT_VerifyLinkKeysReplay(t *testing.T) {
	f := newLinkFixture(t)
	newPub, newPriv, _ := GenerateLinkKey()
	_, evil, _ := GenerateLinkKey()
	rotation, _ := SignLinkKeys(f.priv, newPub, f.pub, 5)
	closing, _ := SignLinkKeys(newPriv, newPub, nil, 6)
	open := LinkTrust{Current: newPub, Previous: f.pub, LastSeq: 5}
	closed := LinkTrust{Current: newPub, LastSeq: 6}

	if seq, err := VerifyLinkKeysReplay(open, rotation); err != nil || seq != 5 {
		t.Fatalf("authentic rotation replay: %d %v", seq, err)
	}
	if seq, err := VerifyLinkKeysReplay(closed, closing); err != nil || seq != 6 {
		t.Fatalf("authentic closing replay: %d %v", seq, err)
	}
	// a relay anchored on the new key with no previous holds nothing able to verify the rotation
	_, err := VerifyLinkKeysReplay(closed, rotation)
	wantCode(t, err, LinkErrMsgChain, true)
	// forged: right keys, wrong signer; the signer announced in the frame is NOT trusted
	forged, _ := SignLinkKeys(evil, newPub, f.pub, 5)
	_, err = VerifyLinkKeysReplay(open, forged)
	wantCode(t, err, LinkErrMsgChain, true)
	selfSigned, _ := SignLinkKeys(evil, newPub, evil.Public().(ed25519.PublicKey), 5) // previous chosen by the attacker
	_, err = VerifyLinkKeysReplay(open, selfSigned)
	wantCode(t, err, LinkErrMsgChain, true)
	// another current key, tampered seq
	other, _ := SignLinkKeys(f.priv, f.pub, nil, 5)
	_, err = VerifyLinkKeysReplay(open, other)
	wantCode(t, err, LinkErrMsgChain, true)
	tampered := strings.Replace(string(rotation), `"seq":5`, `"seq":99999`, 1)
	_, err = VerifyLinkKeysReplay(open, []byte(tampered))
	wantCode(t, err, LinkErrMsgChain, true)
	_, err = VerifyLinkKeysReplay(LinkTrust{}, rotation)
	wantCode(t, err, LinkErrNoTrust, false)
}
