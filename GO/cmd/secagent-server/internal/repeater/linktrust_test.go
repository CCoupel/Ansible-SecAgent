package repeater

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"secagent-server/cmd/secagent-server/internal/auth"
)

type fakeTrustStore struct {
	mu      sync.Mutex
	rec     TrustRecord
	saves   int
	failing bool
}

func (s *fakeTrustStore) LoadLinkTrust() (TrustRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.rec, nil
}
func (s *fakeTrustStore) SaveLinkTrust(r TrustRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failing {
		return errors.New("disk full")
	}
	s.rec, s.saves = r, s.saves+1
	return nil
}

type fakeBlacklist struct {
	mu   sync.Mutex
	m    map[string]time.Time
	fail bool
}

func (b *fakeBlacklist) BlacklistLinkJTI(jti string, exp time.Time) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.fail {
		return errors.New("write failed")
	}
	if b.m == nil {
		b.m = map[string]time.Time{}
	}
	b.m[jti] = exp
	return nil
}
func (b *fakeBlacklist) IsLinkJTIBlacklisted(jti string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	_, ok := b.m[jti]
	return ok
}

type lt struct {
	m     *LinkTrust
	store *fakeTrustStore
	bl    *fakeBlacklist
	pub   ed25519.PublicKey
	priv  ed25519.PrivateKey
	fwd   [][]byte
	rev   []string
}

func newLT(t *testing.T) *lt {
	t.Helper()
	pub, priv, err := auth.GenerateLinkKey()
	if err != nil {
		t.Fatal(err)
	}
	f := &lt{store: &fakeTrustStore{}, bl: &fakeBlacklist{}, pub: pub, priv: priv}
	m, err := NewLinkTrust(LinkTrustConfig{RootID: "root", Anchor: pub, Store: f.store, Blacklist: f.bl})
	if err != nil {
		t.Fatal(err)
	}
	m.OnForward(func(raw []byte) { f.fwd = append(f.fwd, raw) })
	m.OnRevoked(func(jti string) { f.rev = append(f.rev, jti) })
	f.m = m
	return f
}

func (f *lt) revocations(t *testing.T, priv ed25519.PrivateKey, seq uint64, jtis ...string) []byte {
	t.Helper()
	var es []auth.LinkRevocation
	for _, j := range jtis {
		es = append(es, auth.LinkRevocation{JTI: j, Exp: time.Now().Add(time.Hour).Unix()})
	}
	b, err := auth.SignLinkRevocations(priv, seq, es)
	if err != nil {
		t.Fatal(err)
	}
	return withType(b, "link_revocations")
}

func withType(b []byte, typ string) []byte {
	return []byte(`{"type":"` + typ + `",` + strings.TrimPrefix(string(b), "{"))
}

func (f *lt) keys(t *testing.T, signer ed25519.PrivateKey, newPub, prev ed25519.PublicKey, seq uint64) []byte {
	t.Helper()
	b, err := auth.SignLinkKeys(signer, newPub, prev, seq)
	if err != nil {
		t.Fatal(err)
	}
	return withType(b, "link_keys")
}

func TestLinkTrust_UnanchoredFailsClosed(t *testing.T) {
	m, err := NewLinkTrust(LinkTrustConfig{RootID: "root", Store: &fakeTrustStore{}, Blacklist: &fakeBlacklist{}})
	if err != nil {
		t.Fatal(err)
	}
	if m.Anchored() {
		t.Fatal("anchored without a key")
	}
	pub, priv, _ := auth.GenerateLinkKey()
	_ = pub
	tok, _, _ := auth.SignLinkToken(priv, "root", "c", "p", auth.RoleRelayChild, time.Hour)
	_, err = m.VerifyToken(tok, "p", auth.RoleRelayChild, time.Now())
	var le *auth.LinkError
	if !errors.As(err, &le) || le.Code != auth.LinkErrNoTrust {
		t.Fatalf("want link_trust_missing, got %v", err)
	}
	if _, err := m.HandleFrame([]byte(`{"type":"link_keys"}`)); err == nil {
		t.Fatal("frame accepted without anchor")
	}
}

func TestLinkTrust_AnchorIsPersistedAndVerifies(t *testing.T) {
	f := newLT(t)
	if !f.m.Anchored() || f.store.rec.CurrentPub == "" || f.store.rec.RootID != "root" || f.store.rec.CurrentKID != auth.LinkKID(f.pub) {
		t.Fatalf("record = %+v", f.store.rec)
	}
	tok, _, _ := auth.SignLinkToken(f.priv, "root", "child", "me", auth.RoleRelayChild, time.Hour)
	if _, err := f.m.VerifyToken(tok, "me", auth.RoleRelayChild, time.Now()); err != nil {
		t.Fatal(err)
	}
	// a token signed by another key, or with another issuer, is refused
	_, other, _ := auth.GenerateLinkKey()
	tok2, _, _ := auth.SignLinkToken(other, "root", "child", "me", auth.RoleRelayChild, time.Hour)
	if _, err := f.m.VerifyToken(tok2, "me", auth.RoleRelayChild, time.Now()); err == nil {
		t.Fatal("token of another root accepted")
	}
	tok3, _, _ := auth.SignLinkToken(f.priv, "evil", "child", "me", auth.RoleRelayChild, time.Hour)
	if _, err := f.m.VerifyToken(tok3, "me", auth.RoleRelayChild, time.Now()); err == nil {
		t.Fatal("wrong issuer accepted")
	}
}

func TestLinkTrust_StartupAgainstPersistedState(t *testing.T) {
	f := newLT(t)
	// restart with the same file: fine, state kept
	if _, err := NewLinkTrust(LinkTrustConfig{RootID: "root", Anchor: f.pub, Store: f.store, Blacklist: f.bl}); err != nil {
		t.Fatal(err)
	}
	// rotate, then restart with the OLD pinned file (previous key): valid chain, persisted trust wins
	newPub, newPriv, _ := auth.GenerateLinkKey()
	if _, err := f.m.HandleFrame(f.keys(t, f.priv, newPub, f.pub, 1)); err != nil {
		t.Fatal(err)
	}
	m2, err := NewLinkTrust(LinkTrustConfig{RootID: "root", Anchor: f.pub, Store: f.store, Blacklist: f.bl})
	if err != nil {
		t.Fatalf("old file is the previous key: %v", err)
	}
	if seq, kid := m2.State(); seq != 1 || kid != auth.LinkKID(newPub) {
		t.Fatalf("state = %d %s", seq, kid)
	}
	// the new file too
	if _, err := NewLinkTrust(LinkTrustConfig{RootID: "root", Anchor: newPub, Store: f.store, Blacklist: f.bl}); err != nil {
		t.Fatal(err)
	}
	// a stranger key disagrees: refuse to start
	stranger, _, _ := auth.GenerateLinkKey()
	if _, err := NewLinkTrust(LinkTrustConfig{RootID: "root", Anchor: stranger, Store: f.store, Blacklist: f.bl}); !errors.Is(err, ErrAnchorMismatch) {
		t.Fatalf("got %v", err)
	}
	// another root identity: refuse to start
	if _, err := NewLinkTrust(LinkTrustConfig{RootID: "other", Anchor: newPub, Store: f.store, Blacklist: f.bl}); !errors.Is(err, ErrAnchorMismatch) {
		t.Fatalf("got %v", err)
	}
	// no file but persisted trust: still anchored (restart without the file)
	m3, err := NewLinkTrust(LinkTrustConfig{Store: f.store, Blacklist: f.bl})
	if err != nil || !m3.Anchored() || m3.RootID() != "root" {
		t.Fatalf("persisted-only start: %v anchored=%v", err, m3 != nil && m3.Anchored())
	}
	_ = newPriv
	// a pinned key needs the root id
	if _, err := NewLinkTrust(LinkTrustConfig{Anchor: f.pub, Store: &fakeTrustStore{}, Blacklist: f.bl}); err == nil {
		t.Fatal("pinned key without root id accepted")
	}
}

func TestLinkTrust_RotationChain(t *testing.T) {
	f := newLT(t)
	newPub, newPriv, _ := auth.GenerateLinkKey()
	_, evil, _ := auth.GenerateLinkKey()
	evilPub := evil.Public().(ed25519.PublicKey)

	// a compromised parent signs its own key: refused, trust unchanged, nothing forwarded or saved
	saves := f.store.saves
	if _, err := f.m.HandleFrame(f.keys(t, evil, evilPub, f.pub, 1)); err == nil {
		t.Fatal("forged rotation accepted")
	}
	if f.store.saves != saves || len(f.fwd) != 0 {
		t.Fatal("forged rotation had effects")
	}
	// the genuine rotation
	frame := f.keys(t, f.priv, newPub, f.pub, 1)
	res, err := f.m.HandleFrame(frame)
	if err != nil || !res.Applied || res.KID != auth.LinkKID(newPub) {
		t.Fatalf("%+v %v", res, err)
	}
	if string(f.fwd[0]) != string(frame) {
		t.Fatal("frame not forwarded byte for byte")
	}
	// double acceptation: tokens of both keys verify
	for _, k := range []ed25519.PrivateKey{f.priv, newPriv} {
		tok, _, _ := auth.SignLinkToken(k, "root", "c", "me", auth.RoleRelayChild, time.Hour)
		if _, err := f.m.VerifyToken(tok, "me", auth.RoleRelayChild, time.Now()); err != nil {
			t.Fatalf("during the window: %v", err)
		}
	}
	// replay of the same rotation: benign, no second save, children still get it on Replay
	saves = f.store.saves
	if res, err := f.m.HandleFrame(frame); err != nil || res.Applied {
		t.Fatalf("replay: %+v %v", res, err)
	}
	if f.store.saves != saves {
		t.Fatal("replay saved")
	}
	if rp := f.m.Replay(); len(rp) != 1 || string(rp[0]) != string(frame) {
		t.Fatalf("replay frames = %d", len(rp))
	}
	// the window closes (signed by the current key, previous absent)
	closeFrame := f.keys(t, newPriv, newPub, nil, 2)
	if res, err := f.m.HandleFrame(closeFrame); err != nil || !res.Applied {
		t.Fatalf("close: %+v %v", res, err)
	}
	old, _, _ := auth.SignLinkToken(f.priv, "root", "c", "me", auth.RoleRelayChild, time.Hour)
	if _, err := f.m.VerifyToken(old, "me", auth.RoleRelayChild, time.Now()); err == nil {
		t.Fatal("old key still accepted after retire")
	}
	if len(f.m.Replay()) != 0 {
		t.Fatal("closed rotation still replayed")
	}
	if f.store.rec.PreviousPub != "" || f.store.rec.Seq != 2 {
		t.Fatalf("record = %+v", f.store.rec)
	}
}

func TestLinkTrust_PersistFailureKeepsTheOldTrust(t *testing.T) {
	f := newLT(t)
	newPub, _, _ := auth.GenerateLinkKey()
	f.store.failing = true
	if _, err := f.m.HandleFrame(f.keys(t, f.priv, newPub, f.pub, 1)); err == nil {
		t.Fatal("applied although the write failed")
	}
	if _, kid := f.m.State(); kid != auth.LinkKID(f.pub) {
		t.Fatal("in-memory trust changed after a failed write")
	}
	if seq, _ := f.m.State(); seq != 0 {
		t.Fatal("seq advanced")
	}
	// same for revocations: blacklist write fails -> seq not advanced
	f.store.failing = false
	f.bl.fail = true
	if _, err := f.m.HandleFrame(f.revocations(t, f.priv, 3, "j1")); err == nil {
		t.Fatal("revocation applied although the blacklist write failed")
	}
	if seq, _ := f.m.State(); seq != 0 {
		t.Fatal("seq advanced on blacklist failure")
	}
}

func TestLinkTrust_Revocations(t *testing.T) {
	f := newLT(t)
	frame := f.revocations(t, f.priv, 4, "j1", "j2")
	res, err := f.m.HandleFrame(frame)
	if err != nil || !res.Applied || len(res.Revoked) != 2 || res.Seq != 4 {
		t.Fatalf("%+v %v", res, err)
	}
	if !f.bl.IsLinkJTIBlacklisted("j1") || !f.bl.IsLinkJTIBlacklisted("j2") {
		t.Fatal("not blacklisted")
	}
	if strings.Join(f.rev, ",") != "j1,j2" || len(f.fwd) != 1 || string(f.fwd[0]) != string(frame) {
		t.Fatalf("listeners/forward: %v %d", f.rev, len(f.fwd))
	}
	if f.store.rec.Seq != 4 {
		t.Fatalf("seq not persisted: %+v", f.store.rec)
	}
	// a blacklisted jti is refused by VerifyToken
	tok := f.mintWithJTI(t, "j1")
	if _, err := f.m.VerifyToken(tok, "me", auth.RoleRelayChild, time.Now()); err == nil {
		t.Fatal("revoked token accepted")
	}
	// an older list (rollback) and a forged one: refused / ignored, nothing forwarded
	n := len(f.fwd)
	if res, _ := f.m.HandleFrame(f.revocations(t, f.priv, 2, "jx")); res.Applied || f.bl.IsLinkJTIBlacklisted("jx") {
		t.Fatal("rollback applied")
	}
	_, evil, _ := auth.GenerateLinkKey()
	if _, err := f.m.HandleFrame(f.revocations(t, evil, 9, "jy")); err == nil || f.bl.IsLinkJTIBlacklisted("jy") {
		t.Fatal("forged list applied")
	}
	if seq, _ := f.m.State(); seq != 4 || len(f.fwd) != n {
		t.Fatalf("seq %d fwd %d", seq, len(f.fwd))
	}
	// the full list re-sent at the SAME seq on reconnection: re-synchronised (idempotent), forwarded
	f.m.ResetFrames()
	full := f.revocations(t, f.priv, 4, "j1", "j2", "j3")
	res, err = f.m.HandleFrame(full)
	if err != nil || !res.Applied || len(res.Revoked) != 1 || res.Revoked[0] != "j3" {
		t.Fatalf("resync: %+v %v", res, err)
	}
	if seq, _ := f.m.State(); seq != 4 {
		t.Fatal("resync moved seq")
	}
	if rp := f.m.Replay(); len(rp) != 1 || string(rp[0]) != string(full) {
		t.Fatalf("replay = %d", len(rp))
	}
	// expired entries are not blacklisted
	exp, _ := auth.SignLinkRevocations(f.priv, 5, []auth.LinkRevocation{{JTI: "old", Exp: time.Now().Add(-time.Hour).Unix()}})
	if res, err := f.m.HandleFrame(withType(exp, "link_revocations")); err != nil || len(res.Revoked) != 0 || f.bl.IsLinkJTIBlacklisted("old") {
		t.Fatalf("expired entry: %+v %v", res, err)
	}
}

func (f *lt) mintWithJTI(t *testing.T, jti string) string {
	t.Helper()
	// a token whose jti is chosen: forged with the root key (test only)
	return forgeLinkToken(t, f.priv, jti)
}

func TestLinkTrust_UnknownTypeAndGarbage(t *testing.T) {
	f := newLT(t)
	if _, err := f.m.HandleFrame([]byte(`{"type":"nope"}`)); err == nil {
		t.Fatal("unknown type accepted")
	}
	if _, err := f.m.HandleFrame([]byte(`garbage`)); err == nil {
		t.Fatal("garbage accepted")
	}
}

func TestLinkTrust_NoSecretOrKeyInLogs(t *testing.T) {
	f := newLT(t)
	var buf strings.Builder
	prevOut, prevFlags := logWriterSwap(&buf)
	defer logWriterRestore(prevOut, prevFlags)
	_, evil, _ := auth.GenerateLinkKey()
	frame := f.revocations(t, evil, 9, "jy")
	_, _ = f.m.HandleFrame(frame)
	if strings.Contains(buf.String(), string(frame)) || strings.Contains(buf.String(), b64(f.pub)) {
		t.Fatalf("log leaks a frame or a key: %s", buf.String())
	}
	if !strings.Contains(buf.String(), "SECURITY WARNING") {
		t.Fatalf("no security warning: %q", buf.String())
	}
}

// A relay deployed AFTER the rotation is anchored on the new key: it holds no key able to verify the
// replayed rotation (signed by the old one). The frame is NOT trusted: ignored without a security
// warning, not relayed, not remembered, no link_state. The confirmation comes from the verified
// link_revocations whose seq is authenticated by the current key.
func TestLinkTrust_RotationReplayOnAnAnchoredOnNewKeyRelayIsIgnoredNotConfirmed(t *testing.T) {
	root := newLT(t)
	newPub, newPriv, _ := auth.GenerateLinkKey()
	frame := root.keys(t, root.priv, newPub, root.pub, 7) // authentic rotation, signed by the old key

	store, bl := &fakeTrustStore{}, &fakeBlacklist{}
	m, err := NewLinkTrust(LinkTrustConfig{RootID: "root", Anchor: newPub, Store: store, Blacklist: bl})
	if err != nil {
		t.Fatal(err)
	}
	var fwd [][]byte
	m.OnForward(func(raw []byte) { fwd = append(fwd, raw) })
	saves := store.saves
	var buf strings.Builder
	prevOut, prevFlags := logWriterSwap(&buf)
	defer logWriterRestore(prevOut, prevFlags)

	res, err := m.HandleFrame(frame)
	if err != nil || res.Applied || res.Confirm {
		t.Fatalf("%+v %v", res, err)
	}
	if store.saves != saves || len(fwd) != 0 || len(m.Replay()) != 0 {
		t.Fatal("an unverifiable replay was written, relayed or remembered")
	}
	if strings.Contains(buf.String(), "SECURITY WARNING") {
		t.Fatalf("the nominal case must not raise a security warning: %s", buf.String())
	}
	// the confirmation: a verified revocation list at the rotation's seq
	rev := root.revocations(t, newPriv, 7)
	res, err = m.HandleFrame(rev)
	if err != nil || !res.Applied || res.Seq != 7 {
		t.Fatalf("revocations: %+v %v", res, err)
	}
}

// R4 (audit): a FORGED link_keys carrying the trusted current key, a garbage signature and a huge seq
// is never relayed, remembered nor confirmed — during an open rotation (Previous != nil) or not.
func TestLinkTrust_ForgedKeysReplayIsNeverRelayedRememberedOrConfirmed(t *testing.T) {
	for _, openRotation := range []bool{false, true} {
		f := newLT(t)
		cur, curPriv := f.pub, f.priv
		if openRotation {
			newPub, newPriv, _ := auth.GenerateLinkKey()
			if _, err := f.m.HandleFrame(f.keys(t, f.priv, newPub, f.pub, 1)); err != nil {
				t.Fatal(err)
			}
			cur, curPriv = newPub, newPriv
			f.fwd, f.rev = nil, nil
		}
		_ = curPriv
		bogus := base64.RawURLEncoding.EncodeToString(make([]byte, 64))
		for name, frame := range map[string]string{
			"garbage signature":                   `{"type":"link_keys","current_pub":"` + b64(cur) + `","current_kid":"` + auth.LinkKID(cur) + `","seq":99999,"sig":"` + bogus + `"}`,
			"garbage signature + chosen previous": `{"type":"link_keys","current_pub":"` + b64(cur) + `","previous_pub":"` + b64(f.pub) + `","seq":99999,"sig":"` + bogus + `"}`,
			"seq replay with garbage signature":   `{"type":"link_keys","current_pub":"` + b64(cur) + `","seq":1,"sig":"` + bogus + `"}`,
		} {
			saves := f.store.saves
			res, err := f.m.HandleFrame([]byte(frame))
			if res.Applied || res.Confirm || res.Seq == 99999 {
				t.Errorf("open=%v %s: accepted: %+v %v", openRotation, name, res, err)
			}
			if len(f.fwd) != 0 || f.store.saves != saves {
				t.Errorf("open=%v %s: relayed or written", openRotation, name)
			}
			if rp := f.m.Replay(); len(rp) > 1 || (len(rp) == 1 && strings.Contains(string(rp[0]), "99999")) {
				t.Errorf("open=%v %s: remembered", openRotation, name)
			}
		}
		if seq, _ := f.m.State(); seq > 1 {
			t.Errorf("open=%v: seq moved to %d", openRotation, seq)
		}
	}
}

// An authentic re-send (same rotation, signature of the previous key we trust) is confirmed with OUR
// authenticated seq, relayed and remembered; a re-send of the closed window too.
func TestLinkTrust_AuthenticKeysReplayIsConfirmed(t *testing.T) {
	f := newLT(t)
	newPub, newPriv, _ := auth.GenerateLinkKey()
	frame := f.keys(t, f.priv, newPub, f.pub, 4)
	if _, err := f.m.HandleFrame(frame); err != nil {
		t.Fatal(err)
	}
	f.fwd = nil
	saves := f.store.saves
	res, err := f.m.HandleFrame(frame)
	if err != nil || res.Applied || !res.Confirm || res.Seq != 4 {
		t.Fatalf("%+v %v", res, err)
	}
	if f.store.saves != saves || len(f.fwd) != 1 || len(f.m.Replay()) != 1 {
		t.Fatal("authentic replay: expected relayed + remembered, nothing written")
	}
	closeFrame := f.keys(t, newPriv, newPub, nil, 5)
	if _, err := f.m.HandleFrame(closeFrame); err != nil {
		t.Fatal(err)
	}
	f.fwd = nil
	if res, err := f.m.HandleFrame(closeFrame); err != nil || !res.Confirm || res.Seq != 5 {
		t.Fatalf("closed window replay: %+v %v", res, err)
	}
	if len(f.m.Replay()) != 0 {
		t.Fatal("closed window must not be remembered")
	}
}

// A really broken chain is still refused with a warning: unknown key, forged signature.
func TestLinkTrust_BrokenChainIsStillRefused(t *testing.T) {
	f := newLT(t)
	_, evil, _ := auth.GenerateLinkKey()
	evilPub := evil.Public().(ed25519.PublicKey)
	var buf strings.Builder
	prevOut, prevFlags := logWriterSwap(&buf)
	defer logWriterRestore(prevOut, prevFlags)

	res, err := f.m.HandleFrame(f.keys(t, evil, evilPub, f.pub, 3)) // unknown current key, forged signature
	if err == nil || res.Confirm || res.Applied {
		t.Fatalf("%+v %v", res, err)
	}
	if !strings.Contains(buf.String(), "SECURITY WARNING") {
		t.Fatal("a broken chain must warn")
	}
	// the announced current key is ours but the frame is garbage: not confirmed either
	if _, err := f.m.HandleFrame([]byte(`{"type":"link_keys","current_pub":"x","seq":1}`)); err == nil {
		t.Fatal("malformed frame accepted")
	}
}
