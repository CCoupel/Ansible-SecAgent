package auth

// R4 (v3.0.4, QA survivors): VerifyLinkKeysReplay accepts a re-sent link_keys only when it is signed by a key
// we trust AND announces exactly the keys we trust. Each equality needs its own test — a frame genuinely signed
// by a trusted key but announcing other keys must never be taken for a re-send. Mutants killed: "announced
// current == trusted current" removed, "announced previous == trusted previous" removed, "previous accepted on
// a closed window".

import (
	"crypto/ed25519"
	"testing"
)

func signedKeys(t *testing.T, signer ed25519.PrivateKey, cur, prev ed25519.PublicKey, seq uint64) []byte {
	t.Helper()
	b, err := SignLinkKeys(signer, cur, prev, seq)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestVerifyLinkKeysReplay_RejectsValidlySignedFramesAnnouncingOtherKeys(t *testing.T) {
	aPub, aPriv, _ := GenerateLinkKey()
	bPub, bPriv, _ := GenerateLinkKey()
	cPub, _, _ := GenerateLinkKey()
	open := LinkTrust{Current: bPub, Previous: aPub} // rotation A -> B in progress
	closed := LinkTrust{Current: bPub}               // window closed

	// controls: the genuine re-sends are accepted
	if _, err := VerifyLinkKeysReplay(open, signedKeys(t, aPriv, bPub, aPub, 7)); err != nil {
		t.Fatalf("control, open window: %v", err)
	}
	if _, err := VerifyLinkKeysReplay(closed, signedKeys(t, bPriv, bPub, nil, 8)); err != nil {
		t.Fatalf("control, closed window: %v", err)
	}
	// open window, signed by the previous key (A), announcing a current key that is not ours
	if _, err := VerifyLinkKeysReplay(open, signedKeys(t, aPriv, cPub, aPub, 9)); err == nil {
		t.Error("open window: an announced current key different from the trusted one was accepted")
	}
	// open window, signed by A, current right, previous not ours
	if _, err := VerifyLinkKeysReplay(open, signedKeys(t, aPriv, bPub, cPub, 9)); err == nil {
		t.Error("open window: an announced previous key different from the trusted one was accepted")
	}
	// closed window, signed by the trusted current key (B), announcing a previous key
	if _, err := VerifyLinkKeysReplay(closed, signedKeys(t, bPriv, bPub, aPub, 9)); err == nil {
		t.Error("closed window: a previous key announced on a closed window was accepted")
	}
	// signed by a stranger: never
	_, strangerPriv, _ := GenerateLinkKey()
	for name, tr := range map[string]LinkTrust{"open": open, "closed": closed} {
		if _, err := VerifyLinkKeysReplay(tr, signedKeys(t, strangerPriv, bPub, tr.Previous, 9)); err == nil {
			t.Errorf("%s window: a frame signed by an unknown key was accepted", name)
		}
	}
}
