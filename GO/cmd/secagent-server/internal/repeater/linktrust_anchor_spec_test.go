// SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
// SPDX-License-Identifier: AGPL-3.0-or-later

package repeater

// #218 (LOT-3, decision D4: NO tolerance, fail closed) — a relay whose pinned root key file
// (REPEATER_ROOT_LINK_KEY_FILE) is stale refuses to start, as before, but the refusal now EXPLAINS itself:
//
//	- the kid of the pinned file, the persisted current kid and the persisted previous kid (fingerprints, 22
//	  characters: the only identifiers allowed);
//	- the probable cause (the file predates a rotation that was retired) ;
//	- the two remedies with their command: `keys link-pubkey` (re-export from the root) and
//	  `state link-trust reset` (offline).
//
// NO key and no full fingerprint may appear in the message (public keys are not secret, but the output of
// a refusal goes to logs and tickets: only kids are allowed). The refusal never writes the persisted trust,
// and the already accepted chain (pinned == current or == previous) is unchanged: no new tolerance.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"secagent-server/cmd/secagent-server/internal/auth"
)

func genKey(t *testing.T) ed25519.PublicKey {
	t.Helper()
	pub, _, err := auth.GenerateLinkKey()
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

func recordOf(root string, cur, prev ed25519.PublicKey, seq uint64) TrustRecord {
	r := TrustRecord{RootID: root, CurrentPub: b64(cur), CurrentKID: auth.LinkKID(cur), Seq: seq}
	if prev != nil {
		r.PreviousPub, r.PreviousKID = b64(prev), auth.LinkKID(prev)
	}
	return r
}

// forbidden lists every full representation of a key that must not appear in a refusal.
func forbidden(keys ...ed25519.PublicKey) map[string]string {
	out := map[string]string{}
	for i, k := range keys {
		sum := sha256.Sum256(k)
		out[b64(k)] = "public key (base64url) #" + string(rune('0'+i))
		out[base64.StdEncoding.EncodeToString(k)] = "public key (base64) #" + string(rune('0'+i))
		out[hex.EncodeToString(k)] = "public key (hex) #" + string(rune('0'+i))
		out[b64(sum[:])] = "full SHA-256 (base64url) #" + string(rune('0'+i))
		out[hex.EncodeToString(sum[:])] = "full SHA-256 (hex) #" + string(rune('0'+i))
	}
	return out
}

func refusal(t *testing.T, store *fakeTrustStore, root string, anchor ed25519.PublicKey) string {
	t.Helper()
	savesBefore, recBefore := store.saves, store.rec
	_, err := NewLinkTrust(LinkTrustConfig{RootID: root, Anchor: anchor, Store: store, Blacklist: &fakeBlacklist{}})
	if !errors.Is(err, ErrAnchorMismatch) {
		t.Fatalf("a stale pinned key must refuse the start with ErrAnchorMismatch, got %v", err)
	}
	if store.saves != savesBefore || store.rec != recBefore {
		t.Error("a refused start must not write the persisted trust")
	}
	return err.Error()
}

// Typical case: the key was rotated and the previous one retired; the pinned file is the ORIGINAL one.
func TestAnchorMismatch_TheRefusalNamesKidsCauseAndRemedies(t *testing.T) {
	stale, cur := genKey(t), genKey(t)
	store := &fakeTrustStore{rec: recordOf("root", cur, nil, 2)}
	msg := refusal(t, store, "root", stale)

	for _, want := range []struct{ what, needle string }{
		{"the kid of the pinned file", auth.LinkKID(stale)},
		{"the persisted current kid", auth.LinkKID(cur)},
		{"the remedy `keys link-pubkey`", "keys link-pubkey"},
		{"the remedy `state link-trust reset`", "state link-trust reset"},
		{"the name of the pinned file variable", "REPEATER_ROOT_LINK_KEY_FILE"},
	} {
		if !strings.Contains(msg, want.needle) {
			t.Errorf("the refusal must contain %s (%q):\n%s", want.what, want.needle, msg)
		}
	}
	low := strings.ToLower(msg)
	stale1 := strings.Contains(low, "stale") || strings.Contains(low, "outdated") || strings.Contains(low, "older") || strings.Contains(low, "predate") || strings.Contains(low, "old key")
	if !strings.Contains(low, "rotat") || !stale1 {
		t.Errorf("the refusal must give the probable cause (a pinned file older than a rotation):\n%s", msg)
	}
	for needle, what := range forbidden(stale, cur) {
		if strings.Contains(msg, needle) {
			t.Errorf("the refusal leaks the %s:\n%s", what, msg)
		}
	}
}

// With an open rotation window the persisted PREVIOUS kid is reported too (three kids).
func TestAnchorMismatch_ThePreviousKidIsReportedWhenAWindowIsOpen(t *testing.T) {
	stale, prev, cur := genKey(t), genKey(t), genKey(t) // the file is two rotations old
	store := &fakeTrustStore{rec: recordOf("root", cur, prev, 3)}
	msg := refusal(t, store, "root", stale)
	for _, kid := range []string{auth.LinkKID(stale), auth.LinkKID(prev), auth.LinkKID(cur)} {
		if !strings.Contains(msg, kid) {
			t.Errorf("the refusal must contain kid %s:\n%s", kid, msg)
		}
	}
	for needle, what := range forbidden(stale, prev, cur) {
		if strings.Contains(msg, needle) {
			t.Errorf("the refusal leaks the %s:\n%s", what, msg)
		}
	}
}

// D4 — no new tolerance: the chain accepted today is the only one. An older file than the previous key is refused.
func TestAnchorMismatch_NoToleranceBeyondTheAlreadyAcceptedChain(t *testing.T) {
	older, prev, cur := genKey(t), genKey(t), genKey(t)
	for name, anchor := range map[string]ed25519.PublicKey{"current key": cur, "previous key": prev} {
		store := &fakeTrustStore{rec: recordOf("root", cur, prev, 3)}
		if _, err := NewLinkTrust(LinkTrustConfig{RootID: "root", Anchor: anchor, Store: store, Blacklist: &fakeBlacklist{}}); err != nil {
			t.Errorf("a file holding the %s is part of the verified chain and must start: %v", name, err)
		}
	}
	store := &fakeTrustStore{rec: recordOf("root", cur, prev, 3)}
	_ = refusal(t, store, "root", older) // a file older than the previous key: refused
	store = &fakeTrustStore{rec: recordOf("root", cur, nil, 2)}
	_ = refusal(t, store, "root", prev) // the previous key once RETIRED is no longer in the chain
}

// A different root identity is refused with both identities named (they are not secret) and a remedy.
func TestAnchorMismatch_ADifferentRootIdentityIsExplained(t *testing.T) {
	cur := genKey(t)
	store := &fakeTrustStore{rec: recordOf("root-a", cur, nil, 1)}
	msg := refusal(t, store, "root-b", cur)
	for _, want := range []string{"root-a", "root-b"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the refusal must name the root identity %q:\n%s", want, msg)
		}
	}
	if !strings.Contains(msg, "REPEATER_ROOT_ID") && !strings.Contains(msg, "state link-trust reset") {
		t.Errorf("the refusal must point to a remedy (REPEATER_ROOT_ID or state link-trust reset):\n%s", msg)
	}
	for needle, what := range forbidden(cur) {
		if strings.Contains(msg, needle) {
			t.Errorf("the refusal leaks the %s", what)
		}
	}
}

// The refusal reaches the operator's log line as one clean line (no newline that would hide the remedy in a
// multi-line journal) and stays bounded.
func TestAnchorMismatch_TheMessageIsOneBoundedLine(t *testing.T) {
	stale, cur := genKey(t), genKey(t)
	msg := refusal(t, &fakeTrustStore{rec: recordOf("root", cur, nil, 2)}, "root", stale)
	if strings.ContainsAny(msg, "\r\n") {
		t.Errorf("the refusal must be a single line (journals split on newlines):\n%q", msg)
	}
	if len(msg) > 1024 {
		t.Errorf("the refusal is %d bytes long, keep it under 1 KiB", len(msg))
	}
}
