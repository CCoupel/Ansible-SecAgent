package storage

// Link tokens and link keys (v3.0.4, #141/#146): the registry of the link tokens minted by the root,
// the Ed25519 signing key (sealed by the caller, enc:), the single sequence counter and the trust
// anchor of a non-root relay. Every write is ONE state mutation.

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strconv"
	"time"

	"secagent-server/cmd/secagent-server/internal/state"
)

// Keys of server_config (non secret) holding the link counters.
const (
	configLinkSeq         = "link_seq"          // the single counter: revocation, rotation, retire
	configLinkRotationSeq = "link_rotation_seq" // seq of the rotation that opened the double-acceptation window
)

// LinkToken is a registry entry (metadata only: never the token nor its hash).
type LinkToken = state.LinkToken

// LinkTrust is the trust anchor of a non-root relay.
type LinkTrust = state.LinkTrust

// ErrLinkKeyExists: a signing key is already stored.
var ErrLinkKeyExists = errors.New("link signing key already exists")

// ErrPreviousNotRetired: a rotation window is still open.
var ErrPreviousNotRetired = errors.New("previous link key not retired")

// ErrNoPreviousKey: there is no previous key to retire.
var ErrNoPreviousKey = errors.New("no previous link key")

// LinkRevocation is one revoked link token (jti and token expiry, unix seconds).
type LinkRevocation struct {
	JTI string
	Exp int64
}

func configUint(snap state.Snapshot, key string) uint64 {
	v, _ := snap.Config(key)
	n, _ := strconv.ParseUint(v, 10, 64)
	return n
}

func txConfigUint(tx *state.Tx, key string) uint64 {
	v, _ := tx.Config(key)
	n, _ := strconv.ParseUint(v, 10, 64)
	return n
}

// LinkSigningKeys returns the sealed (enc:) signing keys; "" when absent.
func (s *Store) LinkSigningKeys() (current, previous string) {
	snap := s.snap()
	current, _ = snap.Config(state.ConfigLinkSigningKeyCurrent)
	previous, _ = snap.Config(state.ConfigLinkSigningKeyPrevious)
	return current, previous
}

// LinkSeq returns the single counter and the seq of the rotation that opened the open window.
func (s *Store) LinkSeq() (seq, rotationSeq uint64) {
	snap := s.snap()
	return configUint(snap, configLinkSeq), configUint(snap, configLinkRotationSeq)
}

// SetLinkSigningKeyIfAbsent stores the sealed signing key unless one exists (two concurrent lazy
// generations: the first wins, the loser gets ErrLinkKeyExists and must use the stored key).
func (s *Store) SetLinkSigningKeyIfAbsent(sealed string) error {
	err := s.mutate(func(tx *state.Tx) error {
		if v, ok := tx.Config(state.ConfigLinkSigningKeyCurrent); ok && v != "" {
			return ErrLinkKeyExists
		}
		return tx.SetConfig(state.ConfigLinkSigningKeyCurrent, sealed)
	})
	if errors.Is(err, ErrLinkKeyExists) {
		return ErrLinkKeyExists
	}
	if err != nil {
		return fmt.Errorf("store link signing key: %w", err)
	}
	return nil
}

// RotateLinkKey makes the current key the previous one (previousSealed: the old current key sealed
// again with the binding of the PREVIOUS field) and installs newSealed as current; the
// counter is incremented in the same mutation and recorded as the rotation seq. It returns the new
// seq. ErrPreviousNotRetired when a window is still open (one rotation in flight at most).
// wantCurrent is the sealed current key the caller based its decision on (lost-update guard).
func (s *Store) RotateLinkKey(newSealed, previousSealed, wantCurrent string) (uint64, error) {
	var seq uint64
	err := s.mutate(func(tx *state.Tx) error {
		cur, _ := tx.Config(state.ConfigLinkSigningKeyCurrent)
		if cur == "" || cur != wantCurrent {
			return fmt.Errorf("%w: the current link key changed", state.ErrInvalid)
		}
		if prev, _ := tx.Config(state.ConfigLinkSigningKeyPrevious); prev != "" {
			return ErrPreviousNotRetired
		}
		seq = txConfigUint(tx, configLinkSeq) + 1
		for k, v := range map[string]string{
			state.ConfigLinkSigningKeyPrevious: previousSealed,
			state.ConfigLinkSigningKeyCurrent:  newSealed,
			configLinkSeq:                      strconv.FormatUint(seq, 10),
			configLinkRotationSeq:              strconv.FormatUint(seq, 10),
		} {
			if err := tx.SetConfig(k, v); err != nil {
				return err
			}
		}
		return nil
	})
	if errors.Is(err, ErrPreviousNotRetired) {
		return 0, ErrPreviousNotRetired
	}
	if err != nil {
		return 0, fmt.Errorf("rotate link key: %w", err)
	}
	return seq, nil
}

// RetireLinkPrevious closes the double-acceptation window; the counter is incremented in the same
// mutation. It returns the new seq.
func (s *Store) RetireLinkPrevious() (uint64, error) {
	var seq uint64
	err := s.mutate(func(tx *state.Tx) error {
		if prev, _ := tx.Config(state.ConfigLinkSigningKeyPrevious); prev == "" {
			return ErrNoPreviousKey
		}
		tx.DeleteConfig(state.ConfigLinkSigningKeyPrevious)
		tx.DeleteConfig(configLinkRotationSeq)
		seq = txConfigUint(tx, configLinkSeq) + 1
		return tx.SetConfig(configLinkSeq, strconv.FormatUint(seq, 10))
	})
	if errors.Is(err, ErrNoPreviousKey) {
		return 0, ErrNoPreviousKey
	}
	if err != nil {
		return 0, fmt.Errorf("retire link key: %w", err)
	}
	return seq, nil
}

// CreateLinkToken registers a minted link token. The signing key must exist (invariant).
func (s *Store) CreateLinkToken(ctx context.Context, t LinkToken) error {
	if err := s.mutate(func(tx *state.Tx) error { return tx.PutLinkToken(t) }); err != nil {
		return fmt.Errorf("register link token: %w", err)
	}
	return nil
}

// ListLinkTokens returns the registry, sorted by id.
func (s *Store) ListLinkTokens() []LinkToken { return s.snap().LinkTokens() }

// GetLinkToken returns one entry.
func (s *Store) GetLinkToken(id string) (LinkToken, bool) { return s.snap().LinkToken(id) }

// RevokeLinkToken, in ONE mutation: sets revoked_at, blacklists the JTI until the token expires and
// increments the counter. found=false when the id is unknown. Idempotent for an already revoked
// token (no second increment). seq is the counter after the call.
func (s *Store) RevokeLinkToken(ctx context.Context, id string) (tok LinkToken, found bool, seq uint64, err error) {
	err = s.mutate(func(tx *state.Tx) error {
		t, ok := tx.LinkToken(id)
		if !ok {
			return nil
		}
		found = true
		seq = txConfigUint(tx, configLinkSeq)
		if t.RevokedAt != nil {
			tok = t
			return nil
		}
		now := nowUTC()
		t.RevokedAt = &now
		if err := putBlacklist(tx, t.JTI, t.Sub, "link token revoked", now, t.ExpiresAt.UTC()); err != nil {
			return err
		}
		if err := tx.PutLinkToken(t); err != nil {
			return err
		}
		seq++
		if err := tx.SetConfig(configLinkSeq, strconv.FormatUint(seq, 10)); err != nil {
			return err
		}
		tok = t
		return nil
	})
	if err != nil {
		return LinkToken{}, false, 0, fmt.Errorf("revoke link token: %w", err)
	}
	if found {
		log.Printf("Link token revoked: id=%q role=%q sub=%q aud=%q seq=%d", tok.ID, tok.Role, tok.Sub, tok.Aud, seq)
	}
	return tok, found, seq, nil
}

// LinkRevocations lists the revoked link tokens that have not expired (the full list sent when a
// link is established), sorted by JTI.
func (s *Store) LinkRevocations(now time.Time) []LinkRevocation {
	var out []LinkRevocation
	for _, t := range s.snap().LinkTokens() {
		if t.RevokedAt != nil && t.ExpiresAt.After(now) {
			out = append(out, LinkRevocation{JTI: t.JTI, Exp: t.ExpiresAt.Unix()})
		}
	}
	return out
}

// LinkTrust returns the trust anchor of this (non-root) relay; the zero value when none.
func (s *Store) LinkTrust() LinkTrust { return s.snap().LinkTrust() }

// SetLinkTrust replaces the trust anchor (a zero value clears it).
func (s *Store) SetLinkTrust(ctx context.Context, lt LinkTrust) error {
	if err := s.mutate(func(tx *state.Tx) error { return tx.SetLinkTrust(lt) }); err != nil {
		return fmt.Errorf("set link trust: %w", err)
	}
	return nil
}

// ApplyLinkRevocations (non-root): in ONE mutation adds the revoked JTI to the blacklist (until their
// expiry) and records seq as the last accepted message. Entries already expired are skipped; the
// blacklist is only ever extended.
func (s *Store) ApplyLinkRevocations(ctx context.Context, seq uint64, entries []LinkRevocation) error {
	err := s.mutate(func(tx *state.Tx) error {
		now := nowUTC()
		for _, e := range entries {
			exp := time.Unix(e.Exp, 0).UTC()
			if !exp.After(now) {
				continue
			}
			if err := putBlacklist(tx, e.JTI, "", "link token revoked by the root", now, exp); err != nil {
				return err
			}
		}
		lt := tx.LinkTrust()
		if seq > lt.Seq {
			lt.Seq = seq
			return tx.SetLinkTrust(lt)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("apply link revocations: %w", err)
	}
	return nil
}
