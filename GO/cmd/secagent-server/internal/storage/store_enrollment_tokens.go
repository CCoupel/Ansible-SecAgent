package storage

import (
	"context"
	"fmt"
	"log"
	"sort"
	"time"

	"secagent-server/cmd/secagent-server/internal/state"
)

// EnrollmentToken represents a stored enrollment token (SECURITY.md §3).
type EnrollmentToken struct {
	ID              string
	TokenHash       string     // SHA-256(token) — never the token in clear
	HostnamePattern string     // Go regexp, anchored ^...$
	Reusable        bool       // false = one-shot, true = permanent
	UseCount        int        // incremented on each enrollment
	LastUsedAt      *time.Time // nullable
	CreatedAt       time.Time
	ExpiresAt       *time.Time // nullable — nil means no expiry
	CreatedBy       string
}

func enrollmentFromState(t state.EnrollmentToken) *EnrollmentToken {
	return &EnrollmentToken{ID: t.ID, TokenHash: t.TokenHash, HostnamePattern: t.HostnamePattern, Reusable: t.Reusable,
		UseCount: t.UseCount, LastUsedAt: t.LastUsedAt, CreatedAt: t.CreatedAt, ExpiresAt: t.ExpiresAt, CreatedBy: t.CreatedBy}
}

func secondsUTC(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	v := t.UTC().Truncate(time.Second)
	return &v
}

// CreateEnrollmentToken inserts a new enrollment token (use_count 0, never used).
func (s *Store) CreateEnrollmentToken(ctx context.Context, t EnrollmentToken) error {
	err := s.mutate(func(tx *state.Tx) error {
		if _, exists := tx.EnrollmentToken(t.ID); exists {
			return fmt.Errorf("%w: enrollment token id %q", state.ErrDuplicate, t.ID)
		}
		return tx.PutEnrollmentToken(state.EnrollmentToken{ID: t.ID, TokenHash: t.TokenHash, HostnamePattern: t.HostnamePattern,
			Reusable: t.Reusable, CreatedAt: t.CreatedAt.UTC().Truncate(time.Second), ExpiresAt: secondsUTC(t.ExpiresAt), CreatedBy: t.CreatedBy})
	})
	if err != nil {
		return fmt.Errorf("CreateEnrollmentToken: %w", err)
	}
	log.Printf("Enrollment token created: id=%q pattern=%q reusable=%v", t.ID, t.HostnamePattern, t.Reusable)
	return nil
}

// GetEnrollmentTokenByHash returns the token with this hash, or (nil, nil).
func (s *Store) GetEnrollmentTokenByHash(ctx context.Context, tokenHash string) (*EnrollmentToken, error) {
	t, ok := s.snap().EnrollmentTokenByHash(tokenHash)
	if !ok {
		return nil, nil
	}
	return enrollmentFromState(t), nil
}

// GetEnrollmentTokenByID returns the token with this id, or (nil, nil).
func (s *Store) GetEnrollmentTokenByID(ctx context.Context, id string) (*EnrollmentToken, error) {
	t, ok := s.snap().EnrollmentToken(id)
	if !ok {
		return nil, nil
	}
	return enrollmentFromState(t), nil
}

// ListEnrollmentTokens returns all tokens, newest first.
func (s *Store) ListEnrollmentTokens(ctx context.Context) ([]EnrollmentToken, error) {
	var out []EnrollmentToken
	for _, t := range s.snap().EnrollmentTokens() {
		out = append(out, *enrollmentFromState(t))
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

// ConsumeEnrollmentToken counts one use (use_count + last_used_at). Enrollment itself goes through
// EnrollAgent, which does it in the same mutation as the key and the agent.
func (s *Store) ConsumeEnrollmentToken(ctx context.Context, id string) error {
	now := nowUTC()
	err := s.mutate(func(tx *state.Tx) error {
		t, ok := tx.EnrollmentToken(id)
		if !ok {
			return fmt.Errorf("token not found id=%s", id)
		}
		t.UseCount++
		t.LastUsedAt = &now
		return tx.PutEnrollmentToken(t)
	})
	if err != nil {
		return fmt.Errorf("ConsumeEnrollmentToken: %w", err)
	}
	log.Printf("Enrollment token consumed: id=%q", id)
	return nil
}

// DeleteEnrollmentToken removes a token; reports whether it existed.
func (s *Store) DeleteEnrollmentToken(ctx context.Context, id string) (bool, error) {
	deleted := false
	if err := s.mutate(func(tx *state.Tx) error { deleted = tx.DeleteEnrollmentToken(id); return nil }); err != nil {
		return false, fmt.Errorf("DeleteEnrollmentToken: %w", err)
	}
	if deleted {
		log.Printf("Enrollment token deleted: id=%q", id)
	}
	return deleted, nil
}

func (s *Store) purgeEnrollmentTokens(match func(state.EnrollmentToken) bool) (int64, error) {
	any := false
	for _, t := range s.snap().EnrollmentTokens() {
		if match(t) {
			any = true
			break
		}
	}
	if !any {
		return 0, nil
	}
	n := 0
	err := s.mutate(func(tx *state.Tx) error {
		n = 0
		for _, t := range s.snap().EnrollmentTokens() {
			if match(t) && tx.DeleteEnrollmentToken(t.ID) {
				n++
			}
		}
		return nil
	})
	return int64(n), err
}

// PurgeExpiredEnrollmentTokens removes the tokens whose expiry has passed.
func (s *Store) PurgeExpiredEnrollmentTokens(ctx context.Context) (int64, error) {
	now := time.Now().UTC()
	n, err := s.purgeEnrollmentTokens(func(t state.EnrollmentToken) bool { return t.ExpiresAt != nil && !t.ExpiresAt.After(now) })
	if err != nil {
		return 0, fmt.Errorf("PurgeExpiredEnrollmentTokens: %w", err)
	}
	if n > 0 {
		log.Printf("Expired enrollment tokens purged: count=%d", n)
	}
	return n, nil
}

// PurgeUsedOneShotEnrollmentTokens removes the one-shot tokens that were used.
func (s *Store) PurgeUsedOneShotEnrollmentTokens(ctx context.Context) (int64, error) {
	n, err := s.purgeEnrollmentTokens(func(t state.EnrollmentToken) bool { return !t.Reusable && t.UseCount > 0 })
	if err != nil {
		return 0, fmt.Errorf("PurgeUsedOneShotEnrollmentTokens: %w", err)
	}
	if n > 0 {
		log.Printf("Used one-shot enrollment tokens purged: count=%d", n)
	}
	return n, nil
}
