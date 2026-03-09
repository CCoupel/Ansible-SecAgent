package storage

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"time"
)

// EnrollmentToken represents a token authorizing agent enrollment.
// Matches SECURITY.md §3 table schema exactly.
type EnrollmentToken struct {
	ID              string
	TokenHash       string    // SHA-256(token) — never the token in clear
	HostnamePattern string    // Go regexp, anchored ^...$
	Reusable        bool      // false = one-shot, true = permanent
	UseCount        int       // incremented on each enrollment
	LastUsedAt      *time.Time // nullable
	CreatedAt       time.Time
	ExpiresAt       *time.Time // nullable — nil means no expiry
	CreatedBy       string
}

// CreateEnrollmentToken inserts a new enrollment token.
// id and tokenHash must be pre-computed by the caller (UUID + SHA-256).
func (s *Store) CreateEnrollmentToken(ctx context.Context, t EnrollmentToken) error {
	s.dbMu.Lock()
	defer s.dbMu.Unlock()

	createdAt := t.CreatedAt.UTC().Unix()

	var expiresAt interface{}
	if t.ExpiresAt != nil {
		expiresAt = t.ExpiresAt.UTC().Unix()
	}

	reusable := 0
	if t.Reusable {
		reusable = 1
	}

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO enrollment_tokens
			(id, token_hash, hostname_pattern, reusable, use_count, last_used_at, created_at, expires_at, created_by)
		VALUES (?, ?, ?, ?, 0, NULL, ?, ?, ?)
	`, t.ID, t.TokenHash, t.HostnamePattern, reusable, createdAt, expiresAt, t.CreatedBy)
	if err != nil {
		return fmt.Errorf("CreateEnrollmentToken: %w", err)
	}

	log.Printf("Enrollment token created: id=%s pattern=%s reusable=%v", t.ID, t.HostnamePattern, t.Reusable)
	return nil
}

// GetEnrollmentTokenByHash returns the token matching the given SHA-256 hash,
// or nil if not found.
func (s *Store) GetEnrollmentTokenByHash(ctx context.Context, tokenHash string) (*EnrollmentToken, error) {
	s.dbMu.RLock()
	defer s.dbMu.RUnlock()

	row := s.db.QueryRowContext(ctx, `
		SELECT id, token_hash, hostname_pattern, reusable, use_count,
		       last_used_at, created_at, expires_at, created_by
		FROM enrollment_tokens
		WHERE token_hash = ?
	`, tokenHash)

	return scanEnrollmentToken(row)
}

// GetEnrollmentTokenByID returns the token matching the given UUID.
func (s *Store) GetEnrollmentTokenByID(ctx context.Context, id string) (*EnrollmentToken, error) {
	s.dbMu.RLock()
	defer s.dbMu.RUnlock()

	row := s.db.QueryRowContext(ctx, `
		SELECT id, token_hash, hostname_pattern, reusable, use_count,
		       last_used_at, created_at, expires_at, created_by
		FROM enrollment_tokens
		WHERE id = ?
	`, id)

	return scanEnrollmentToken(row)
}

// ListEnrollmentTokens returns all enrollment tokens ordered by created_at desc.
func (s *Store) ListEnrollmentTokens(ctx context.Context) ([]EnrollmentToken, error) {
	s.dbMu.RLock()
	defer s.dbMu.RUnlock()

	rows, err := s.db.QueryContext(ctx, `
		SELECT id, token_hash, hostname_pattern, reusable, use_count,
		       last_used_at, created_at, expires_at, created_by
		FROM enrollment_tokens
		ORDER BY created_at DESC
	`)
	if err != nil {
		return nil, fmt.Errorf("ListEnrollmentTokens: %w", err)
	}
	defer rows.Close()

	var tokens []EnrollmentToken
	for rows.Next() {
		t, err := scanEnrollmentTokenRow(rows)
		if err != nil {
			return nil, fmt.Errorf("ListEnrollmentTokens scan: %w", err)
		}
		tokens = append(tokens, *t)
	}
	return tokens, rows.Err()
}

// ConsumeEnrollmentToken increments use_count and updates last_used_at.
// Must be called within the enrollment transaction after all validations pass.
func (s *Store) ConsumeEnrollmentToken(ctx context.Context, id string) error {
	s.dbMu.Lock()
	defer s.dbMu.Unlock()

	now := time.Now().UTC().Unix()
	result, err := s.db.ExecContext(ctx, `
		UPDATE enrollment_tokens
		SET use_count = use_count + 1, last_used_at = ?
		WHERE id = ?
	`, now, id)
	if err != nil {
		return fmt.Errorf("ConsumeEnrollmentToken: %w", err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("ConsumeEnrollmentToken rows: %w", err)
	}
	if affected == 0 {
		return fmt.Errorf("ConsumeEnrollmentToken: token not found id=%s", id)
	}

	log.Printf("Enrollment token consumed: id=%s", id)
	return nil
}

// DeleteEnrollmentToken removes a token permanently.
// Returns (true, nil) if deleted, (false, nil) if not found.
func (s *Store) DeleteEnrollmentToken(ctx context.Context, id string) (bool, error) {
	s.dbMu.Lock()
	defer s.dbMu.Unlock()

	result, err := s.db.ExecContext(ctx,
		"DELETE FROM enrollment_tokens WHERE id = ?", id)
	if err != nil {
		return false, fmt.Errorf("DeleteEnrollmentToken: %w", err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("DeleteEnrollmentToken rows: %w", err)
	}

	deleted := affected > 0
	if deleted {
		log.Printf("Enrollment token deleted: id=%s", id)
	}
	return deleted, nil
}

// PurgeExpiredEnrollmentTokens removes tokens whose expires_at is in the past.
func (s *Store) PurgeExpiredEnrollmentTokens(ctx context.Context) (int64, error) {
	s.dbMu.Lock()
	defer s.dbMu.Unlock()

	now := time.Now().UTC().Unix()
	result, err := s.db.ExecContext(ctx,
		"DELETE FROM enrollment_tokens WHERE expires_at IS NOT NULL AND expires_at <= ?", now)
	if err != nil {
		return 0, fmt.Errorf("PurgeExpiredEnrollmentTokens: %w", err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("PurgeExpiredEnrollmentTokens rows: %w", err)
	}

	if affected > 0 {
		log.Printf("Expired enrollment tokens purged: count=%d", affected)
	}
	return affected, nil
}

// PurgeUsedOneShotEnrollmentTokens removes one-shot tokens that have been consumed.
func (s *Store) PurgeUsedOneShotEnrollmentTokens(ctx context.Context) (int64, error) {
	s.dbMu.Lock()
	defer s.dbMu.Unlock()

	result, err := s.db.ExecContext(ctx,
		"DELETE FROM enrollment_tokens WHERE reusable = 0 AND use_count > 0")
	if err != nil {
		return 0, fmt.Errorf("PurgeUsedOneShotEnrollmentTokens: %w", err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("PurgeUsedOneShotEnrollmentTokens rows: %w", err)
	}

	if affected > 0 {
		log.Printf("Used one-shot enrollment tokens purged: count=%d", affected)
	}
	return affected, nil
}

// ========================================================================
// internal scan helpers
// ========================================================================

func scanEnrollmentToken(row *sql.Row) (*EnrollmentToken, error) {
	var t EnrollmentToken
	var reusable int
	var lastUsedAtUnix sql.NullInt64
	var createdAtUnix int64
	var expiresAtUnix sql.NullInt64
	var createdBy sql.NullString

	err := row.Scan(
		&t.ID, &t.TokenHash, &t.HostnamePattern,
		&reusable, &t.UseCount,
		&lastUsedAtUnix, &createdAtUnix, &expiresAtUnix, &createdBy,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("scan enrollment token: %w", err)
	}

	t.Reusable = reusable != 0
	t.CreatedAt = time.Unix(createdAtUnix, 0).UTC()
	if lastUsedAtUnix.Valid {
		ts := time.Unix(lastUsedAtUnix.Int64, 0).UTC()
		t.LastUsedAt = &ts
	}
	if expiresAtUnix.Valid {
		ts := time.Unix(expiresAtUnix.Int64, 0).UTC()
		t.ExpiresAt = &ts
	}
	if createdBy.Valid {
		t.CreatedBy = createdBy.String
	}

	return &t, nil
}

func scanEnrollmentTokenRow(rows *sql.Rows) (*EnrollmentToken, error) {
	var t EnrollmentToken
	var reusable int
	var lastUsedAtUnix sql.NullInt64
	var createdAtUnix int64
	var expiresAtUnix sql.NullInt64
	var createdBy sql.NullString

	err := rows.Scan(
		&t.ID, &t.TokenHash, &t.HostnamePattern,
		&reusable, &t.UseCount,
		&lastUsedAtUnix, &createdAtUnix, &expiresAtUnix, &createdBy,
	)
	if err != nil {
		return nil, fmt.Errorf("scan enrollment token row: %w", err)
	}

	t.Reusable = reusable != 0
	t.CreatedAt = time.Unix(createdAtUnix, 0).UTC()
	if lastUsedAtUnix.Valid {
		ts := time.Unix(lastUsedAtUnix.Int64, 0).UTC()
		t.LastUsedAt = &ts
	}
	if expiresAtUnix.Valid {
		ts := time.Unix(expiresAtUnix.Int64, 0).UTC()
		t.ExpiresAt = &ts
	}
	if createdBy.Valid {
		t.CreatedBy = createdBy.String
	}

	return &t, nil
}
