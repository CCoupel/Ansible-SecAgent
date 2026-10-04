package storage

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"time"
)

// RelayParentToken is the persisted metadata of a relay-parent JWT minted on this (child)
// relay for its parent (#150). The JWT itself is never stored: only its identifier (JTI).
type RelayParentToken struct {
	ID          string // internal id used by `tokens revoke`
	JTI         string // JWT identifier (blacklist key)
	ParentID    string // jwt.sub: the parent this token was minted for
	Description string
	CreatedAt   time.Time
	ExpiresAt   time.Time
	RevokedAt   *time.Time
}

// Revoked reports whether the token was revoked.
func (t RelayParentToken) Revoked() bool { return t.RevokedAt != nil }

// CreateRelayParentToken persists the metadata of a freshly minted relay-parent token.
func (s *Store) CreateRelayParentToken(ctx context.Context, t RelayParentToken) error {
	s.dbMu.Lock()
	defer s.dbMu.Unlock()
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO relay_parent_tokens (id, jti, parent_id, description, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?)`,
		t.ID, t.JTI, t.ParentID, t.Description, t.CreatedAt.UTC().Unix(), t.ExpiresAt.UTC().Unix())
	if err != nil {
		return fmt.Errorf("CreateRelayParentToken: %w", err)
	}
	log.Printf("Relay-parent token created: id=%s parent=%s", t.ID, t.ParentID)
	return nil
}

// ListRelayParentTokens returns all relay-parent tokens (metadata only), newest first.
func (s *Store) ListRelayParentTokens(ctx context.Context) ([]RelayParentToken, error) {
	s.dbMu.RLock()
	defer s.dbMu.RUnlock()
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, jti, parent_id, COALESCE(description, ''), created_at, expires_at, revoked_at
		FROM relay_parent_tokens ORDER BY created_at DESC, id`)
	if err != nil {
		return nil, fmt.Errorf("ListRelayParentTokens: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []RelayParentToken
	for rows.Next() {
		t, err := scanRelayParentToken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// GetRelayParentToken returns the token with the given id, or (nil, nil) if unknown.
func (s *Store) GetRelayParentToken(ctx context.Context, id string) (*RelayParentToken, error) {
	s.dbMu.RLock()
	defer s.dbMu.RUnlock()
	row := s.db.QueryRowContext(ctx, `
		SELECT id, jti, parent_id, COALESCE(description, ''), created_at, expires_at, revoked_at
		FROM relay_parent_tokens WHERE id = ?`, id)
	t, err := scanRelayParentToken(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// RevokeRelayParentToken marks the token revoked and blacklists its JTI atomically, so a
// token can never be "revoked" without being refused at the next handshake.
// Returns (token, true, nil) on success, (nil, false, nil) if the id is unknown. Revoking an
// already revoked token is idempotent.
func (s *Store) RevokeRelayParentToken(ctx context.Context, id string) (*RelayParentToken, bool, error) {
	s.dbMu.Lock()
	defer s.dbMu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, false, fmt.Errorf("RevokeRelayParentToken begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }() // no-op after Commit

	row := tx.QueryRowContext(ctx, `
		SELECT id, jti, parent_id, COALESCE(description, ''), created_at, expires_at, revoked_at
		FROM relay_parent_tokens WHERE id = ?`, id)
	t, err := scanRelayParentToken(row)
	if err == sql.ErrNoRows {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	now := time.Now().UTC()
	if t.RevokedAt == nil {
		if _, err = tx.ExecContext(ctx, "UPDATE relay_parent_tokens SET revoked_at = ? WHERE id = ?", now.Unix(), id); err != nil {
			return nil, false, fmt.Errorf("RevokeRelayParentToken update: %w", err)
		}
		t.RevokedAt = &now
	}
	if _, err = tx.ExecContext(ctx, `
		INSERT INTO blacklist (jti, hostname, revoked_at, reason, expires_at) VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(jti) DO NOTHING`,
		t.JTI, t.ParentID, now.Format(time.RFC3339), "relay-parent token revoked", t.ExpiresAt.UTC().Format(time.RFC3339)); err != nil {
		return nil, false, fmt.Errorf("RevokeRelayParentToken blacklist: %w", err)
	}
	if err = tx.Commit(); err != nil {
		return nil, false, fmt.Errorf("RevokeRelayParentToken commit: %w", err)
	}
	log.Printf("Relay-parent token revoked: id=%s parent=%s", t.ID, t.ParentID)
	return &t, true, nil
}

type rowScanner interface{ Scan(dest ...any) error }

func scanRelayParentToken(r rowScanner) (RelayParentToken, error) {
	var t RelayParentToken
	var created, expires int64
	var revoked sql.NullInt64
	if err := r.Scan(&t.ID, &t.JTI, &t.ParentID, &t.Description, &created, &expires, &revoked); err != nil {
		if err == sql.ErrNoRows {
			return t, err
		}
		return t, fmt.Errorf("scan relay parent token: %w", err)
	}
	t.CreatedAt = time.Unix(created, 0).UTC()
	t.ExpiresAt = time.Unix(expires, 0).UTC()
	if revoked.Valid {
		r := time.Unix(revoked.Int64, 0).UTC()
		t.RevokedAt = &r
	}
	return t, nil
}
