// Relay token lifecycle (#153): the JTI and expiry of the token issued at registration are
// persisted (never the token), so a relay can be revoked: JTI blacklisted + relay flagged revoked.
package storage

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"time"
)

// RelayTokenInfo is the persisted token metadata of a relay node.
type RelayTokenInfo struct {
	JTI     string // "" for legacy rows created before #153
	Exp     int64  // unix seconds, 0 when unknown
	Revoked bool
}

// SetRelayTokenInfo records the JTI/expiry of the token just issued for relayID and clears the
// revoked flag (issuing a fresh token is an explicit admin action that re-enables the relay).
func (s *Store) SetRelayTokenInfo(relayID, jti string, exp int64) error {
	s.dbMu.Lock()
	defer s.dbMu.Unlock()
	res, err := s.db.Exec("UPDATE relay_nodes SET jti = ?, token_exp = ?, revoked = 0 WHERE relay_id = ?", jti, exp, relayID)
	if err != nil {
		return fmt.Errorf("SetRelayTokenInfo %q: %w", relayID, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("SetRelayTokenInfo %q: unknown relay", relayID)
	}
	return nil
}

// GetRelayTokenInfo returns the token metadata of relayID; (zero, nil) when the relay is unknown.
func (s *Store) GetRelayTokenInfo(relayID string) (RelayTokenInfo, error) {
	s.dbMu.RLock()
	defer s.dbMu.RUnlock()
	var jti sql.NullString
	var exp sql.NullInt64
	var revoked int
	err := s.db.QueryRow("SELECT jti, token_exp, revoked FROM relay_nodes WHERE relay_id = ?", relayID).Scan(&jti, &exp, &revoked)
	if err == sql.ErrNoRows {
		return RelayTokenInfo{}, nil
	}
	if err != nil {
		return RelayTokenInfo{}, fmt.Errorf("GetRelayTokenInfo %q: %w", relayID, err)
	}
	return RelayTokenInfo{JTI: jti.String, Exp: exp.Int64, Revoked: revoked == 1}, nil
}

// RevokeRelayNode flags relayID revoked and, when its JTI is known, blacklists it, in one
// transaction. It returns the token info as it was. A legacy relay (no JTI) is still flagged
// revoked: the revoked flag alone makes /ws/relay refuse it. Idempotent.
// found=false when the relay is unknown.
func (s *Store) RevokeRelayNode(ctx context.Context, relayID, reason string) (info RelayTokenInfo, found bool, err error) {
	s.dbMu.Lock()
	defer s.dbMu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return RelayTokenInfo{}, false, fmt.Errorf("RevokeRelayNode begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }() // no-op after Commit

	var jti sql.NullString
	var exp sql.NullInt64
	var revoked int
	err = tx.QueryRowContext(ctx, "SELECT jti, token_exp, revoked FROM relay_nodes WHERE relay_id = ?", relayID).Scan(&jti, &exp, &revoked)
	if err == sql.ErrNoRows {
		return RelayTokenInfo{}, false, nil
	}
	if err != nil {
		return RelayTokenInfo{}, false, fmt.Errorf("RevokeRelayNode select: %w", err)
	}
	info = RelayTokenInfo{JTI: jti.String, Exp: exp.Int64, Revoked: revoked == 1}
	if _, err = tx.ExecContext(ctx, "UPDATE relay_nodes SET revoked = 1 WHERE relay_id = ?", relayID); err != nil {
		return RelayTokenInfo{}, false, fmt.Errorf("RevokeRelayNode update: %w", err)
	}
	if info.JTI != "" {
		expires := time.Now().UTC().Add(30 * 24 * time.Hour)
		if info.Exp > 0 {
			expires = time.Unix(info.Exp, 0).UTC()
		}
		if _, err = tx.ExecContext(ctx, `
			INSERT INTO blacklist (jti, hostname, revoked_at, reason, expires_at) VALUES (?, ?, ?, ?, ?)
			ON CONFLICT(jti) DO NOTHING`,
			info.JTI, relayID, time.Now().UTC().Format(time.RFC3339), reason, expires.Format(time.RFC3339)); err != nil {
			return RelayTokenInfo{}, false, fmt.Errorf("RevokeRelayNode blacklist: %w", err)
		}
	}
	if err = tx.Commit(); err != nil {
		return RelayTokenInfo{}, false, fmt.Errorf("RevokeRelayNode commit: %w", err)
	}
	log.Printf("Relay revoked: relay_id=%s jti_known=%v", relayID, info.JTI != "")
	return info, true, nil
}

// BlacklistJTI adds a standalone JTI (e.g. the previous token of a re-registered relay).
func (s *Store) BlacklistJTI(ctx context.Context, jti, relayID, reason string, exp int64) error {
	expires := time.Now().UTC().Add(30 * 24 * time.Hour)
	if exp > 0 {
		expires = time.Unix(exp, 0).UTC()
	}
	r := reason
	return s.AddToBlacklist(ctx, jti, relayID, expires.Format(time.RFC3339), &r)
}
