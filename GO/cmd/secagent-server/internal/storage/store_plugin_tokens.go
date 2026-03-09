package storage

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net"
	"regexp"
	"strings"
	"time"
)

// PluginToken represents a static bearer token authorizing an Ansible plugin.
// Matches SECURITY.md §6 table schema exactly.
type PluginToken struct {
	ID                    string
	TokenHash             string     // SHA-256(token) — never the token in clear
	Description           string
	Role                  string     // "plugin"
	AllowedIPs            string     // comma-separated CIDRs, empty = no restriction
	AllowedHostnamePattern string    // Go regexp anchored ^...$, empty = no restriction
	CreatedAt             time.Time
	ExpiresAt             *time.Time // nil = no expiry
	LastUsedAt            *time.Time // nil = never used
	LastUsedIP            string
	Revoked               bool
}

// CreatePluginToken inserts a new plugin token.
// id and tokenHash must be pre-computed by the caller (UUID + SHA-256).
func (s *Store) CreatePluginToken(ctx context.Context, t PluginToken) error {
	s.dbMu.Lock()
	defer s.dbMu.Unlock()

	createdAt := t.CreatedAt.UTC().Unix()

	var expiresAt interface{}
	if t.ExpiresAt != nil {
		expiresAt = t.ExpiresAt.UTC().Unix()
	}

	role := t.Role
	if role == "" {
		role = "plugin"
	}

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO plugin_tokens
			(id, token_hash, description, role, allowed_ips, allowed_hostname_pattern,
			 created_at, expires_at, last_used_at, last_used_ip, revoked)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, 0)
	`, t.ID, t.TokenHash, t.Description, role,
		nullableString(t.AllowedIPs), nullableString(t.AllowedHostnamePattern),
		createdAt, expiresAt)
	if err != nil {
		return fmt.Errorf("CreatePluginToken: %w", err)
	}

	log.Printf("Plugin token created: id=%s description=%q role=%s", t.ID, t.Description, role)
	return nil
}

// GetPluginTokenByHash returns the token matching the given SHA-256 hash,
// or nil if not found.
func (s *Store) GetPluginTokenByHash(ctx context.Context, tokenHash string) (*PluginToken, error) {
	s.dbMu.RLock()
	defer s.dbMu.RUnlock()

	row := s.db.QueryRowContext(ctx, `
		SELECT id, token_hash, description, role, allowed_ips, allowed_hostname_pattern,
		       created_at, expires_at, last_used_at, last_used_ip, revoked
		FROM plugin_tokens
		WHERE token_hash = ?
	`, tokenHash)

	return scanPluginToken(row)
}

// GetPluginTokenByID returns the token matching the given UUID.
func (s *Store) GetPluginTokenByID(ctx context.Context, id string) (*PluginToken, error) {
	s.dbMu.RLock()
	defer s.dbMu.RUnlock()

	row := s.db.QueryRowContext(ctx, `
		SELECT id, token_hash, description, role, allowed_ips, allowed_hostname_pattern,
		       created_at, expires_at, last_used_at, last_used_ip, revoked
		FROM plugin_tokens
		WHERE id = ?
	`, id)

	return scanPluginToken(row)
}

// ListPluginTokens returns all plugin tokens ordered by created_at desc.
func (s *Store) ListPluginTokens(ctx context.Context) ([]PluginToken, error) {
	s.dbMu.RLock()
	defer s.dbMu.RUnlock()

	rows, err := s.db.QueryContext(ctx, `
		SELECT id, token_hash, description, role, allowed_ips, allowed_hostname_pattern,
		       created_at, expires_at, last_used_at, last_used_ip, revoked
		FROM plugin_tokens
		ORDER BY created_at DESC
	`)
	if err != nil {
		return nil, fmt.Errorf("ListPluginTokens: %w", err)
	}
	defer rows.Close()

	var tokens []PluginToken
	for rows.Next() {
		t, err := scanPluginTokenRow(rows)
		if err != nil {
			return nil, fmt.Errorf("ListPluginTokens scan: %w", err)
		}
		tokens = append(tokens, *t)
	}
	return tokens, rows.Err()
}

// RevokePluginToken soft-deletes a token by setting revoked=1.
// Returns (true, nil) if found, (false, nil) if not found.
func (s *Store) RevokePluginToken(ctx context.Context, id string) (bool, error) {
	s.dbMu.Lock()
	defer s.dbMu.Unlock()

	result, err := s.db.ExecContext(ctx,
		"UPDATE plugin_tokens SET revoked = 1 WHERE id = ?", id)
	if err != nil {
		return false, fmt.Errorf("RevokePluginToken: %w", err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("RevokePluginToken rows: %w", err)
	}

	found := affected > 0
	if found {
		log.Printf("Plugin token revoked: id=%s", id)
	}
	return found, nil
}

// DeletePluginToken removes a token permanently.
// Returns (true, nil) if deleted, (false, nil) if not found.
func (s *Store) DeletePluginToken(ctx context.Context, id string) (bool, error) {
	s.dbMu.Lock()
	defer s.dbMu.Unlock()

	result, err := s.db.ExecContext(ctx,
		"DELETE FROM plugin_tokens WHERE id = ?", id)
	if err != nil {
		return false, fmt.Errorf("DeletePluginToken: %w", err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("DeletePluginToken rows: %w", err)
	}

	deleted := affected > 0
	if deleted {
		log.Printf("Plugin token deleted: id=%s", id)
	}
	return deleted, nil
}

// TouchPluginToken updates last_used_at and last_used_ip for audit purposes.
func (s *Store) TouchPluginToken(ctx context.Context, id, remoteIP string) error {
	s.dbMu.Lock()
	defer s.dbMu.Unlock()

	now := time.Now().UTC().Unix()
	result, err := s.db.ExecContext(ctx,
		"UPDATE plugin_tokens SET last_used_at = ?, last_used_ip = ? WHERE id = ?",
		now, remoteIP, id)
	if err != nil {
		return fmt.Errorf("TouchPluginToken: %w", err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("TouchPluginToken rows: %w", err)
	}
	if affected == 0 {
		return fmt.Errorf("TouchPluginToken: token not found id=%s", id)
	}
	return nil
}

// ========================================================================
// Validation helpers — SECURITY.md §6 logic
// ========================================================================

// PluginTokenCheckIP returns true if remoteIP is allowed by the token's allowed_ips.
// If allowed_ips is empty, access is always allowed (no IP restriction).
// Accepts remoteIP in "host:port" or "host" format.
func PluginTokenCheckIP(allowedIPs, remoteAddr string) (bool, error) {
	if allowedIPs == "" {
		return true, nil
	}

	// Strip port if present
	host := remoteAddr
	if h, _, err := net.SplitHostPort(remoteAddr); err == nil {
		host = h
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return false, fmt.Errorf("invalid remote IP: %q", host)
	}

	for _, cidr := range strings.Split(allowedIPs, ",") {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			continue
		}
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			return false, fmt.Errorf("invalid CIDR %q: %w", cidr, err)
		}
		if network.Contains(ip) {
			return true, nil
		}
	}
	return false, nil
}

// PluginTokenCheckHostname returns true if hostname matches the token's allowed_hostname_pattern.
// If allowed_hostname_pattern is empty, access is always allowed.
// The pattern is anchored (^...$) as per SECURITY.md §6.
func PluginTokenCheckHostname(pattern, hostname string) (bool, error) {
	if pattern == "" {
		return true, nil
	}

	anchored := "^" + pattern + "$"
	matched, err := regexp.MatchString(anchored, hostname)
	if err != nil {
		return false, fmt.Errorf("invalid hostname pattern %q: %w", pattern, err)
	}
	return matched, nil
}

// ========================================================================
// internal scan helpers
// ========================================================================

func nullableString(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

func scanPluginToken(row *sql.Row) (*PluginToken, error) {
	var t PluginToken
	var description, allowedIPs, allowedHostnamePattern, lastUsedIP sql.NullString
	var createdAtUnix int64
	var expiresAtUnix, lastUsedAtUnix sql.NullInt64
	var revoked int

	err := row.Scan(
		&t.ID, &t.TokenHash, &description, &t.Role,
		&allowedIPs, &allowedHostnamePattern,
		&createdAtUnix, &expiresAtUnix, &lastUsedAtUnix, &lastUsedIP, &revoked,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("scan plugin token: %w", err)
	}

	applyPluginTokenNullables(&t, description, allowedIPs, allowedHostnamePattern,
		lastUsedIP, createdAtUnix, expiresAtUnix, lastUsedAtUnix, revoked)
	return &t, nil
}

func scanPluginTokenRow(rows *sql.Rows) (*PluginToken, error) {
	var t PluginToken
	var description, allowedIPs, allowedHostnamePattern, lastUsedIP sql.NullString
	var createdAtUnix int64
	var expiresAtUnix, lastUsedAtUnix sql.NullInt64
	var revoked int

	err := rows.Scan(
		&t.ID, &t.TokenHash, &description, &t.Role,
		&allowedIPs, &allowedHostnamePattern,
		&createdAtUnix, &expiresAtUnix, &lastUsedAtUnix, &lastUsedIP, &revoked,
	)
	if err != nil {
		return nil, fmt.Errorf("scan plugin token row: %w", err)
	}

	applyPluginTokenNullables(&t, description, allowedIPs, allowedHostnamePattern,
		lastUsedIP, createdAtUnix, expiresAtUnix, lastUsedAtUnix, revoked)
	return &t, nil
}

func applyPluginTokenNullables(t *PluginToken,
	description, allowedIPs, allowedHostnamePattern, lastUsedIP sql.NullString,
	createdAtUnix int64, expiresAtUnix, lastUsedAtUnix sql.NullInt64, revoked int,
) {
	if description.Valid {
		t.Description = description.String
	}
	if allowedIPs.Valid {
		t.AllowedIPs = allowedIPs.String
	}
	if allowedHostnamePattern.Valid {
		t.AllowedHostnamePattern = allowedHostnamePattern.String
	}
	if lastUsedIP.Valid {
		t.LastUsedIP = lastUsedIP.String
	}
	t.CreatedAt = time.Unix(createdAtUnix, 0).UTC()
	if expiresAtUnix.Valid {
		ts := time.Unix(expiresAtUnix.Int64, 0).UTC()
		t.ExpiresAt = &ts
	}
	if lastUsedAtUnix.Valid {
		ts := time.Unix(lastUsedAtUnix.Int64, 0).UTC()
		t.LastUsedAt = &ts
	}
	t.Revoked = revoked != 0
}
