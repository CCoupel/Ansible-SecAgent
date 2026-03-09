package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// AgentRecord represents stored agent data
type AgentRecord struct {
	Hostname      string
	PublicKeyPEM  string
	TokenJTI      string
	EnrolledAt    time.Time
	LastSeen      time.Time
	Status        string // "connected", "disconnected"
	Suspended     bool
	Vars          string // JSON object, e.g. {"key": "value"}
}

// AuthorizedKeyRecord represents a pre-authorized public key
type AuthorizedKeyRecord struct {
	Hostname      string
	PublicKeyPEM  string
	ApprovedAt    time.Time
	ApprovedBy    string
}

// BlacklistEntry represents a revoked JWT identifier
type BlacklistEntry struct {
	JTI       string
	Hostname  string
	RevokedAt time.Time
	ExpiresAt time.Time
	Reason    string
}

// Store provides SQLite database access for relay server
// Matches ARCHITECTURE.md §20 schema exactly
type Store struct {
	db    *sql.DB
	dbMu  sync.RWMutex
	dbURL string
}

// DDL defines the SQL schema (matches ARCHITECTURE.md §20 exactly)
const DDL = `
CREATE TABLE IF NOT EXISTS agents (
    hostname        TEXT PRIMARY KEY,
    public_key_pem  TEXT NOT NULL,
    token_jti       TEXT,
    enrolled_at     TIMESTAMP,
    last_seen       TIMESTAMP,
    status          TEXT NOT NULL DEFAULT 'disconnected',
    suspended       BOOLEAN NOT NULL DEFAULT FALSE,
    vars            TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS authorized_keys (
    hostname        TEXT PRIMARY KEY,
    public_key_pem  TEXT NOT NULL,
    approved_at     TIMESTAMP NOT NULL,
    approved_by     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS blacklist (
    jti             TEXT PRIMARY KEY,
    hostname        TEXT NOT NULL,
    revoked_at      TIMESTAMP NOT NULL,
    reason          TEXT,
    expires_at      TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_blacklist_expires ON blacklist (expires_at);
CREATE INDEX IF NOT EXISTS idx_agents_status ON agents (status);

CREATE TABLE IF NOT EXISTS server_config (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at TIMESTAMP NOT NULL
);

CREATE TABLE IF NOT EXISTS enrollment_tokens (
    id               TEXT PRIMARY KEY,
    token_hash       TEXT NOT NULL UNIQUE,
    hostname_pattern TEXT NOT NULL,
    reusable         INTEGER NOT NULL DEFAULT 0,
    use_count        INTEGER NOT NULL DEFAULT 0,
    last_used_at     INTEGER,
    created_at       INTEGER NOT NULL,
    expires_at       INTEGER,
    created_by       TEXT
);

CREATE INDEX IF NOT EXISTS idx_enrollment_tokens_hash ON enrollment_tokens (token_hash);

CREATE TABLE IF NOT EXISTS plugin_tokens (
    id                       TEXT PRIMARY KEY,
    token_hash               TEXT NOT NULL UNIQUE,
    description              TEXT,
    role                     TEXT NOT NULL DEFAULT 'plugin',
    allowed_ips              TEXT,
    allowed_hostname_pattern TEXT,
    created_at               INTEGER NOT NULL,
    expires_at               INTEGER,
    last_used_at             INTEGER,
    last_used_ip             TEXT,
    revoked                  INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_plugin_tokens_hash ON plugin_tokens (token_hash);
`

// NewStore creates a new SQLite store and opens the connection
func NewStore(dbURL string) (*Store, error) {
	// dbURL format: "sqlite:////data/relay.db" or "sqlite:///./relay.db"
	// Convert to file path for sql.Open
	filePath := dbURL
	if len(filePath) > 9 && filePath[:9] == "sqlite:///" {
		filePath = filePath[9:] // Remove "sqlite://"
	} else if len(filePath) > 10 && filePath[:10] == "sqlite:////" {
		filePath = filePath[10:] // Remove "sqlite:///"
	}

	// Ensure parent directory exists
	if dir := filepath.Dir(filePath); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create database directory: %w", err)
		}
	}

	// Open database
	db, err := sql.Open("sqlite3", filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Set connection pool parameters
	db.SetMaxOpenConns(1) // SQLite prefers sequential writes
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(time.Hour)

	// Enable WAL mode for better concurrency and pragma settings
	_, err = db.Exec("PRAGMA journal_mode=WAL")
	if err != nil {
		return nil, fmt.Errorf("failed to enable WAL: %w", err)
	}

	_, err = db.Exec("PRAGMA foreign_keys=ON")
	if err != nil {
		return nil, fmt.Errorf("failed to enable foreign keys: %w", err)
	}

	// Create tables
	if _, err := db.Exec(DDL); err != nil {
		return nil, fmt.Errorf("failed to create tables: %w", err)
	}

	// Apply migrations for existing DBs (ignore errors — columns may already exist)
	for _, stmt := range []string{
		"ALTER TABLE agents ADD COLUMN suspended BOOLEAN NOT NULL DEFAULT FALSE",
		"ALTER TABLE agents ADD COLUMN vars TEXT NOT NULL DEFAULT '{}'",
	} {
		_, _ = db.Exec(stmt) // intentionally ignore "duplicate column" errors
	}

	store := &Store{
		db:    db,
		dbURL: dbURL,
	}

	log.Printf("AgentStore initialized: db=%s", filePath)
	return store, nil
}

// Close closes the database connection
func (s *Store) Close() error {
	s.dbMu.Lock()
	defer s.dbMu.Unlock()

	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// nowISO returns current UTC time as ISO 8601 string
func nowISO() string {
	return time.Now().UTC().Format(time.RFC3339)
}

// ========================================================================
// authorized_keys — pre-enrollment (called by CI/CD pipeline)
// ========================================================================

// AddAuthorizedKey pre-authorizes a public key for a hostname before agent boots
// Called via POST /api/admin/authorize (CI/CD pipeline)
func (s *Store) AddAuthorizedKey(ctx context.Context, hostname, publicKeyPEM, approvedBy string) error {
	s.dbMu.Lock()
	defer s.dbMu.Unlock()

	now := nowISO()
	query := `
		INSERT INTO authorized_keys (hostname, public_key_pem, approved_at, approved_by)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(hostname) DO UPDATE SET
			public_key_pem = excluded.public_key_pem,
			approved_at    = excluded.approved_at,
			approved_by    = excluded.approved_by
	`

	_, err := s.db.ExecContext(ctx, query, hostname, publicKeyPEM, now, approvedBy)
	if err != nil {
		return fmt.Errorf("failed to add authorized key: %w", err)
	}

	log.Printf("Key authorized: hostname=%s approved_by=%s", hostname, approvedBy)
	return nil
}

// GetAuthorizedKey fetches the authorized key entry for a hostname
// Used during enrollment to verify agent's public key
func (s *Store) GetAuthorizedKey(ctx context.Context, hostname string) (*AuthorizedKeyRecord, error) {
	s.dbMu.RLock()
	defer s.dbMu.RUnlock()

	query := `
		SELECT hostname, public_key_pem, approved_at, approved_by
		FROM authorized_keys WHERE hostname = ?
	`

	row := s.db.QueryRowContext(ctx, query, hostname)
	var rec AuthorizedKeyRecord
	err := row.Scan(&rec.Hostname, &rec.PublicKeyPEM, &rec.ApprovedAt, &rec.ApprovedBy)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get authorized key: %w", err)
	}

	return &rec, nil
}

// RevokeKey removes the authorized key for a hostname (prevents future enrollment)
func (s *Store) RevokeKey(ctx context.Context, hostname string) (bool, error) {
	s.dbMu.Lock()
	defer s.dbMu.Unlock()

	result, err := s.db.ExecContext(ctx, "DELETE FROM authorized_keys WHERE hostname = ?", hostname)
	if err != nil {
		return false, fmt.Errorf("failed to revoke key: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("failed to get rows affected: %w", err)
	}

	deleted := rowsAffected > 0
	if deleted {
		log.Printf("Authorized key revoked: hostname=%s", hostname)
	}
	return deleted, nil
}

// ========================================================================
// agents — enrolled agent registry
// ========================================================================

// RegisterAgent registers or re-enrolls an agent after successful key verification
func (s *Store) RegisterAgent(ctx context.Context, hostname, publicKeyPEM, tokenJTI string) (string, error) {
	s.dbMu.Lock()
	defer s.dbMu.Unlock()

	now := nowISO()
	query := `
		INSERT INTO agents (hostname, public_key_pem, token_jti, enrolled_at, last_seen, status)
		VALUES (?, ?, ?, ?, ?, 'disconnected')
		ON CONFLICT(hostname) DO UPDATE SET
			public_key_pem = excluded.public_key_pem,
			token_jti      = excluded.token_jti,
			enrolled_at    = excluded.enrolled_at,
			last_seen      = excluded.last_seen
	`

	_, err := s.db.ExecContext(ctx, query, hostname, publicKeyPEM, tokenJTI, now, now)
	if err != nil {
		return "", fmt.Errorf("failed to register agent: %w", err)
	}

	log.Printf("Agent registered: hostname=%s jti=%s", hostname, tokenJTI)
	return hostname, nil
}

// UpsertAgent is an alias for RegisterAgent
func (s *Store) UpsertAgent(ctx context.Context, hostname, publicKeyPEM, tokenJTI string) error {
	_, err := s.RegisterAgent(ctx, hostname, publicKeyPEM, tokenJTI)
	return err
}

// GetAgent retrieves a registered agent by hostname
func (s *Store) GetAgent(ctx context.Context, hostname string) (*AgentRecord, error) {
	s.dbMu.RLock()
	defer s.dbMu.RUnlock()

	query := `
		SELECT hostname, public_key_pem, token_jti, enrolled_at, last_seen, status, suspended, vars
		FROM agents WHERE hostname = ?
	`

	row := s.db.QueryRowContext(ctx, query, hostname)
	var rec AgentRecord
	err := row.Scan(&rec.Hostname, &rec.PublicKeyPEM, &rec.TokenJTI, &rec.EnrolledAt, &rec.LastSeen, &rec.Status, &rec.Suspended, &rec.Vars)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get agent: %w", err)
	}

	return &rec, nil
}

// ListAgents returns all agents, optionally filtered to connected ones
func (s *Store) ListAgents(ctx context.Context, onlyConnected bool) ([]AgentRecord, error) {
	s.dbMu.RLock()
	defer s.dbMu.RUnlock()

	query := `
		SELECT hostname, public_key_pem, token_jti, enrolled_at, last_seen, status, suspended, vars
		FROM agents
	`
	if onlyConnected {
		query += " WHERE status = 'connected'"
	}

	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to list agents: %w", err)
	}
	defer rows.Close()

	var agents []AgentRecord
	for rows.Next() {
		var rec AgentRecord
		if err := rows.Scan(&rec.Hostname, &rec.PublicKeyPEM, &rec.TokenJTI,
			&rec.EnrolledAt, &rec.LastSeen, &rec.Status, &rec.Suspended, &rec.Vars); err != nil {
			return nil, fmt.Errorf("failed to scan agent: %w", err)
		}
		agents = append(agents, rec)
	}

	return agents, rows.Err()
}

// UpdateLastSeen updates the last_seen timestamp and sets status to 'connected'
func (s *Store) UpdateLastSeen(ctx context.Context, hostname string) (bool, error) {
	s.dbMu.Lock()
	defer s.dbMu.Unlock()

	now := nowISO()
	result, err := s.db.ExecContext(ctx,
		"UPDATE agents SET last_seen = ?, status = 'connected' WHERE hostname = ?",
		now, hostname)
	if err != nil {
		return false, fmt.Errorf("failed to update last_seen: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	return rowsAffected > 0, err
}

// UpdateAgentStatus sets the connection status of an agent
func (s *Store) UpdateAgentStatus(ctx context.Context, hostname, status, lastSeen string) error {
	s.dbMu.Lock()
	defer s.dbMu.Unlock()

	ts := lastSeen
	if ts == "" {
		ts = nowISO()
	}

	_, err := s.db.ExecContext(ctx,
		"UPDATE agents SET status = ?, last_seen = ? WHERE hostname = ?",
		status, ts, hostname)
	if err != nil {
		return fmt.Errorf("failed to update agent status: %w", err)
	}

	return nil
}

// UpdateTokenJTI updates the active token JTI for an agent (token refresh)
func (s *Store) UpdateTokenJTI(ctx context.Context, hostname, tokenJTI string) (bool, error) {
	s.dbMu.Lock()
	defer s.dbMu.Unlock()

	result, err := s.db.ExecContext(ctx,
		"UPDATE agents SET token_jti = ? WHERE hostname = ?",
		tokenJTI, hostname)
	if err != nil {
		return false, fmt.Errorf("failed to update token JTI: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	return rowsAffected > 0, err
}

// ========================================================================
// blacklist — revoked JWT identifiers
// ========================================================================

// AddToBlacklist adds a JWT identifier to the revocation blacklist
func (s *Store) AddToBlacklist(ctx context.Context, jti, hostname, expiresAt string, reason *string) error {
	s.dbMu.Lock()
	defer s.dbMu.Unlock()

	now := nowISO()
	query := `
		INSERT INTO blacklist (jti, hostname, revoked_at, reason, expires_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(jti) DO NOTHING
	`

	reasonStr := ""
	if reason != nil {
		reasonStr = *reason
	}

	_, err := s.db.ExecContext(ctx, query, jti, hostname, now, reasonStr, expiresAt)
	if err != nil {
		return fmt.Errorf("failed to add to blacklist: %w", err)
	}

	log.Printf("JTI blacklisted: jti=%s hostname=%s reason=%s", jti, hostname, reasonStr)
	return nil
}

// IsJTIBlacklisted checks whether a JWT identifier is in the revocation blacklist
func (s *Store) IsJTIBlacklisted(ctx context.Context, jti string) (bool, error) {
	s.dbMu.RLock()
	defer s.dbMu.RUnlock()

	var exists int
	err := s.db.QueryRowContext(ctx,
		"SELECT 1 FROM blacklist WHERE jti = ?", jti).Scan(&exists)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("failed to check blacklist: %w", err)
	}

	return true, nil
}

// PurgeExpiredBlacklist removes blacklist entries whose expires_at is in the past
func (s *Store) PurgeExpiredBlacklist(ctx context.Context) (int64, error) {
	s.dbMu.Lock()
	defer s.dbMu.Unlock()

	now := nowISO()
	result, err := s.db.ExecContext(ctx,
		"DELETE FROM blacklist WHERE expires_at <= ?", now)
	if err != nil {
		return 0, fmt.Errorf("failed to purge blacklist: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected > 0 {
		log.Printf("Blacklist entries purged: count=%d", rowsAffected)
	}
	return rowsAffected, nil
}

// CleanupExpiredBlacklist is an alias for PurgeExpiredBlacklist
func (s *Store) CleanupExpiredBlacklist(ctx context.Context) (int64, error) {
	return s.PurgeExpiredBlacklist(ctx)
}

// ========================================================================
// agents — suspend / resume / vars
// ========================================================================

// SetSuspended sets the suspended flag for an agent.
// When suspended=true, exec requests for this agent will return 503.
func (s *Store) SetSuspended(ctx context.Context, hostname string, suspended bool) (bool, error) {
	s.dbMu.Lock()
	defer s.dbMu.Unlock()

	result, err := s.db.ExecContext(ctx,
		"UPDATE agents SET suspended = ? WHERE hostname = ?", suspended, hostname)
	if err != nil {
		return false, fmt.Errorf("failed to set suspended: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected > 0 {
		action := "suspended"
		if !suspended {
			action = "resumed"
		}
		log.Printf("Agent %s: hostname=%s", action, hostname)
	}
	return rowsAffected > 0, nil
}

// IsAgentSuspended returns true if the agent exists and is suspended.
func (s *Store) IsAgentSuspended(ctx context.Context, hostname string) (bool, error) {
	s.dbMu.RLock()
	defer s.dbMu.RUnlock()

	var suspended bool
	err := s.db.QueryRowContext(ctx,
		"SELECT suspended FROM agents WHERE hostname = ?", hostname).Scan(&suspended)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("failed to check suspended: %w", err)
	}
	return suspended, nil
}

// GetAgentVars returns the vars JSON string for an agent.
func (s *Store) GetAgentVars(ctx context.Context, hostname string) (string, error) {
	s.dbMu.RLock()
	defer s.dbMu.RUnlock()

	var vars string
	err := s.db.QueryRowContext(ctx,
		"SELECT vars FROM agents WHERE hostname = ?", hostname).Scan(&vars)
	if err == sql.ErrNoRows {
		return "", nil // agent not found
	}
	if err != nil {
		return "", fmt.Errorf("failed to get vars: %w", err)
	}
	return vars, nil
}

// SetAgentVar adds or updates a single key in the vars JSON for an agent.
// The value must be a JSON-serializable type.
func (s *Store) SetAgentVar(ctx context.Context, hostname, key string, value interface{}) error {
	s.dbMu.Lock()
	defer s.dbMu.Unlock()

	// Read existing vars
	var existing string
	err := s.db.QueryRowContext(ctx,
		"SELECT vars FROM agents WHERE hostname = ?", hostname).Scan(&existing)
	if err == sql.ErrNoRows {
		return fmt.Errorf("agent_not_found")
	}
	if err != nil {
		return fmt.Errorf("failed to read vars: %w", err)
	}

	// Merge key into map
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(existing), &m); err != nil {
		m = make(map[string]interface{})
	}
	m[key] = value

	updated, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("failed to marshal vars: %w", err)
	}

	_, err = s.db.ExecContext(ctx,
		"UPDATE agents SET vars = ? WHERE hostname = ?", string(updated), hostname)
	if err != nil {
		return fmt.Errorf("failed to update vars: %w", err)
	}

	log.Printf("Agent var set: hostname=%s key=%s", hostname, key)
	return nil
}

// DeleteAgentVar removes a single key from the vars JSON for an agent.
// Returns (true, nil) if the key existed, (false, nil) if not.
func (s *Store) DeleteAgentVar(ctx context.Context, hostname, key string) (bool, error) {
	s.dbMu.Lock()
	defer s.dbMu.Unlock()

	var existing string
	err := s.db.QueryRowContext(ctx,
		"SELECT vars FROM agents WHERE hostname = ?", hostname).Scan(&existing)
	if err == sql.ErrNoRows {
		return false, fmt.Errorf("agent_not_found")
	}
	if err != nil {
		return false, fmt.Errorf("failed to read vars: %w", err)
	}

	var m map[string]interface{}
	if err := json.Unmarshal([]byte(existing), &m); err != nil {
		m = make(map[string]interface{})
	}

	if _, exists := m[key]; !exists {
		return false, nil
	}

	delete(m, key)

	updated, err := json.Marshal(m)
	if err != nil {
		return false, fmt.Errorf("failed to marshal vars: %w", err)
	}

	_, err = s.db.ExecContext(ctx,
		"UPDATE agents SET vars = ? WHERE hostname = ?", string(updated), hostname)
	if err != nil {
		return false, fmt.Errorf("failed to update vars: %w", err)
	}

	log.Printf("Agent var deleted: hostname=%s key=%s", hostname, key)
	return true, nil
}

// ========================================================================
// server_config — persistent server-side key/value store
// Keys: jwt_secret_current, jwt_secret_previous, key_rotation_deadline,
//       rsa_key_current, rsa_key_previous
// ========================================================================

// ConfigGet returns the value for a config key, or ("", nil) if not found.
func (s *Store) ConfigGet(ctx context.Context, key string) (string, error) {
	s.dbMu.RLock()
	defer s.dbMu.RUnlock()

	var value string
	err := s.db.QueryRowContext(ctx,
		"SELECT value FROM server_config WHERE key = ?", key).Scan(&value)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("ConfigGet %q: %w", key, err)
	}
	return value, nil
}

// ConfigSet upserts a config key/value pair.
func (s *Store) ConfigSet(ctx context.Context, key, value string) error {
	s.dbMu.Lock()
	defer s.dbMu.Unlock()

	now := nowISO()
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO server_config (key, value, updated_at)
		VALUES (?, ?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
	`, key, value, now)
	if err != nil {
		return fmt.Errorf("ConfigSet %q: %w", key, err)
	}
	return nil
}

// ConfigDelete removes a config key (no-op if absent).
func (s *Store) ConfigDelete(ctx context.Context, key string) error {
	s.dbMu.Lock()
	defer s.dbMu.Unlock()

	_, err := s.db.ExecContext(ctx, "DELETE FROM server_config WHERE key = ?", key)
	if err != nil {
		return fmt.Errorf("ConfigDelete %q: %w", key, err)
	}
	return nil
}

// ListBlacklistEntries returns all entries in the blacklist (not yet expired)
func (s *Store) ListBlacklistEntries(ctx context.Context) ([]BlacklistEntry, error) {
	s.dbMu.RLock()
	defer s.dbMu.RUnlock()

	query := `
		SELECT jti, hostname, revoked_at, expires_at, reason
		FROM blacklist
		ORDER BY revoked_at DESC
	`

	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to list blacklist: %w", err)
	}
	defer rows.Close()

	var entries []BlacklistEntry
	for rows.Next() {
		var e BlacklistEntry
		if err := rows.Scan(&e.JTI, &e.Hostname, &e.RevokedAt, &e.ExpiresAt, &e.Reason); err != nil {
			return nil, fmt.Errorf("failed to scan blacklist entry: %w", err)
		}
		entries = append(entries, e)
	}
	return entries, rows.Err()
}
