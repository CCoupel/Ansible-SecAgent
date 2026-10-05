// Phase 12 — store_relay.go
// CRUD operations for relay_nodes and relay_routing tables.
// These tables back the Proxy/Gateway mode of secagent-server.
package storage

import (
	"database/sql"
	"fmt"
	"log"
	"time"
)

// RelayNode represents a downstream relay registered on a proxy.
// Mode "pull": the relay connects to the proxy via /ws/relay.
// Mode "push": the proxy initiates HTTP REST calls to the relay's URL.
type RelayNode struct {
	ID          string // UUID (internal primary key)
	RelayID     string // human-readable unique ID, e.g. "dmz1"
	URL         string // HTTP base URL — push mode only, empty for pull
	Description string
	TokenHash   string // SHA-256 of bearer token — push mode; SHA-256 of JWT JTI — pull mode
	Mode        string // "pull" | "push"
	IsProxy     bool   // true if the downstream relay is itself a proxy
	CreatedAt   int64  // Unix timestamp
	LastSeen    *int64 // nil if never connected
	Status      string // "connected" | "disconnected" | "pending"
}

// nullableInt64 converts *int64 to nil/int64 for SQL parameters.
func nullableInt64(v *int64) interface{} {
	if v == nil {
		return nil
	}
	return *v
}

// ========================================================================
// relay_nodes — CRUD
// ========================================================================

// UpsertRelayNode inserts or updates a relay node keyed on relay_id.
// If the row already exists (ON CONFLICT relay_id), the mutable columns are updated.
func (s *Store) UpsertRelayNode(node RelayNode) error {
	if err := checkRelayID(node.RelayID); err != nil { // last line of defence for every entry point
		return fmt.Errorf("UpsertRelayNode: %w", err)
	}
	s.dbMu.Lock()
	defer s.dbMu.Unlock()

	if node.CreatedAt == 0 {
		node.CreatedAt = time.Now().UTC().Unix()
	}
	if node.Status == "" {
		node.Status = "pending"
	}
	if node.Mode == "" {
		node.Mode = "pull"
	}

	isProxy := 0
	if node.IsProxy {
		isProxy = 1
	}

	_, err := s.db.Exec(`
		INSERT INTO relay_nodes
			(id, relay_id, url, description, token_hash, mode, is_proxy, created_at, last_seen, status)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(relay_id) DO UPDATE SET
			url         = excluded.url,
			description = excluded.description,
			token_hash  = excluded.token_hash,
			mode        = excluded.mode,
			is_proxy    = excluded.is_proxy,
			status      = excluded.status
	`, node.ID, node.RelayID,
		nullableString(node.URL), nullableString(node.Description),
		nullableString(node.TokenHash), node.Mode, isProxy,
		node.CreatedAt, nullableInt64(node.LastSeen), node.Status)
	if err != nil {
		return fmt.Errorf("UpsertRelayNode %q: %w", node.RelayID, err)
	}

	log.Printf("RelayNode upserted: relay_id=%s mode=%s status=%s", node.RelayID, node.Mode, node.Status)
	return nil
}

// GetRelayNode returns the relay node for the given relay_id, or nil if not found.
func (s *Store) GetRelayNode(relayID string) (*RelayNode, error) {
	s.dbMu.RLock()
	defer s.dbMu.RUnlock()

	row := s.db.QueryRow(`
		SELECT id, relay_id, url, description, token_hash, mode, is_proxy, created_at, last_seen, status
		FROM relay_nodes WHERE relay_id = ?
	`, relayID)

	return scanRelayNode(row)
}

// GetRelayNodeByID returns the relay node for the given internal UUID, or nil if not found.
func (s *Store) GetRelayNodeByID(id string) (*RelayNode, error) {
	s.dbMu.RLock()
	defer s.dbMu.RUnlock()

	row := s.db.QueryRow(`
		SELECT id, relay_id, url, description, token_hash, mode, is_proxy, created_at, last_seen, status
		FROM relay_nodes WHERE id = ?
	`, id)

	return scanRelayNode(row)
}

// ListRelayNodes returns all relay nodes ordered by relay_id.
func (s *Store) ListRelayNodes() ([]RelayNode, error) {
	s.dbMu.RLock()
	defer s.dbMu.RUnlock()

	rows, err := s.db.Query(`
		SELECT id, relay_id, url, description, token_hash, mode, is_proxy, created_at, last_seen, status
		FROM relay_nodes ORDER BY relay_id
	`)
	if err != nil {
		return nil, fmt.Errorf("ListRelayNodes: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var nodes []RelayNode
	for rows.Next() {
		n, err := scanRelayNodeRow(rows)
		if err != nil {
			return nil, fmt.Errorf("ListRelayNodes scan: %w", err)
		}
		nodes = append(nodes, *n)
	}
	return nodes, rows.Err()
}

// DeleteRelayNode removes a relay node by its internal UUID.
// Returns (true, nil) if deleted, (false, nil) if not found.
// Cascades to relay_routing rows (ON DELETE CASCADE).
func (s *Store) DeleteRelayNode(id string) error {
	s.dbMu.Lock()
	defer s.dbMu.Unlock()

	result, err := s.db.Exec("DELETE FROM relay_nodes WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("DeleteRelayNode: %w", err)
	}

	n, _ := result.RowsAffected()
	if n > 0 {
		log.Printf("RelayNode deleted: id=%s", id)
	}
	return nil
}

// SetRelayIsProxy updates the is_proxy flag for a relay identified by relay_id.
// Called when a relay announces itself as a proxy node in relay_hello.
func (s *Store) SetRelayIsProxy(relayID string, isProxy bool) error {
	s.dbMu.Lock()
	defer s.dbMu.Unlock()

	val := 0
	if isProxy {
		val = 1
	}
	_, err := s.db.Exec(
		"UPDATE relay_nodes SET is_proxy = ? WHERE relay_id = ?", val, relayID)
	if err != nil {
		return fmt.Errorf("SetRelayIsProxy %q: %w", relayID, err)
	}
	return nil
}

// UpdateRelayStatus updates the status and last_seen for a relay identified by relay_id.
func (s *Store) UpdateRelayStatus(relayID, status string, lastSeen int64) error {
	s.dbMu.Lock()
	defer s.dbMu.Unlock()

	_, err := s.db.Exec(
		"UPDATE relay_nodes SET status = ?, last_seen = ? WHERE relay_id = ?",
		status, lastSeen, relayID)
	if err != nil {
		return fmt.Errorf("UpdateRelayStatus %q: %w", relayID, err)
	}
	return nil
}

// ========================================================================
// relay_routing — hostname → relay_id mapping
// ========================================================================

// UpsertRelayRouting inserts or updates a single hostname → relay_id mapping.
func (s *Store) UpsertRelayRouting(hostname, relayID string) error {
	s.dbMu.Lock()
	defer s.dbMu.Unlock()

	now := time.Now().UTC().Unix()
	_, err := s.db.Exec(`
		INSERT INTO relay_routing (hostname, relay_id, updated_at, relay_chain)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(hostname) DO UPDATE SET relay_id = excluded.relay_id, updated_at = excluded.updated_at,
			relay_chain = excluded.relay_chain
	`, hostname, relayID, now, chainJSON([]string{relayID}))
	if err != nil {
		return fmt.Errorf("UpsertRelayRouting %q→%q: %w", hostname, relayID, err)
	}
	return nil
}

// GetRelayForHostname returns the relay_id that owns the given hostname.
// Returns ("", nil) if the hostname is not in any relay's routing table.
func (s *Store) GetRelayForHostname(hostname string) (string, error) {
	s.dbMu.RLock()
	defer s.dbMu.RUnlock()

	var relayID string
	err := s.db.QueryRow(
		"SELECT relay_id FROM relay_routing WHERE hostname = ?", hostname).Scan(&relayID)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("GetRelayForHostname %q: %w", hostname, err)
	}
	if !hostnameShape.MatchString(hostname) || !ValidRelayID(relayID) {
		warnIgnoredOnce("relay route", hostname)
		return "", nil
	}
	return relayID, nil
}

// BulkUpsertRelayRouting replaces all routing entries for relayID with the given
// hostnames list. Hostnames no longer present in the list are removed.
// Uses a transaction for atomicity. Safe with 100+ hostnames.
func (s *Store) BulkUpsertRelayRouting(relayID string, hostnames []string) error {
	s.dbMu.Lock()
	defer s.dbMu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("BulkUpsertRelayRouting begin tx: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	// Remove all existing entries for this relay
	if _, err = tx.Exec("DELETE FROM relay_routing WHERE relay_id = ?", relayID); err != nil {
		return fmt.Errorf("BulkUpsertRelayRouting delete: %w", err)
	}

	now := time.Now().UTC().Unix()
	// Last arrival wins: a hostname already routed through another relay is re-pointed here
	// (the caller emits host.conflict). relay_chain defaults to [relayID] (direct agents).
	stmt, err := tx.Prepare(`INSERT INTO relay_routing (hostname, relay_id, updated_at, relay_chain) VALUES (?, ?, ?, ?)
		ON CONFLICT(hostname) DO UPDATE SET relay_id = excluded.relay_id, updated_at = excluded.updated_at,
			relay_chain = excluded.relay_chain`)
	if err != nil {
		return fmt.Errorf("BulkUpsertRelayRouting prepare: %w", err)
	}
	defer func() { _ = stmt.Close() }()

	for _, hostname := range hostnames {
		if hostname == "" {
			continue
		}
		if _, err = stmt.Exec(hostname, relayID, now, chainJSON([]string{relayID})); err != nil {
			return fmt.Errorf("BulkUpsertRelayRouting insert %q: %w", hostname, err)
		}
	}

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("BulkUpsertRelayRouting commit: %w", err)
	}

	log.Printf("BulkUpsertRelayRouting: relay_id=%s count=%d", relayID, len(hostnames))
	return nil
}

// DeleteRelayRoutingByRelay removes all routing entries for the given relay_id.
func (s *Store) DeleteRelayRoutingByRelay(relayID string) error {
	s.dbMu.Lock()
	defer s.dbMu.Unlock()

	result, err := s.db.Exec("DELETE FROM relay_routing WHERE relay_id = ?", relayID)
	if err != nil {
		return fmt.Errorf("DeleteRelayRoutingByRelay %q: %w", relayID, err)
	}
	n, _ := result.RowsAffected()
	log.Printf("DeleteRelayRoutingByRelay: relay_id=%q deleted=%d", relayID, n)
	return nil
}

// ListRelayRouting returns all routing entries for a given relay_id.
// Returns (hostnames, nil). Empty slice if none.
func (s *Store) ListRelayRouting(relayID string) ([]string, error) {
	s.dbMu.RLock()
	defer s.dbMu.RUnlock()

	rows, err := s.db.Query(
		"SELECT hostname FROM relay_routing WHERE relay_id = ? ORDER BY hostname", relayID)
	if err != nil {
		return nil, fmt.Errorf("ListRelayRouting: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var hostnames []string
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			return nil, fmt.Errorf("ListRelayRouting scan: %w", err)
		}
		if !hostnameShape.MatchString(h) {
			warnIgnoredOnce("relay route", h)
			continue
		}
		hostnames = append(hostnames, h)
	}
	return hostnames, rows.Err()
}

// ========================================================================
// Internal helpers
// ========================================================================

func scanRelayNode(row *sql.Row) (*RelayNode, error) {
	var n RelayNode
	var url, description, tokenHash sql.NullString
	var lastSeen sql.NullInt64
	var isProxy int

	err := row.Scan(
		&n.ID, &n.RelayID, &url, &description, &tokenHash,
		&n.Mode, &isProxy, &n.CreatedAt, &lastSeen, &n.Status)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("scanRelayNode: %w", err)
	}

	n.URL = url.String
	n.Description = description.String
	n.TokenHash = tokenHash.String
	n.IsProxy = isProxy == 1
	if lastSeen.Valid {
		v := lastSeen.Int64
		n.LastSeen = &v
	}
	return &n, nil
}

// scanRelayNodeRow scans a *sql.Rows (not *sql.Row) into a RelayNode.
func scanRelayNodeRow(rows *sql.Rows) (*RelayNode, error) {
	var n RelayNode
	var url, description, tokenHash sql.NullString
	var lastSeen sql.NullInt64
	var isProxy int

	err := rows.Scan(
		&n.ID, &n.RelayID, &url, &description, &tokenHash,
		&n.Mode, &isProxy, &n.CreatedAt, &lastSeen, &n.Status)
	if err != nil {
		return nil, fmt.Errorf("scanRelayNodeRow: %w", err)
	}

	n.URL = url.String
	n.Description = description.String
	n.TokenHash = tokenHash.String
	n.IsProxy = isProxy == 1
	if lastSeen.Valid {
		v := lastSeen.Int64
		n.LastSeen = &v
	}
	return &n, nil
}
