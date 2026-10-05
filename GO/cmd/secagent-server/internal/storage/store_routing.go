// Hierarchical routing helpers (#127) on top of relay_routing.
//
// relay_routing is keyed by hostname alone (strict tree: one path per host).
//   - relay_id    : the relay that DECLARES the host (where the host is attached)
//   - relay_chain : path from the direct child of this node down to that relay, e.g.
//     ["dmz1","zone-a"]; the NEXT HOP of a task is relay_chain[0] (relay_id when the chain is empty)
//   - hop_type    : always 'relay'. Directly connected agents are NOT stored: they are resolved from
//     the live /ws/agent connections (the FK on relay_nodes and stale rows make a table entry a
//     liability; a live connection is the only reliable proof the agent is reachable).
package storage

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

// HopTypeRelay is the only hop type persisted in relay_routing.
const HopTypeRelay = "relay"

// RelayRoute is one row of relay_routing.
type RelayRoute struct {
	Hostname   string
	RelayID    string   // declaring relay
	HopType    string   // "relay"
	RelayChain []string // top-down path from this node's direct child to RelayID
	UpdatedAt  int64
}

// NextHop returns the direct child to dispatch to.
func (r RelayRoute) NextHop() string {
	if len(r.RelayChain) > 0 {
		return r.RelayChain[0]
	}
	return r.RelayID
}

func chainJSON(chain []string) string {
	if chain == nil {
		chain = []string{}
	}
	b, err := json.Marshal(chain)
	if err != nil { // []string cannot fail to marshal
		return "[]"
	}
	return string(b)
}

func parseChain(s string) []string {
	var c []string
	if err := json.Unmarshal([]byte(s), &c); err != nil {
		return nil
	}
	return c
}

// GetRelayRoute returns the route of hostname, or (nil, nil) when unrouted.
func (s *Store) GetRelayRoute(hostname string) (*RelayRoute, error) {
	s.dbMu.RLock()
	defer s.dbMu.RUnlock()
	return s.getRelayRouteLocked(hostname)
}

func (s *Store) getRelayRouteLocked(hostname string) (*RelayRoute, error) {
	var r RelayRoute
	var chain string
	err := s.db.QueryRow(
		"SELECT hostname, relay_id, hop_type, relay_chain, updated_at FROM relay_routing WHERE hostname = ?",
		hostname).Scan(&r.Hostname, &r.RelayID, &r.HopType, &chain, &r.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("GetRelayRoute %q: %w", hostname, err)
	}
	r.RelayChain = parseChain(chain)
	if !validRoute(r.Hostname, r.RelayID, r.RelayChain) { // legacy / hostile row: never served
		warnIgnoredOnce("relay route", hostname)
		return nil, nil
	}
	return &r, nil
}

// GetNextHopForHostname returns the direct child relay to dispatch a task for hostname to.
// Returns ("", nil) when the hostname is unrouted.
func (s *Store) GetNextHopForHostname(hostname string) (string, error) {
	r, err := s.GetRelayRoute(hostname)
	if err != nil || r == nil {
		return "", err
	}
	return r.NextHop(), nil
}

// UpsertRelayRoute sets hostname → (declaring relay, chain); last arrival wins.
// It returns the previous route (nil if none) so the caller can detect a next-hop change.
func (s *Store) UpsertRelayRoute(hostname, relayID string, chain []string) (prev *RelayRoute, err error) {
	s.dbMu.Lock()
	defer s.dbMu.Unlock()
	prev, err = s.getRelayRouteLocked(hostname)
	if err != nil {
		return nil, err
	}
	_, err = s.db.Exec(`
		INSERT INTO relay_routing (hostname, relay_id, updated_at, hop_type, relay_chain)
		VALUES (?, ?, ?, 'relay', ?)
		ON CONFLICT(hostname) DO UPDATE SET relay_id = excluded.relay_id, updated_at = excluded.updated_at,
			relay_chain = excluded.relay_chain`,
		hostname, relayID, time.Now().UTC().Unix(), chainJSON(chain))
	if err != nil {
		return nil, fmt.Errorf("UpsertRelayRoute %q→%q: %w", hostname, relayID, err)
	}
	return prev, nil
}

// RouteChain is a (hostname, declaring relay, chain) triple used by SetRelayRouteChains.
type RouteChain struct {
	Hostname string
	RelayID  string
	Chain    []string
}

// SetRelayRouteChains records the full top-down chain of already-upserted routes
// (topology_snapshot). Only rows still pointing at the declared relay are updated.
func (s *Store) SetRelayRouteChains(entries []RouteChain) error {
	s.dbMu.Lock()
	defer s.dbMu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("SetRelayRouteChains begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }() // no-op after Commit
	for _, e := range entries {
		if _, err = tx.Exec("UPDATE relay_routing SET relay_chain = ? WHERE hostname = ? AND relay_id = ?",
			chainJSON(e.Chain), e.Hostname, e.RelayID); err != nil {
			return fmt.Errorf("SetRelayRouteChains %q: %w", e.Hostname, err)
		}
	}
	return tx.Commit()
}

// ListRelayRoutes returns every route of relay_routing ordered by hostname.
func (s *Store) ListRelayRoutes() ([]RelayRoute, error) {
	s.dbMu.RLock()
	defer s.dbMu.RUnlock()
	rows, err := s.db.Query("SELECT hostname, relay_id, hop_type, relay_chain, updated_at FROM relay_routing ORDER BY hostname")
	if err != nil {
		return nil, fmt.Errorf("ListRelayRoutes: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []RelayRoute
	for rows.Next() {
		var r RelayRoute
		var chain string
		if err := rows.Scan(&r.Hostname, &r.RelayID, &r.HopType, &chain, &r.UpdatedAt); err != nil {
			return nil, fmt.Errorf("ListRelayRoutes scan: %w", err)
		}
		r.RelayChain = parseChain(chain)
		if !validRoute(r.Hostname, r.RelayID, r.RelayChain) {
			warnIgnoredOnce("relay route", r.Hostname)
			continue
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
