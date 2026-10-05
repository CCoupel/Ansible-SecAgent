package storage

import "fmt"

// SetRelayChain records the top-down path from this node's direct child down to relayID
// (["r2","r3"] for r3 learned through r2; ["r3"] for a direct child). A nil/empty chain clears it
// (the relay is then treated as a direct child). It returns false when the relay is unknown.
func (s *Store) SetRelayChain(relayID string, chain []string) (bool, error) {
	s.dbMu.Lock()
	defer s.dbMu.Unlock()
	var v any
	if len(chain) > 0 {
		v = chainJSON(chain)
	}
	res, err := s.db.Exec("UPDATE relay_nodes SET relay_chain = ? WHERE relay_id = ?", v, relayID)
	if err != nil {
		return false, fmt.Errorf("SetRelayChain %q: %w", relayID, err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// ListRelayChains returns relay_id → stored chain for every relay that has one.
func (s *Store) ListRelayChains() (map[string][]string, error) {
	s.dbMu.RLock()
	defer s.dbMu.RUnlock()
	rows, err := s.db.Query("SELECT relay_id, relay_chain FROM relay_nodes WHERE relay_chain IS NOT NULL AND relay_chain != ''")
	if err != nil {
		return nil, fmt.Errorf("ListRelayChains: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string][]string{}
	for rows.Next() {
		var id, raw string
		if err := rows.Scan(&id, &raw); err != nil {
			return nil, fmt.Errorf("ListRelayChains scan: %w", err)
		}
		if c := parseChain(raw); len(c) > 0 {
			out[id] = c
		}
	}
	return out, rows.Err()
}
