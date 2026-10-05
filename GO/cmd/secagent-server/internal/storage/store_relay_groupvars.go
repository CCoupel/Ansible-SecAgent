package storage

import (
	"fmt"
)

// SetRelayGroupVars records the (already validated) JSON group vars of relayID; "" clears them.
// It returns false when the relay is unknown.
func (s *Store) SetRelayGroupVars(relayID, groupVarsJSON string) (bool, error) {
	s.dbMu.Lock()
	defer s.dbMu.Unlock()
	var v any
	if groupVarsJSON != "" {
		v = groupVarsJSON
	}
	res, err := s.db.Exec("UPDATE relay_nodes SET group_vars = ? WHERE relay_id = ?", v, relayID)
	if err != nil {
		return false, fmt.Errorf("SetRelayGroupVars %q: %w", relayID, err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// ListRelayGroupVars returns relay_id → stored JSON group vars for every relay that has some.
func (s *Store) ListRelayGroupVars() (map[string]string, error) {
	s.dbMu.RLock()
	defer s.dbMu.RUnlock()
	rows, err := s.db.Query("SELECT relay_id, group_vars FROM relay_nodes WHERE group_vars IS NOT NULL AND group_vars != ''")
	if err != nil {
		return nil, fmt.Errorf("ListRelayGroupVars: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]string{}
	for rows.Next() {
		var id, gv string
		if err := rows.Scan(&id, &gv); err != nil {
			return nil, fmt.Errorf("ListRelayGroupVars scan: %w", err)
		}
		out[id] = gv
	}
	return out, rows.Err()
}
