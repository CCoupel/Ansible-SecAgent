package storage

import (
	"context"
	"database/sql"
	"time"
)

// ActionLogEntry records one hook action execution result.
type ActionLogEntry struct {
	ID             string
	Event          string
	Hostname       string
	ActionType     string
	ActionIndex    int
	ConfigSnapshot string // JSON-serialised ActionDef at execution time
	Success        bool
	Error          string
	DurationMs     int64
	ExecutedAt     time.Time
}

// ActionLogFilter specifies optional filters for ListActionLogs.
type ActionLogFilter struct {
	Event    string // filter by event type, e.g. "host.new"
	Hostname string // filter by agent hostname
	Limit    int    // max rows returned; defaults to 50 when 0
}

// CreateActionLog inserts one action execution record into action_log.
func (s *Store) CreateActionLog(ctx context.Context, entry ActionLogEntry) error {
	s.dbMu.Lock()
	defer s.dbMu.Unlock()

	successInt := 0
	if entry.Success {
		successInt = 1
	}

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO action_log
		    (id, event, hostname, action_type, action_index,
		     config_snapshot, success, error, duration_ms, executed_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		entry.ID,
		entry.Event,
		entry.Hostname,
		entry.ActionType,
		entry.ActionIndex,
		entry.ConfigSnapshot,
		successInt,
		entry.Error,
		entry.DurationMs,
		entry.ExecutedAt.Unix(),
	)
	return err
}

// ListActionLogs returns action log entries, most-recent first.
// The Limit in the filter defaults to 50 and is capped at 200.
func (s *Store) ListActionLogs(ctx context.Context, f ActionLogFilter) ([]ActionLogEntry, error) {
	limit := f.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}

	query := `SELECT id, event, hostname, action_type, action_index,
	                 config_snapshot, success, error, duration_ms, executed_at
	          FROM action_log
	          WHERE 1=1`
	args := []interface{}{}

	if f.Event != "" {
		query += " AND event = ?"
		args = append(args, f.Event)
	}
	if f.Hostname != "" {
		query += " AND hostname = ?"
		args = append(args, f.Hostname)
	}
	query += " ORDER BY executed_at DESC LIMIT ?"
	args = append(args, limit)

	s.dbMu.RLock()
	rows, err := s.db.QueryContext(ctx, query, args...)
	s.dbMu.RUnlock()
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var entries []ActionLogEntry
	for rows.Next() {
		var e ActionLogEntry
		var successInt int
		var errStr sql.NullString
		var executedAtUnix int64

		if err := rows.Scan(
			&e.ID, &e.Event, &e.Hostname, &e.ActionType, &e.ActionIndex,
			&e.ConfigSnapshot, &successInt, &errStr, &e.DurationMs, &executedAtUnix,
		); err != nil {
			return nil, err
		}
		e.Success = successInt != 0
		if errStr.Valid {
			e.Error = errStr.String
		}
		e.ExecutedAt = time.Unix(executedAtUnix, 0).UTC()
		entries = append(entries, e)
	}
	if entries == nil {
		entries = []ActionLogEntry{}
	}
	return entries, rows.Err()
}
