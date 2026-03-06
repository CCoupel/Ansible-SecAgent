//go:build !cgo

package storage

// Register pure-Go sqlite driver as "sqlite3" when CGO is unavailable.
// This allows tests to run without gcc on Windows.
import (
	"database/sql"

	modernc "modernc.org/sqlite"
)

func init() {
	// Register modernc sqlite under the "sqlite3" name so that store.go's
	// sql.Open("sqlite3", ...) works without CGO.
	sql.Register("sqlite3", &modernc.Driver{})
}
