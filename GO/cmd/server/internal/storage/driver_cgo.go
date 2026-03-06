//go:build cgo

package storage

// Use the CGO-based sqlite3 driver in production (requires gcc)
import _ "github.com/mattn/go-sqlite3"
