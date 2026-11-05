// SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package storagetest opens stores on temporary test states. It is imported by tests only, so none of
// it is compiled into a release binary (#221; it used to live in storage/testing.go).
package storagetest

import (
	"os"

	"secagent-server/cmd/secagent-server/internal/storage"
	"secagent-server/cmd/secagent-server/internal/storage/testsupport"
)

// OpenTemp returns a store backed by a private temporary state directory, with an allow-all write guard
// and the explicit insecure test mode (secrets in clear). The directory is removed by Close.
func OpenTemp() (*storage.Store, error) {
	dir, err := testsupport.TempDir()
	if err != nil {
		return nil, err
	}
	s, err := OpenTestDir(dir)
	if err != nil {
		_ = os.RemoveAll(dir)
		return nil, err
	}
	s.AfterClose(func() { _ = os.RemoveAll(dir) })
	return s, nil
}

// OpenTestDir opens (creating the initial test state when the directory has none) the state of dir
// with an allow-all write guard and the insecure test mode. Reopening the same directory is how tests
// simulate a restart.
func OpenTestDir(dir string) (*storage.Store, error) {
	if err := testsupport.Prepare(dir); err != nil {
		return nil, err
	}
	return storage.Open(testsupport.Options(dir))
}
