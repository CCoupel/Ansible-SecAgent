// SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
// SPDX-License-Identifier: AGPL-3.0-or-later

package storage

// OpenTemp and OpenTestDir for the tests of this package. Other packages use storagetest. Neither is in a
// release binary (#221).

import (
	"os"

	"secagent-server/cmd/secagent-server/internal/storage/testsupport"
)

// OpenTemp returns a store on a private temporary state (insecure test mode); Close removes the directory.
func OpenTemp() (*Store, error) {
	dir, err := testsupport.TempDir()
	if err != nil {
		return nil, err
	}
	s, err := OpenTestDir(dir)
	if err != nil {
		_ = os.RemoveAll(dir)
		return nil, err
	}
	s.cleanup = func() { _ = os.RemoveAll(dir) }
	return s, nil
}

// OpenTestDir opens the test state of dir (created when missing); reopening is how tests simulate a restart.
func OpenTestDir(dir string) (*Store, error) {
	if err := testsupport.Prepare(dir); err != nil {
		return nil, err
	}
	return Open(testsupport.Options(dir))
}
