// SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build unix

package secretenv

import (
	"errors"
	"os"
	"syscall"
)

// openSecret opens path read-only without following a symbolic link in final position and without ever
// blocking on a named pipe: a FIFO swapped in between the Lstat and the open would otherwise hang the read
// forever (B61). The caller checks on the descriptor that it is a regular file.
func openSecret(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil && errors.Is(err, syscall.ELOOP) {
		return nil, ErrSymlink
	}
	return f, err
}
