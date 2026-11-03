// SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !unix

package secretenv

import "os"

// openSecret: no O_NOFOLLOW / O_NONBLOCK outside unix (Linux is the only supported target); the Lstat
// and the check on the descriptor remain.
func openSecret(path string) (*os.File, error) { return os.Open(path) }
