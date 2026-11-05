// SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !linux && !windows

package facts

import "fmt"

func diskTotalBytesOS(path string) (uint64, error) {
	return 0, fmt.Errorf("disk stat not implemented on this platform")
}
