// SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
// SPDX-License-Identifier: AGPL-3.0-or-later

package server

// Wiring of the real dial policy into the stored push line spec (#151).

import "secagent-server/cmd/secagent-server/internal/repeater"

func init() {
	specConfigureDialPolicy = func(allowLoopback bool, deny, allow string) (func(), error) {
		p, err := repeater.ParseDialPolicy(allowLoopback, deny, allow)
		if err != nil {
			return nil, err
		}
		return repeater.SetDialPolicy(p), nil
	}
}
