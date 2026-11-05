// SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
// SPDX-License-Identifier: AGPL-3.0-or-later

package ws

// Wiring of the #216 quota table into the spec tests (event_quota_spec_test.go).

func init() {
	specEventQuotaEntries = eventQuotaEntries
}
