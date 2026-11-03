// SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build race

package state

// raceFactor relaxes the performance thresholds under the race detector (5-10x slower).
const raceFactor = 8
