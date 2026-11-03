// SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build race

package storage

// raceFactor relaxes the dimensioning thresholds under the race detector.
const raceFactor = 8
