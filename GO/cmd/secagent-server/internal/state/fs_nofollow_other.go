// SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !unix

package state

// oNoFollow is not available outside unix (Linux is the only supported target).
const oNoFollow = 0
