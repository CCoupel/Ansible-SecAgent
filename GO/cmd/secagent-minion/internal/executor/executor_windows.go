// SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package executor — stubs Windows.
//
// Le scope v1 est Linux uniquement (CLAUDE.md §Décisions techniques).
// Ces stubs permettent à `GOOS=windows go vet ./...` de compiler sans erreur.

//go:build windows

package executor

import "os/exec"

// setupCmdSysProcAttr est un noop sur Windows (pas de groupes de processus POSIX).
func setupCmdSysProcAttr(_ *exec.Cmd) {}

// setCmdCancel est un noop sur Windows.
// Sur Windows, exec.CommandContext utilise TerminateProcess, ce qui est suffisant
// pour le périmètre v1 (Linux uniquement).
func setCmdCancel(_ *exec.Cmd) {}
