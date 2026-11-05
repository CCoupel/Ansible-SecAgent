// SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package testsupport prepares the temporary state directories of the tests. It does not import
// storage (so storage's own tests can use it) and is imported by test code only: nothing of it is in a
// release binary (#221).
package testsupport

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"secagent-server/cmd/secagent-server/internal/state"
)

// TempDir returns a new private temporary state directory (the caller removes it) holding the initial
// test state (one RSA key, generated once per process and copied).
func TempDir() (string, error) {
	dir, err := os.MkdirTemp("", "secagent-state-*")
	if err != nil {
		return "", err
	}
	if err := Prepare(dir); err != nil {
		_ = os.RemoveAll(dir)
		return "", err
	}
	return dir, nil
}

// Prepare creates the initial test state in dir when it has none (reopening the same directory is how
// tests simulate a restart).
func Prepare(dir string) error {
	path := filepath.Join(dir, state.StateFile)
	if _, err := os.Stat(path); err == nil {
		return nil
	}
	tpl, err := tempTemplate()
	if err != nil {
		return err
	}
	return copyFile(tpl, path)
}

// Options are the engine options of a test store: allow-all write guard and the explicit insecure test
// mode (secrets in clear).
func Options(dir string) state.Options {
	return state.Options{Dir: dir, BeforeWrite: func() error { return nil }, InsecureTestMode: true, Instance: "test"}
}

var (
	tplOnce sync.Once
	tplPath string
	tplErr  error
)

func tempTemplate() (string, error) {
	tplOnce.Do(func() {
		dir, err := os.MkdirTemp("", "secagent-state-template-*")
		if err != nil {
			tplErr = err
			return
		}
		if err := state.Init(state.InitOptions{Dir: dir, AllowPlaintext: true, RSABits: 2048}); err != nil {
			tplErr = fmt.Errorf("state init (template): %w", err)
			return
		}
		tplPath = filepath.Join(dir, state.StateFile)
	})
	return tplPath, tplErr
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}
