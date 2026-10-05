package storage

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"secagent-server/cmd/secagent-server/internal/state"
)

// OpenTemp returns a store backed by a private temporary state directory, with an allow-all write
// guard and the explicit insecure test mode (secrets in clear). It is for tests and tools only:
// production opens its STATE_DIR with Open. The directory is removed by Close.
//
// The initial state (one RSA key) is generated once per process and copied for every store.
func OpenTemp() (*Store, error) {
	dir, err := os.MkdirTemp("", "secagent-state-*")
	if err != nil {
		return nil, err
	}
	s, err := OpenTestDir(dir)
	if err != nil {
		_ = os.RemoveAll(dir)
		return nil, err
	}
	s.cleanup = func() { _ = os.RemoveAll(dir) }
	return s, nil
}

// OpenTestDir opens (creating the initial test state when the directory has none) the state of dir
// with an allow-all write guard and the insecure test mode. Reopening the same directory is how
// tests simulate a restart. Tests and tools only.
func OpenTestDir(dir string) (*Store, error) {
	path := filepath.Join(dir, state.StateFile)
	if _, err := os.Stat(path); err != nil {
		tpl, terr := tempTemplate()
		if terr != nil {
			return nil, terr
		}
		if err := copyFile(tpl, path); err != nil {
			return nil, err
		}
	}
	return Open(state.Options{Dir: dir, BeforeWrite: func() error { return nil }, InsecureTestMode: true, Instance: "test"})
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
