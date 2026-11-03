//go:build unix

package secretenv

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// B61: a named pipe never blocks the read (neither at the Lstat nor if it is swapped in before the open), and a
// symbolic link swapped in before the open is refused by O_NOFOLLOW.
func TestReadFile_NamedPipeAndSymlinkNeverBlock(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "pipe")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	done := make(chan error, 1)
	go func() { _, err := ReadFile(fifo); done <- err }()
	select {
	case err := <-done:
		if !errors.Is(err, ErrNotRegular) {
			t.Fatalf("a named pipe: %v, want ErrNotRegular", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("reading a named pipe blocked")
	}
	// the open itself (the race window after the Lstat) does not block on a pipe and the descriptor is not regular
	f, err := openSecret(fifo)
	if err != nil {
		t.Fatalf("openSecret on a pipe must return at once: %v", err)
	}
	defer func() { _ = f.Close() }()
	if fi, serr := f.Stat(); serr != nil || fi.Mode().IsRegular() {
		t.Fatalf("the descriptor of a pipe must not look regular: %v %v", fi, serr)
	}
	// a symbolic link in final position is refused by the open
	target := filepath.Join(dir, "real")
	if err := os.WriteFile(target, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink: %v", err)
	}
	if _, err := openSecret(link); !errors.Is(err, ErrSymlink) {
		t.Fatalf("openSecret on a symbolic link: %v, want ErrSymlink", err)
	}
	if _, err := ReadFile(link); !errors.Is(err, ErrSymlink) {
		t.Fatalf("ReadFile on a symbolic link: %v", err)
	}
}
