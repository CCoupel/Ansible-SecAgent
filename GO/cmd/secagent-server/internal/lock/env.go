package lock

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"math/big"
	"os"
	"syscall"
	"time"
)

// FileID identifies a file independently of its path (device and inode).
type FileID struct{ Dev, Ino uint64 }

// Handle is the descriptor the lock keeps open for its whole life. Every action on "my" file goes
// through it (never through the path): after the file was deleted and replaced, the handle still
// points to the old inode.
type Handle interface {
	// Rewrite replaces the whole content in place and fsyncs.
	Rewrite(content []byte) error
	// Chmod is fchmod on the descriptor.
	Chmod(mode os.FileMode) error
	// ID is fstat of the descriptor.
	ID() (FileID, error)
	Close() error
}

// FS is the file system the lock uses. Reads REOPEN the file (NFS close-to-open consistency);
// the logic never lists a directory, never reads mtime and never chmods a path.
type FS interface {
	// CreateExclusive is open(O_CREAT|O_EXCL|O_WRONLY, perm): os.ErrExist when it is already there.
	CreateExclusive(path string, perm os.FileMode) (Handle, error)
	ReadFile(path string) ([]byte, error)
	Remove(path string) error
	// StatPath is lstat of the path.
	StatPath(path string) (FileID, error)
	MkdirAll(dir string) error
}

// Clock is the local monotonic clock. Staleness is judged on it, never on file times.
type Clock interface {
	Now() time.Time
	Sleep(ctx context.Context, d time.Duration) error
}

// Rand supplies the instance id and the random pause.
type Rand interface {
	InstanceID() string
	Duration(min, max time.Duration) time.Duration
}

// ── real implementations ─────────────────────────────────────────────────────

// OSFS is the real file system.
type OSFS struct{}

type osHandle struct{ f *os.File }

func (OSFS) CreateExclusive(path string, perm os.FileMode) (Handle, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return nil, err
	}
	// the umask may have removed bits: fchmod on the descriptor makes the hint exact
	if err := f.Chmod(perm); err != nil {
		_ = f.Close()
		return nil, err
	}
	return &osHandle{f: f}, nil
}

func (OSFS) ReadFile(path string) ([]byte, error) { return os.ReadFile(path) }
func (OSFS) Remove(path string) error             { return os.Remove(path) }
func (OSFS) MkdirAll(dir string) error            { return os.MkdirAll(dir, 0o755) }

func (OSFS) StatPath(path string) (FileID, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return FileID{}, err
	}
	return idOf(fi)
}

func idOf(fi os.FileInfo) (FileID, error) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return FileID{}, os.ErrInvalid
	}
	return FileID{Dev: uint64(st.Dev), Ino: uint64(st.Ino)}, nil //nolint:unconvert // platform dependent widths
}

func (h *osHandle) Rewrite(content []byte) error {
	if err := h.f.Truncate(0); err != nil {
		return err
	}
	if _, err := h.f.WriteAt(content, 0); err != nil {
		return err
	}
	return h.f.Sync()
}

func (h *osHandle) Chmod(mode os.FileMode) error { return h.f.Chmod(mode) }
func (h *osHandle) Close() error                 { return h.f.Close() }
func (h *osHandle) ID() (FileID, error) {
	fi, err := h.f.Stat()
	if err != nil {
		return FileID{}, err
	}
	return idOf(fi)
}

// RealClock is the process clock (time.Now carries the monotonic reading used by Sub).
type RealClock struct{}

func (RealClock) Now() time.Time { return time.Now() }
func (RealClock) Sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// CryptoRand draws the instance id (128 random bits, new at every process start) and the pause
// from crypto/rand.
type CryptoRand struct{ R io.Reader }

func (c CryptoRand) reader() io.Reader {
	if c.R != nil {
		return c.R
	}
	return rand.Reader
}

func (c CryptoRand) InstanceID() string {
	b := make([]byte, 16)
	if _, err := io.ReadFull(c.reader(), b); err != nil {
		panic("lock: no entropy: " + err.Error()) // an instance id that is not random would break exclusivity
	}
	return hex.EncodeToString(b)
}

func (c CryptoRand) Duration(min, max time.Duration) time.Duration {
	if max <= min {
		return min
	}
	n, err := rand.Int(c.reader(), big.NewInt(int64(max-min)+1))
	if err != nil {
		return max
	}
	return min + time.Duration(n.Int64())
}
