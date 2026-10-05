package state

import (
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
)

// errTooBig: a state file larger than the configured ceiling.
var errTooBig = errors.New("state file larger than the size ceiling")

// File is the subset of *os.File the engine writes through.
type File interface {
	io.Writer
	Sync() error
	Close() error
}

// FS is the file system the engine uses. Tests inject faults through it (crash at every step of
// the atomic write); production uses OSFS.
type FS interface {
	MkdirAll(path string, perm os.FileMode) error
	// ReadFileMax reads name without following a final symbolic link, refusing (errTooBig) a file
	// larger than max bytes BEFORE reading it.
	ReadFileMax(name string, max int64) ([]byte, error)
	// CreateExclusive creates name (O_EXCL) with mode perm; an existing file is an error.
	CreateExclusive(name string, perm os.FileMode) (File, error)
	Rename(oldpath, newpath string) error
	Link(oldpath, newpath string) error
	Remove(name string) error
	Stat(name string) (os.FileInfo, error)
	// SyncDir flushes the directory entry changes (rename, link, remove) to disk.
	SyncDir(dir string) error
}

// OSFS is the real file system.
type OSFS struct{}

func (OSFS) MkdirAll(p string, perm os.FileMode) error { return os.MkdirAll(p, perm) }
func (OSFS) ReadFileMax(n string, max int64) ([]byte, error) {
	f, err := os.OpenFile(n, os.O_RDONLY|oNoFollow, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	if fi, err := f.Stat(); err != nil {
		return nil, err
	} else if max > 0 && fi.Size() > max {
		return nil, fmt.Errorf("%w: %d bytes > %d", errTooBig, fi.Size(), max)
	}
	if max <= 0 {
		return io.ReadAll(f)
	}
	data, err := io.ReadAll(io.LimitReader(f, max+1)) // the file may grow after the stat
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, fmt.Errorf("%w: more than %d bytes", errTooBig, max)
	}
	return data, nil
}
func (OSFS) CreateExclusive(n string, perm os.FileMode) (File, error) {
	f, err := os.OpenFile(n, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return nil, err
	}
	// the umask can only remove bits, but be explicit: the file is 0600 whatever the environment
	if err := f.Chmod(perm); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}
func (OSFS) Rename(a, b string) error           { return os.Rename(a, b) }
func (OSFS) Link(a, b string) error             { return os.Link(a, b) }
func (OSFS) Remove(n string) error              { return os.Remove(n) }
func (OSFS) Stat(n string) (os.FileInfo, error) { return os.Stat(n) }
func (OSFS) SyncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	if err := d.Sync(); err != nil && !errors.Is(err, syscall.EINVAL) && !errors.Is(err, syscall.ENOTSUP) {
		return err
	}
	return nil
}

func exists(fs FS, name string) (bool, error) {
	_, err := fs.Stat(name)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, err
}
