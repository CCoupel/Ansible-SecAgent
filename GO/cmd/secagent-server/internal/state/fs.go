package state

import (
	"errors"
	"io"
	"os"
	"syscall"
)

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
	ReadFile(name string) ([]byte, error)
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
func (OSFS) ReadFile(n string) ([]byte, error)         { return os.ReadFile(n) }
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
