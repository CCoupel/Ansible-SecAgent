package state

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var errInjected = errors.New("injected fault")

// faultFS wraps the real FS and fails the failAt-th operation (1-based; 0 = never). Once a fault
// fired the process is "crashed": every later operation fails too (a dead process does not clean
// up), which leaves the directory exactly as a crash at that step would.
type faultFS struct {
	OSFS
	mu      sync.Mutex
	n       int
	failAt  int
	crashed bool
	tornAt  int  // fail the failAt-th op, but let a Write write half of its data first
	noLink  bool // hard links unsupported
	ops     []string
}

func (f *faultFS) step(op string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.n++
	f.ops = append(f.ops, op)
	if f.crashed {
		return errInjected
	}
	if f.failAt > 0 && f.n == f.failAt {
		f.crashed = true
		return errInjected
	}
	return nil
}

func (f *faultFS) CreateExclusive(n string, perm os.FileMode) (File, error) {
	if err := f.step("create"); err != nil {
		return nil, err
	}
	file, err := f.OSFS.CreateExclusive(n, perm)
	if err != nil {
		return nil, err
	}
	return &faultFile{File: file, fs: f}, nil
}
func (f *faultFS) Rename(a, b string) error {
	if err := f.step("rename"); err != nil {
		return err
	}
	return f.OSFS.Rename(a, b)
}
func (f *faultFS) Link(a, b string) error {
	if f.noLink {
		return errors.New("links unsupported")
	}
	if err := f.step("link"); err != nil {
		return err
	}
	return f.OSFS.Link(a, b)
}
func (f *faultFS) Remove(n string) error {
	if err := f.step("remove"); err != nil {
		return err
	}
	return f.OSFS.Remove(n)
}
func (f *faultFS) SyncDir(d string) error {
	if err := f.step("syncdir"); err != nil {
		return err
	}
	return f.OSFS.SyncDir(d)
}

type faultFile struct {
	File
	fs *faultFS
}

func (w *faultFile) Write(p []byte) (int, error) {
	if err := w.fs.step("write"); err != nil {
		if w.fs.tornAt != 0 { // torn write: half of the data reaches the disk
			_, _ = w.File.Write(p[:len(p)/2])
		}
		return 0, err
	}
	return w.File.Write(p)
}
func (w *faultFile) Sync() error {
	if err := w.fs.step("sync"); err != nil {
		return err
	}
	return w.File.Sync()
}
func (w *faultFile) Close() error {
	if err := w.fs.step("close"); err != nil {
		_ = w.File.Close()
		return err
	}
	return w.File.Close()
}

// seedState writes an empty valid state (write_seq 1) into dir.
func seedState(t testing.TB, dir string) {
	t.Helper()
	p := newPayload()
	data, err := encode(&p, 1, "seed", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := atomicWrite(OSFS{}, dir, data, false); err != nil {
		t.Fatal(err)
	}
}

var allowAll = func() error { return nil }

func openEngine(t testing.TB, dir string, mod func(*Options)) *Engine {
	t.Helper()
	o := Options{Dir: dir, BeforeWrite: allowAll, Instance: "test"}
	if mod != nil {
		mod(&o)
	}
	e, err := Open(o)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return e
}

func testPEM(host string) string {
	return "-----BEGIN PUBLIC KEY-----\n" + strings.Repeat(host+"A", 60) + "\n-----END PUBLIC KEY-----\n"
}

func addAgent(host string) func(*Tx) error {
	return func(tx *Tx) error {
		return tx.PutAgent(Agent{Hostname: host, PublicKeyPEM: testPEM(host), TokenJTI: "jti-" + host, EnrolledAt: time.Unix(1700000000, 0).UTC()})
	}
}

func listDir(t testing.TB, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range ents {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	return names
}

// captureSlog redirects the default slog logger into a buffer for the test.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

func captureSlog(t testing.TB) *syncBuf {
	t.Helper()
	buf := &syncBuf{}
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return buf
}

func mustFile(t testing.TB, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mode(t testing.TB, path string) os.FileMode {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode().Perm()
}

var counter atomic.Int64

func uniq(prefix string) string { return fmt.Sprintf("%s-%d", prefix, counter.Add(1)) }

var _ = filepath.Join
