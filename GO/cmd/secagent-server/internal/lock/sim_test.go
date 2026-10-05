package lock

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"sort"
	"sync"
	"testing"
	"time"
)

// ── deterministic simulation: virtual time, in-memory FS, cooperative actors ─

// sim owns the virtual time. Actors (goroutines started with Go) block in Sleep and are woken one
// at a time, in time order, by Advance: with a single runnable goroutine at any moment the run is
// deterministic. The test goroutine itself uses "immediate" clocks: their Sleep advances the time.
type sim struct {
	mu      sync.Mutex
	now     time.Time
	waiters []*waiter
	running int
	cond    *sync.Cond
}

type waiter struct {
	wake time.Time
	ch   chan struct{}
	seq  int
}

func newSim() *sim {
	s := &sim{now: time.Unix(1_700_000_000, 0)}
	s.cond = sync.NewCond(&s.mu)
	return s
}

func (s *sim) Now() time.Time { s.mu.Lock(); defer s.mu.Unlock(); return s.now }

// Go registers fn as an actor. It does NOT start running now: it is released, in time order, by
// the next Advance, so that the creator keeps the only running goroutine (determinism).
func (s *sim) Go(fn func()) {
	s.mu.Lock()
	w := &waiter{wake: s.now, ch: make(chan struct{}), seq: len(s.waiters)}
	s.waiters = append(s.waiters, w)
	s.mu.Unlock()
	go func() {
		<-w.ch // released by Advance, which accounted for us as running
		defer func() {
			s.mu.Lock()
			s.running--
			s.cond.Broadcast()
			s.mu.Unlock()
		}()
		fn()
	}()
}

// block parks the calling actor until the simulation releases it. The context is checked AFTER the
// wake-up (never during the wait): an actor must only ever run when the simulation lets it, or the
// run would not be deterministic.
func (s *sim) block(d time.Duration, ctx context.Context) error {
	s.mu.Lock()
	w := &waiter{wake: s.now.Add(d), ch: make(chan struct{}), seq: len(s.waiters)}
	s.waiters = append(s.waiters, w)
	s.running--
	s.cond.Broadcast()
	s.mu.Unlock()
	<-w.ch
	return ctx.Err()
}

// Drain releases every actor, one at a time and in time order, until none is left (the contexts
// are canceled first: they all return). The virtual time jumps as needed.
func (s *sim) Drain() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for {
		s.settleLocked()
		if len(s.waiters) == 0 {
			return
		}
		sort.SliceStable(s.waiters, func(i, j int) bool { return s.waiters[i].wake.Before(s.waiters[j].wake) })
		w := s.waiters[0]
		s.waiters = s.waiters[1:]
		if w.wake.After(s.now) {
			s.now = w.wake
		}
		s.running++
		close(w.ch)
	}
}

func (s *sim) settleLocked() {
	for s.running > 0 {
		s.cond.Wait()
	}
}

// Advance moves the virtual time forward by d, running every actor that wakes up on the way.
func (s *sim) Advance(d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	target := s.now.Add(d)
	for {
		s.settleLocked()
		sort.SliceStable(s.waiters, func(i, j int) bool { return s.waiters[i].wake.Before(s.waiters[j].wake) })
		if len(s.waiters) == 0 || s.waiters[0].wake.After(target) {
			break
		}
		w := s.waiters[0]
		s.waiters = s.waiters[1:]
		if w.wake.After(s.now) {
			s.now = w.wake
		}
		s.running++
		close(w.ch)
	}
	s.settleLocked()
	s.now = target
}

// clockFor returns an instance clock. immediate=true: Sleep advances the whole simulation (used
// by code driven from the test goroutine); onSleep (optional) runs after the time moved.
type simClock struct {
	s         *sim
	immediate bool
	onSleep   func(d time.Duration)
}

func (c *simClock) Now() time.Time { return c.s.Now() }
func (c *simClock) Sleep(ctx context.Context, d time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if c.immediate {
		if c.onSleep != nil {
			c.onSleep(d)
		}
		c.s.Advance(d)
		return nil
	}
	return c.s.block(d, ctx)
}

// ── in-memory FS with inodes ────────────────────────────────────────────────

type inode struct {
	id   uint64
	data []byte
	mode os.FileMode
}

type chmodRec struct {
	ino  uint64
	mode os.FileMode
}

type memFS struct {
	mu          sync.Mutex
	next        uint64
	files       map[string]*inode
	ignoreModes bool // stat reports 0644 and fchmod has no visible effect
	reuseInodes bool // a new file gets the inode number of a deleted one (ext4/tmpfs/NFS do): the inode check can no longer tell files apart
	freeInos    []uint64
	failWrites  bool // storage lost: every write/create fails
	chmods      []chmodRec
	before      func(op string) // called before each operation (freezes, latency), WITHOUT the fs lock
}

func newMemFS() *memFS { return &memFS{files: map[string]*inode{}, next: 100} }

func (m *memFS) hook(op string) {
	if m.before != nil {
		m.before(op)
	}
}

type memHandle struct {
	fs  *memFS
	ino *inode
}

func (m *memFS) CreateExclusive(path string, perm os.FileMode) (Handle, error) {
	m.hook("create")
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failWrites {
		return nil, fmt.Errorf("storage unavailable")
	}
	if _, ok := m.files[path]; ok {
		return nil, fmt.Errorf("create %s: %w", path, os.ErrExist)
	}
	var id uint64
	if m.reuseInodes && len(m.freeInos) > 0 {
		id, m.freeInos = m.freeInos[len(m.freeInos)-1], m.freeInos[:len(m.freeInos)-1]
	} else {
		m.next++
		id = m.next
	}
	ino := &inode{id: id, mode: perm}
	m.files[path] = ino
	return &memHandle{fs: m, ino: ino}, nil
}

func (m *memFS) ReadFile(path string) ([]byte, error) {
	m.hook("read")
	m.mu.Lock()
	defer m.mu.Unlock()
	f, ok := m.files[path]
	if !ok {
		return nil, fmt.Errorf("read %s: %w", path, os.ErrNotExist)
	}
	return append([]byte(nil), f.data...), nil
}

func (m *memFS) Remove(path string) error {
	m.hook("remove")
	m.mu.Lock()
	defer m.mu.Unlock()
	f, ok := m.files[path]
	if !ok {
		return fmt.Errorf("remove %s: %w", path, os.ErrNotExist)
	}
	m.freeInos = append(m.freeInos, f.id)
	delete(m.files, path)
	return nil
}

func (m *memFS) StatPath(path string) (FileID, error) {
	m.hook("stat")
	m.mu.Lock()
	defer m.mu.Unlock()
	f, ok := m.files[path]
	if !ok {
		return FileID{}, fmt.Errorf("stat %s: %w", path, os.ErrNotExist)
	}
	return FileID{Dev: 1, Ino: f.id}, nil
}

func (m *memFS) MkdirAll(string) error { return nil }

// Mode is what an operator would see with ls (0644 when modes are ignored).
func (m *memFS) Mode(path string) (os.FileMode, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	f, ok := m.files[path]
	if !ok {
		return 0, false
	}
	if m.ignoreModes {
		return 0o644, true
	}
	return f.mode, true
}

func (m *memFS) content(path string) (content, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	f, ok := m.files[path]
	if !ok {
		return content{}, false
	}
	return parseContent(f.data)
}

func (h *memHandle) Rewrite(b []byte) error {
	h.fs.hook("write")
	h.fs.mu.Lock()
	defer h.fs.mu.Unlock()
	if h.fs.failWrites {
		return fmt.Errorf("storage unavailable")
	}
	h.ino.data = append([]byte(nil), b...)
	return nil
}

func (h *memHandle) Chmod(mode os.FileMode) error {
	h.fs.mu.Lock()
	defer h.fs.mu.Unlock()
	h.fs.chmods = append(h.fs.chmods, chmodRec{ino: h.ino.id, mode: mode})
	if !h.fs.ignoreModes {
		h.ino.mode = mode
	}
	return nil
}

func (h *memHandle) ID() (FileID, error) { return FileID{Dev: 1, Ino: h.ino.id}, nil }
func (h *memHandle) Close() error        { return nil }

// ── deterministic randomness ────────────────────────────────────────────────

type simRand struct {
	r  *rand.Rand
	id string
}

func (s *simRand) InstanceID() string { return s.id }
func (s *simRand) Duration(min, max time.Duration) time.Duration {
	if max <= min {
		return min
	}
	return min + time.Duration(s.r.Int63n(int64(max-min)+1))
}

// ── fixtures ────────────────────────────────────────────────────────────────

const simDir = "/state"

var lockPath = simDir + "/" + FileName

// testParams are the production values: the cases run on the real calibration.
func testParams() Params { return DefaultParams() }

type inst struct {
	l     *Lock
	clk   *simClock
	lost  []error
	lostT []time.Time
	name  string
}

// newInst builds an instance on the shared sim and FS. immediate=true: driven by the test goroutine.
func newInst(t testing.TB, s *sim, fs FS, name string, seed int64, immediate bool, mod func(*Config)) *inst {
	t.Helper()
	in := &inst{name: name, clk: &simClock{s: s, immediate: immediate}}
	cfg := Config{Dir: simDir, FS: fs, Clock: in.clk, Rand: &simRand{r: rand.New(rand.NewSource(seed)), id: name + "-id"}, Host: name, Params: testParams(), Spawn: s.Go,
		OnLost: func(err error) { in.lost = append(in.lost, err); in.lostT = append(in.lostT, s.Now()) }}
	if mod != nil {
		mod(&cfg)
	}
	l, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	in.l = l
	return in
}

// fsPair runs body once with a normal FS and once with an FS that ignores modes.
func forBothModes(t *testing.T, body func(t *testing.T, fs *memFS)) {
	for _, ignore := range []bool{false, true} {
		name := "modes honored"
		if ignore {
			name = "modes ignored"
		}
		t.Run(name, func(t *testing.T) {
			fs := newMemFS()
			fs.ignoreModes = ignore
			body(t, fs)
		})
	}
}

// forAllFS also replays with inode numbers that get reused after a deletion: the instance_id in
// the content is then the only thing that tells the files apart. Only for cases whose assertions do
// not rely on distinct inodes.
func forAllFS(t *testing.T, body func(t *testing.T, fs *memFS)) {
	forBothModes(t, body)
	t.Run("inodes reused", func(t *testing.T) {
		fs := newMemFS()
		fs.ignoreModes, fs.reuseInodes = true, true
		body(t, fs)
	})
}

// engine is a stand-in for the state engine: a write happens only if the guard passes.
type engine struct {
	mu     sync.Mutex
	writes []string // instance names, in order
}

func (e *engine) write(in *inst, s *sim) bool {
	if err := in.l.CheckOwnership(); err != nil {
		return false
	}
	e.mu.Lock()
	e.writes = append(e.writes, in.name)
	e.mu.Unlock()
	return true
}

func (e *engine) count(name string) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	n := 0
	for _, w := range e.writes {
		if w == name {
			n++
		}
	}
	return n
}
