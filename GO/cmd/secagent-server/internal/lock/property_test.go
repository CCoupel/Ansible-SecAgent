package lock

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"sync"
	"testing"
	"time"
)

// Property: with N instances racing for the lock, random freezes (a process stopped between any
// two operations, up to longer than the staleness) and crashes, there is NEVER a moment where two
// instances validly hold the lock, and NEVER a state write by an instance after another instance
// has written (an evicted master that wakes up is refused by its guard).

type knobs struct {
	freezeProb float64 // per file operation
	longFreeze float64 // among freezes: longer than the master staleness
	crashProb  float64 // per file operation: the process never runs again
	meanFreeze time.Duration
	torn       bool // a write is visible half done (NFS): empty, then a third, then complete
}

// delayFS freezes the calling actor (a process stopped by the scheduler or by a slow mount)
// BEFORE an operation: the operation itself is then instantaneous in virtual time.
type delayFS struct {
	inner *memFS
	clk   *simClock
	ctx   context.Context
	r     *rand.Rand
	k     knobs
}

func (d *delayFS) freeze() {
	p := d.r.Float64()
	switch {
	case p < d.k.crashProb:
		_ = d.clk.Sleep(d.ctx, 24*time.Hour)
	case p < d.k.crashProb+d.k.freezeProb:
		dur := time.Duration(d.r.Int63n(int64(d.k.meanFreeze)*2 + 1))
		if d.r.Float64() < d.k.longFreeze {
			dur = DefaultParams().MasterStale + time.Duration(d.r.Int63n(int64(3*time.Minute)))
		}
		_ = d.clk.Sleep(d.ctx, dur)
	}
}

func (d *delayFS) CreateExclusive(path string, perm os.FileMode) (Handle, error) {
	d.freeze()
	h, err := d.inner.CreateExclusive(path, perm)
	if err != nil {
		return nil, err
	}
	return &delayHandle{h: h, d: d}, nil
}
func (d *delayFS) ReadFile(p string) ([]byte, error) { d.freeze(); return d.inner.ReadFile(p) }
func (d *delayFS) Remove(p string) error             { d.freeze(); return d.inner.Remove(p) }
func (d *delayFS) StatPath(p string) (FileID, error) { d.freeze(); return d.inner.StatPath(p) }
func (d *delayFS) MkdirAll(p string) error           { return nil }

type delayHandle struct {
	h Handle
	d *delayFS
}

func (h *delayHandle) Rewrite(b []byte) error {
	h.d.freeze()
	if mh, ok := h.h.(*memHandle); ok && h.d.k.torn {
		// a write seen half done by other processes: empty, then a third, then complete
		mh.setRaw(nil)
		_ = h.d.clk.Sleep(h.d.ctx, time.Duration(h.d.r.Int63n(int64(250*time.Millisecond))))
		mh.setRaw(b[:20])
		_ = h.d.clk.Sleep(h.d.ctx, time.Duration(h.d.r.Int63n(int64(250*time.Millisecond))))
	}
	return h.h.Rewrite(b)
}
func (h *delayHandle) Chmod(m os.FileMode) error { h.d.freeze(); return h.h.Chmod(m) }
func (h *delayHandle) ID() (FileID, error)       { return h.h.ID() }
func (h *delayHandle) Close() error              { return h.h.Close() }

// registry of every Lock ever created (generations), for the invariant probes.
type registry struct {
	mu    sync.Mutex
	locks []*Lock
	fs    *memFS
}

func (r *registry) add(l *Lock) { r.mu.Lock(); r.locks = append(r.locks, l); r.mu.Unlock() }

// holds is a pure, read-only probe: the lock file carries this instance's id AND is this
// instance's inode.
func (r *registry) holds(l *Lock) bool {
	l.mu.Lock()
	h, master, lost := l.h, l.master, l.lost
	l.mu.Unlock()
	if !master || lost || h == nil {
		return false
	}
	c, ok := r.fs.content(lockPath)
	if !ok || c.InstanceID != l.id || c.Role != RoleMaster {
		return false
	}
	mine, _ := h.ID()
	onPath, err := r.fs.inner().StatPath(lockPath)
	return err == nil && mine == onPath
}

func (m *memFS) inner() *memFS { return m }

func (r *registry) holders() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	for _, l := range r.locks {
		if r.holds(l) {
			out = append(out, l.id)
		}
	}
	return out
}

// writes records the guarded writes and enforces "no write after another instance wrote".
type writes struct {
	mu      sync.Mutex
	order   []string
	retired map[string]bool
	last    string
	errs    []string
	refused int // guard refusals (a superseded master that woke up, or a lost lock)
}

func newWrites() *writes { return &writes{retired: map[string]bool{}} }

func (w *writes) record(id string, now time.Time) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.retired[id] {
		w.errs = append(w.errs, fmt.Sprintf("%s wrote at %v after being superseded (writes: %v)", id, now, w.order))
	}
	if w.last != "" && w.last != id {
		w.retired[w.last] = true
	}
	w.last = id
	w.order = append(w.order, id)
}

func runScenario(t *testing.T, seed int64, n int, k knobs, duration time.Duration, reuse bool) (*registry, *writes, *sim) {
	t.Helper()
	s := newSim()
	fs := newMemFS()
	fs.reuseInodes = reuse
	reg := &registry{fs: fs}
	w := newWrites()
	ctx, cancel := context.WithCancel(context.Background())

	for i := 0; i < n; i++ {
		name := fmt.Sprintf("n%d", i)
		r := rand.New(rand.NewSource(seed*100 + int64(i)))
		s.Go(func() {
			for gen := 0; ctx.Err() == nil; gen++ {
				id := fmt.Sprintf("%s-g%d", name, gen)
				clk := &simClock{s: s}
				l, err := New(Config{Dir: simDir, FS: &delayFS{inner: fs, clk: clk, ctx: ctx, r: r, k: k}, Clock: clk,
					Rand: &simRand{r: rand.New(rand.NewSource(r.Int63())), id: id}, Host: name, Params: DefaultParams(), Spawn: s.Go})
				if err != nil {
					t.Error(err)
					return
				}
				reg.add(l)
				if l.Acquire(ctx) != nil {
					return
				}
				mctx, mcancel := context.WithCancel(ctx)
				s.Go(func() { _ = l.Maintain(mctx) })
				for ctx.Err() == nil && l.IsMaster() {
					if clk.Sleep(ctx, time.Second+time.Duration(r.Int63n(int64(14*time.Second)))) != nil {
						break
					}
					if l.CheckOwnership() == nil {
						w.record(id, s.Now())
					} else {
						w.mu.Lock()
						w.refused++
						w.mu.Unlock()
					}
				}
				mcancel()
				// the process exited (lost the lock): the supervisor restarts it with a NEW instance id
				if clk.Sleep(ctx, 5*time.Second+time.Duration(r.Int63n(int64(55*time.Second)))) != nil {
					return
				}
			}
		})
	}

	end := s.Now().Add(duration)
	for s.Now().Before(end) {
		s.Advance(time.Second)
		if h := reg.holders(); len(h) > 1 {
			t.Fatalf("seed %d: two instances hold the lock at %v: %v (writes %v)", seed, s.Now(), h, w.order)
		}
	}
	cancel()
	s.Drain() // every actor ends before the next scenario
	return reg, w, s
}

func TestProperty_NeverTwoMastersWriting(t *testing.T) {
	// 16 seeds in every mode: the hazard scenarios are deterministic per seed, and fewer seeds do not all
	// reach a takeover (the run takes under a second anyway)
	const seeds = 16
	scenarios := []struct {
		name string
		k    knobs
	}{
		{"light freezes", knobs{freezeProb: 0.02, meanFreeze: 2 * time.Second}},
		{"heavy freezes", knobs{freezeProb: 0.15, meanFreeze: 4 * time.Second}},
		{"long freezes (beyond the staleness)", knobs{freezeProb: 0.03, longFreeze: 0.4, meanFreeze: 3 * time.Second}},
		{"crashes", knobs{freezeProb: 0.05, crashProb: 0.004, meanFreeze: 2 * time.Second}},
		{"torn writes (NFS)", knobs{freezeProb: 0.02, meanFreeze: 2 * time.Second, torn: true}},
		{"torn writes and long freezes", knobs{freezeProb: 0.03, longFreeze: 0.4, meanFreeze: 3 * time.Second, torn: true}},
	}
	for _, sc := range scenarios {
		for _, reuse := range []bool{false, true} {
			name := sc.name
			if reuse {
				name += " / inode numbers reused"
			}
			t.Run(name, func(t *testing.T) {
				totalWrites, takeovers, refused := 0, 0, 0
				for seed := int64(1); seed <= int64(seeds); seed++ {
					_, w, _ := runScenario(t, seed, 3, sc.k, 20*time.Minute, reuse)
					w.mu.Lock()
					if len(w.errs) > 0 {
						t.Fatalf("seed %d: %v", seed, w.errs)
					}
					totalWrites += len(w.order)
					distinct := map[string]bool{}
					for _, id := range w.order {
						distinct[id] = true
					}
					takeovers += len(distinct) - 1
					refused += w.refused
					w.mu.Unlock()
				}
				t.Logf("%d seeds: %d guarded writes, %d takeovers, %d refusals of an evicted master", seeds, totalWrites, takeovers, refused)
				if totalWrites == 0 {
					t.Fatal("the scenarios never produced a single guarded write: the property is vacuous")
				}
				if sc.k.longFreeze > 0 && (takeovers == 0 || refused == 0) {
					t.Fatalf("long freezes must produce takeovers and refusals of the evicted master (got %d, %d): the scenario does not exercise the hazard", takeovers, refused)
				}
			})
		}
	}
}

// Liveness without faults: one master emerges, stays, and writes.
func TestProperty_ACalmClusterElectsExactlyOneMaster(t *testing.T) {
	for seed := int64(1); seed <= 10; seed++ {
		reg, w, _ := runScenario(t, seed, 4, knobs{}, 5*time.Minute, false)
		if h := reg.holders(); len(h) != 1 {
			t.Fatalf("seed %d: %d holders at the end: %v", seed, len(h), h)
		}
		if len(w.order) == 0 || len(w.errs) > 0 {
			t.Fatalf("seed %d: writes=%d errs=%v", seed, len(w.order), w.errs)
		}
		for _, id := range w.order {
			if id != w.order[0] {
				t.Fatalf("seed %d: the master changed in a calm cluster: %v", seed, w.order)
			}
		}
	}
}
