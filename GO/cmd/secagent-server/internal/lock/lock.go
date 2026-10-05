// Package lock is the master lease of a relay instance (v3.0.3, #162, variant A).
//
// Several instances of the same relay share STATE_DIR (NFS-like storage); exactly one may be the
// master (it opens the ports and writes the state), the others wait. The protocol uses ONE file,
// relay.lock:
//
//   - an instance becomes a candidate by creating it exclusively (O_CREAT|O_EXCL, mode 0755) and
//     keeping the descriptor open for the whole life of the lock;
//   - it becomes master only if, after a random pause of 1-2 s and a re-read (the file is
//     REOPENED), the content still carries its own instance_id: it then does fchmod 0700 on its
//     descriptor, checks that the path still designates its inode, and writes role=master;
//   - the master increments a beat counter every ~30 s (write in place + fsync) and checks its
//     identity every ~5 s; it gives up when no beat succeeded for ~3 min;
//   - a secondary judges the lock stale when its content did not change for ~5 min (master) or
//     ~10 s (candidate) on ITS OWN monotonic clock (never mtime), and then deletes it.
//
// The modes (0755/0700) are only a hint: the instance_id inside the file is authoritative, so a
// mount that ignores modes changes nothing. The logic never lists a directory, never reads mtime
// and never chmods a path.
//
// A residual overlap is accepted (case 5: a delayed deletion of a stale lock erases a fresh one):
// two instances may believe they are master for at most one check period, but the write guard
// (CheckOwnership, to be called before every state write) refuses the writes of the evicted one,
// and its next check makes it stop.
package lock

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Hooks are test seams: they let a test interleave another instance at a precise point of the
// protocol (a process frozen between two steps). They are nil in production.
type Hooks struct {
	BeforeRemove  func() // a stale lock was judged stale, before it is deleted
	BeforeCreate  func() // before the exclusive creation
	BeforePromote func() // the re-read showed our id, before fchmod
}

// Config configures a Lock.
type Config struct {
	Dir   string
	FS    FS     // default OSFS
	Clock Clock  // default RealClock
	Rand  Rand   // default CryptoRand
	Host  string // for logs only
	// Params default to DefaultParams(); only tests override them.
	Params Params
	// OnLost is called once when a master loses the lock (identity changed, self-retire).
	// The server must stop (fail closed): #163.
	OnLost func(error)
	Hooks  Hooks
	// Spawn starts the heartbeat goroutine (default: go). Test seam of the deterministic simulation.
	Spawn func(func())
}

type content struct {
	InstanceID string `json:"instance_id"`
	Role       string `json:"role"`
	Beat       uint64 `json:"beat"`
	Host       string `json:"host,omitempty"`
}

// Lock is one instance's view of the lease.
type Lock struct {
	cfg  Config
	p    Params
	id   string
	path string

	mu         sync.Mutex
	h          Handle // set once promoted
	master     bool
	lost       bool
	lostErr    error
	beat       uint64
	lastBeatOK time.Time

	// observation of the lock content by this secondary (monotonic local clock)
	obsRaw   string
	obsSince time.Time
	observed bool
}

// ErrNotMaster is returned by CheckOwnership when this instance does not hold the lock.
var ErrNotMaster = errors.New("lock: this instance is not the master")

// New validates the calibration and draws the instance id (128 random bits, new at every start).
func New(cfg Config) (*Lock, error) {
	if cfg.Dir == "" {
		return nil, errors.New("lock: empty directory")
	}
	if cfg.FS == nil {
		cfg.FS = OSFS{}
	}
	if cfg.Clock == nil {
		cfg.Clock = RealClock{}
	}
	if cfg.Rand == nil {
		cfg.Rand = CryptoRand{}
	}
	if cfg.Spawn == nil {
		cfg.Spawn = func(f func()) { go f() }
	}
	if cfg.Params == (Params{}) {
		cfg.Params = DefaultParams()
	}
	if err := cfg.Params.Validate(); err != nil {
		return nil, err
	}
	if cfg.Host == "" {
		cfg.Host, _ = os.Hostname()
	}
	return &Lock{cfg: cfg, p: cfg.Params, id: cfg.Rand.InstanceID(), path: filepath.Join(cfg.Dir, FileName)}, nil
}

// InstanceID is this process' identity in the lock file.
func (l *Lock) InstanceID() string { return l.id }

// IsMaster reports whether this instance currently holds the lock.
func (l *Lock) IsMaster() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.master && !l.lost
}

func (l *Lock) log(msg string, args ...any) {
	slog.Info("lock: "+msg, append([]any{"instance_id", l.id, "host", l.cfg.Host}, args...)...)
}

func (l *Lock) warn(msg string, args ...any) {
	slog.Warn("lock: "+msg, append([]any{"instance_id", l.id, "host", l.cfg.Host}, args...)...)
}

func encodeContent(c content) []byte {
	b, _ := json.Marshal(c)
	return b
}

func parseContent(raw []byte) (content, bool) {
	var c content
	if err := json.Unmarshal(raw, &c); err != nil || c.InstanceID == "" {
		return content{}, false
	}
	return c, true
}

// ── secondary loop ───────────────────────────────────────────────────────────

// Acquire runs the secondary loop until this instance is the master (nil) or ctx ends.
func (l *Lock) Acquire(ctx context.Context) error {
	if err := l.cfg.FS.MkdirAll(l.cfg.Dir); err != nil {
		return fmt.Errorf("lock: create %s: %w", l.cfg.Dir, err)
	}
	for {
		promoted, err := l.step(ctx)
		if err != nil {
			l.warn("candidacy step failed", "error", err)
		}
		if promoted {
			return nil
		}
		if err := l.cfg.Clock.Sleep(ctx, l.p.Check); err != nil {
			return err
		}
	}
}

// fresh records what the secondary reads and judges the staleness on its monotonic clock.
func (l *Lock) fresh(raw []byte) (isFresh bool, age time.Duration, owner content) {
	now := l.cfg.Clock.Now()
	c, ok := parseContent(raw)
	role := RoleCandidate // an unreadable or half-written file is a candidate that did not finish
	if ok {
		role = c.Role
	}
	if !l.observed || l.obsRaw != string(raw) {
		l.observed, l.obsRaw, l.obsSince = true, string(raw), now
		return true, 0, c
	}
	age = now.Sub(l.obsSince)
	limit := l.p.CandidateStale
	if role == RoleMaster {
		limit = l.p.MasterStale
	}
	return age < limit, age, c
}

// step is one iteration of the secondary loop. It returns true once promoted to master.
func (l *Lock) step(ctx context.Context) (bool, error) {
	raw, err := l.cfg.FS.ReadFile(l.path)
	switch {
	case err == nil:
		isFresh, age, owner := l.fresh(raw)
		if isFresh {
			return false, nil // somebody holds it: wait
		}
		if l.cfg.Hooks.BeforeRemove != nil {
			l.cfg.Hooks.BeforeRemove()
		}
		l.warn("stale lock removed", "stale_instance_id", owner.InstanceID, "stale_role", owner.Role, "unchanged_for", age.Round(time.Second))
		if rerr := l.cfg.FS.Remove(l.path); rerr != nil && !errors.Is(rerr, os.ErrNotExist) {
			return false, fmt.Errorf("remove stale lock: %w", rerr)
		}
	case errors.Is(err, os.ErrNotExist):
		// free
	default:
		return false, fmt.Errorf("read lock: %w", err)
	}

	if l.cfg.Hooks.BeforeCreate != nil {
		l.cfg.Hooks.BeforeCreate()
	}
	start := l.cfg.Clock.Now()
	h, err := l.cfg.FS.CreateExclusive(l.path, ModeCandidate)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return false, nil // another instance was first
		}
		return false, fmt.Errorf("create lock: %w", err)
	}
	if err := h.Rewrite(encodeContent(content{InstanceID: l.id, Role: RoleCandidate, Host: l.cfg.Host})); err != nil {
		l.abandon(h, "write failed")
		return false, fmt.Errorf("write candidate lock: %w", err)
	}
	if took := l.cfg.Clock.Now().Sub(start); took > l.p.MaxWriteLatency {
		l.abandon(h, fmt.Sprintf("creation took %v (> %v)", took, l.p.MaxWriteLatency))
		return false, nil
	}
	l.log("candidate")

	if err := l.cfg.Clock.Sleep(ctx, l.cfg.Rand.Duration(l.p.PauseMin, l.p.PauseMax)); err != nil {
		l.abandon(h, "interrupted")
		return false, err
	}

	// re-read by REOPENING the file: we are master only if the lock still carries our id
	raw, err = l.cfg.FS.ReadFile(l.path)
	if err != nil {
		_ = h.Close()
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("re-read lock: %w", err)
	}
	if c, ok := parseContent(raw); !ok || c.InstanceID != l.id {
		_ = h.Close() // never touch the file of another instance
		l.log("lost the candidacy", "owner_instance_id", c.InstanceID)
		return false, nil
	}

	if l.cfg.Hooks.BeforePromote != nil {
		l.cfg.Hooks.BeforePromote()
	}
	// promotion: fchmod on OUR descriptor, then the path must still designate OUR inode
	if err := h.Chmod(ModeMaster); err != nil {
		l.abandon(h, "fchmod failed")
		return false, fmt.Errorf("fchmod: %w", err)
	}
	mine, err := h.ID()
	if err != nil {
		_ = h.Close()
		return false, fmt.Errorf("fstat: %w", err)
	}
	onPath, err := l.cfg.FS.StatPath(l.path)
	if err != nil || onPath != mine {
		_ = h.Close() // the path is another file now: leave it alone
		l.warn("promotion aborted: the lock path no longer designates our file")
		return false, nil
	}
	start = l.cfg.Clock.Now()
	l.beat = 1
	if err := h.Rewrite(encodeContent(content{InstanceID: l.id, Role: RoleMaster, Beat: l.beat, Host: l.cfg.Host})); err != nil {
		l.abandon(h, "first beat failed")
		return false, fmt.Errorf("first beat: %w", err)
	}
	if took := l.cfg.Clock.Now().Sub(start); took > l.p.MaxWriteLatency {
		l.abandon(h, fmt.Sprintf("first beat took %v (> %v)", took, l.p.MaxWriteLatency))
		return false, nil
	}
	// verify through the path (reopened) that the master content is what is published: with a
	// reused inode number the check above could not tell a replaced file from ours
	raw, err = l.cfg.FS.ReadFile(l.path)
	if c, ok := parseContent(raw); err != nil || !ok || c.InstanceID != l.id || c.Role != RoleMaster {
		_ = h.Close() // not ours (any more): leave the file alone
		l.warn("promotion aborted: the published lock is not ours")
		return false, nil
	}
	l.mu.Lock()
	l.h, l.master, l.lastBeatOK = h, true, l.cfg.Clock.Now()
	l.mu.Unlock()
	l.log("promoted to master")
	return true, nil
}

// abandon gives up a candidacy: it removes the file only if the path still is OUR file.
func (l *Lock) abandon(h Handle, why string) {
	l.warn("candidacy abandoned", "reason", why)
	if mine, err := h.ID(); err == nil {
		if onPath, err := l.cfg.FS.StatPath(l.path); err == nil && onPath == mine {
			_ = l.cfg.FS.Remove(l.path)
		}
	}
	_ = h.Close()
}

// ── master ───────────────────────────────────────────────────────────────────

// CheckOwnership is the write guard: it re-reads the lock (reopening it) and refuses when the
// instance_id or the inode is not ours, or when no heartbeat succeeded for the self-retire delay.
// It must be called before EVERY state write (it is the BeforeWrite hook of the state engine).
// A failed identity check is final: the instance is no longer the master.
func (l *Lock) CheckOwnership() error {
	l.mu.Lock()
	if l.lost {
		err := l.lostErr
		l.mu.Unlock()
		return err
	}
	if !l.master || l.h == nil {
		l.mu.Unlock()
		return ErrNotMaster
	}
	h, lastOK := l.h, l.lastBeatOK
	l.mu.Unlock()

	if age := l.cfg.Clock.Now().Sub(lastOK); age >= l.p.SelfRetire {
		return l.lose(fmt.Errorf("lock: self-retire: no successful heartbeat for %v", age.Round(time.Second)))
	}
	// Order matters: the inode is compared FIRST and the content is read LAST. Inode numbers are
	// reused after a deletion (ext4, tmpfs, NFS), so a frozen master could pass an inode check
	// made after another instance replaced its file; the content (our instance_id, written only
	// by us on our own inode) read last is the linearization point of the guard.
	mine, err := h.ID()
	if err != nil {
		return fmt.Errorf("lock: cannot confirm ownership (write refused): %w", err)
	}
	onPath, err := l.cfg.FS.StatPath(l.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return l.lose(errors.New("lock: the lock file is gone"))
		}
		return fmt.Errorf("lock: cannot confirm ownership (write refused): %w", err)
	}
	if onPath != mine {
		return l.lose(errors.New("lock: the lock path designates another file"))
	}
	raw, err := l.cfg.FS.ReadFile(l.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return l.lose(errors.New("lock: the lock file is gone"))
		}
		return fmt.Errorf("lock: cannot confirm ownership (write refused): %w", err) // fail closed, not final
	}
	c, ok := parseContent(raw)
	if !ok || c.InstanceID != l.id || c.Role != RoleMaster {
		return l.lose(fmt.Errorf("lock: the lock now belongs to instance %q", c.InstanceID))
	}
	return nil
}

// lose records the loss (once), closes the descriptor WITHOUT touching the file, and notifies.
func (l *Lock) lose(err error) error {
	l.mu.Lock()
	if l.lost {
		e := l.lostErr
		l.mu.Unlock()
		return e
	}
	l.lost, l.lostErr, l.master = true, err, false
	h := l.h
	l.h = nil
	cb := l.cfg.OnLost
	l.mu.Unlock()
	if h != nil {
		_ = h.Close()
	}
	l.warn("lock lost", "reason", err)
	if cb != nil {
		cb(err)
	}
	return err
}

// doBeat increments the counter in place (write + fsync).
func (l *Lock) doBeat() error {
	l.mu.Lock()
	if !l.master || l.h == nil || l.lost {
		l.mu.Unlock()
		return ErrNotMaster
	}
	h := l.h
	l.beat++
	c := content{InstanceID: l.id, Role: RoleMaster, Beat: l.beat, Host: l.cfg.Host}
	l.mu.Unlock()
	if err := h.Rewrite(encodeContent(c)); err != nil {
		return err
	}
	l.mu.Lock()
	l.lastBeatOK = l.cfg.Clock.Now()
	l.mu.Unlock()
	return nil
}

// Maintain runs the heartbeat and the identity check until ctx ends or the lock is lost (then
// OnLost has been called and Maintain returns the cause). The heartbeat and the check run on
// separate goroutines so that a blocked write (storage lost) can not prevent the self-retire.
func (l *Lock) Maintain(ctx context.Context) error {
	if !l.IsMaster() {
		return ErrNotMaster
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	l.cfg.Spawn(func() { // heartbeat
		for {
			if err := l.cfg.Clock.Sleep(ctx, l.p.Beat); err != nil {
				return
			}
			if err := l.doBeat(); err != nil {
				if errors.Is(err, ErrNotMaster) {
					return
				}
				l.warn("heartbeat failed", "error", err)
			}
		}
	})
	var lostErr error
	for {
		if err := l.cfg.Clock.Sleep(ctx, l.p.Check); err != nil {
			break
		}
		if err := l.CheckOwnership(); err != nil {
			l.mu.Lock()
			final := l.lost
			l.mu.Unlock()
			if final {
				lostErr = err
				break
			}
			l.warn("ownership check inconclusive", "error", err)
		}
	}
	// The heartbeat is NOT waited for: it may be stuck in a write on a lost mount, and the loss
	// must be reported anyway. It ends by itself (ctx canceled, or its write returned).
	cancel()
	return lostErr
}

// Release is the clean shutdown: when the lock is still ours it is deleted (an immediate takeover
// by a secondary); the descriptor is always closed. It never removes the file of another instance.
func (l *Lock) Release() error {
	l.mu.Lock()
	h, master, lost := l.h, l.master, l.lost
	l.h, l.master = nil, false
	l.mu.Unlock()
	if h == nil {
		return nil
	}
	defer func() { _ = h.Close() }()
	if !master || lost {
		return nil
	}
	mine, err := h.ID()
	if err != nil {
		return fmt.Errorf("lock: release: %w", err)
	}
	if onPath, err := l.cfg.FS.StatPath(l.path); err != nil || onPath != mine {
		return nil // gone, or another file: not ours to delete
	}
	raw, err := l.cfg.FS.ReadFile(l.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("lock: release: %w", err)
	}
	if c, ok := parseContent(raw); !ok || c.InstanceID != l.id {
		l.warn("release: the lock is not ours any more, left untouched", "owner_instance_id", c.InstanceID)
		return nil
	}
	if err := l.cfg.FS.Remove(l.path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("lock: release: %w", err)
	}
	l.log("released")
	return nil
}
