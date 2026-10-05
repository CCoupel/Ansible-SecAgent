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
	// Seq is the write_seq of relay.state as last published by the master (#163, anti-replay):
	// every secondary remembers the highest value it ever read here, and a master that promotes
	// refuses a state older than it.
	Seq  uint64 `json:"write_seq,omitempty"`
	Host string `json:"host,omitempty"`
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
	// uncertainSince: since when the content could not be read COMPLETE (guard); zero = certain.
	uncertainSince time.Time

	// observation of the lock content by this secondary (monotonic local clock)
	obsRaw   string
	obsSince time.Time
	observed bool

	// minSeq is the highest write_seq ever read in a lock content (stale ones included, read just
	// before they are deleted); notedSeq the master's last state write_seq (NoteSeq) and
	// publishedSeq what the lock content carries.
	minSeq       uint64
	notedSeq     uint64
	publishedSeq uint64
	// wmu serializes the writes of the content (heartbeat and seq publication)
	wmu sync.Mutex
	// for Status
	lastCheck time.Time
	phase     string
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

// contentSize is the FIXED size of the lock content: it is rewritten in place by ONE write of the
// same length, never truncated, so that a reader never sees an empty or partial file produced by
// our own heartbeat (JSON tolerates the trailing spaces).
const contentSize = 256

func encodeContent(c content) []byte {
	if len(c.Host) > 64 {
		c.Host = c.Host[:64]
	}
	b, _ := json.Marshal(c)
	if len(b) > contentSize {
		c.Host = ""
		b, _ = json.Marshal(c)
	}
	out := make([]byte, contentSize)
	copy(out, b)
	for i := len(b); i < contentSize; i++ {
		out[i] = ' '
	}
	return out
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
		l.mu.Lock()
		if c.Seq > l.minSeq {
			l.minSeq = c.Seq
		}
		l.mu.Unlock()
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
	l.mu.Lock()
	l.phase = PhaseSecondary
	l.mu.Unlock()
	raw, err := l.cfg.FS.ReadFile(l.path)
	if err == nil || errors.Is(err, os.ErrNotExist) { // a SUCCESSFUL poll (free lock included)
		l.mu.Lock()
		l.lastCheck = l.cfg.Clock.Now()
		l.mu.Unlock()
	}
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
	l.mu.Lock()
	l.phase = PhaseCandidate
	l.mu.Unlock()
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
	l.mu.Lock()
	l.beat = 1
	first := content{InstanceID: l.id, Role: RoleMaster, Beat: l.beat, Seq: l.minSeq, Host: l.cfg.Host}
	l.mu.Unlock()
	if err := h.Rewrite(encodeContent(first)); err != nil {
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
	l.publishedSeq, l.phase = first.Seq, PhaseMaster
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
	return l.confirmContent()
}

// Short bounded re-reads of an unreadable content before the guard gives up for this call.
const (
	inconclusiveRetries = 3
	inconclusivePause   = 20 * time.Millisecond
)

// confirmContent reads the lock content (last step of the guard). A content that is missing,
// empty or partial is INCONCLUSIVE (another process, or a slow mount, may be in the middle of a
// write): the write is refused for this call but the lock is NOT lost, and the content is read
// again after a short pause. The lock is lost only when a COMPLETE content belongs to another
// instance, or when the uncertainty lasts longer than SelfRetire/2 (< self-retire).
func (l *Lock) confirmContent() error {
	var lastErr error
	for attempt := 0; attempt <= inconclusiveRetries; attempt++ {
		if attempt > 0 {
			_ = l.cfg.Clock.Sleep(context.Background(), inconclusivePause)
		}
		raw, err := l.cfg.FS.ReadFile(l.path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return l.lose(errors.New("lock: the lock file is gone"))
			}
			lastErr = err
			continue
		}
		c, ok := parseContent(raw)
		if !ok {
			lastErr = errors.New("content empty or partial")
			continue
		}
		if c.InstanceID != l.id || c.Role != RoleMaster {
			return l.lose(fmt.Errorf("lock: the lock now belongs to instance %q", c.InstanceID))
		}
		l.mu.Lock()
		l.uncertainSince = time.Time{}
		l.mu.Unlock()
		return nil
	}
	now := l.cfg.Clock.Now()
	l.mu.Lock()
	if l.uncertainSince.IsZero() {
		l.uncertainSince = now
	}
	for_ := now.Sub(l.uncertainSince)
	l.mu.Unlock()
	if for_ >= l.p.SelfRetire/2 {
		return l.lose(fmt.Errorf("lock: ownership could not be confirmed for %v (%v)", for_.Round(time.Second), lastErr))
	}
	return fmt.Errorf("lock: cannot confirm ownership (write refused, inconclusive read: %v)", lastErr)
}

// lose records the loss (once), closes the descriptor WITHOUT touching the file, and notifies.
func (l *Lock) lose(err error) error {
	l.mu.Lock()
	if l.lost {
		e := l.lostErr
		l.mu.Unlock()
		return e
	}
	l.lost, l.lostErr, l.master, l.phase = true, err, false, PhaseLost
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

// writeContent rewrites the lock content in place (write + fsync). With nextBeat the counter is
// incremented (the heartbeat); without, the current counter is kept (a seq publication). Either
// way a success proves the storage answers, so it counts as a successful beat for the self-retire.
func (l *Lock) writeContent(nextBeat bool) error {
	l.wmu.Lock()
	defer l.wmu.Unlock()
	l.mu.Lock()
	if !l.master || l.h == nil || l.lost {
		l.mu.Unlock()
		return ErrNotMaster
	}
	h := l.h
	if nextBeat {
		l.beat++
	}
	seq := l.notedSeq
	if l.minSeq > seq {
		seq = l.minSeq // never publish less than what this instance saw before it was master
	}
	c := content{InstanceID: l.id, Role: RoleMaster, Beat: l.beat, Seq: seq, Host: l.cfg.Host}
	l.mu.Unlock()
	if err := h.Rewrite(encodeContent(c)); err != nil {
		return err
	}
	l.mu.Lock()
	l.lastBeatOK = l.cfg.Clock.Now()
	l.publishedSeq = seq
	l.mu.Unlock()
	return nil
}

func (l *Lock) doBeat() error { return l.writeContent(true) }

// NoteSeq tells the lock the write_seq of the state file (called after every state write, and once
// after the state was loaded). The master publishes it in the lock content at its next check or
// beat (never lower than before). Safe for concurrent use; a no-op unless master.
func (l *Lock) NoteSeq(seq uint64) {
	l.mu.Lock()
	if seq > l.notedSeq {
		l.notedSeq = seq
	}
	l.mu.Unlock()
}

// MinSeq is the highest write_seq this instance ever read in the lock (the floor below which a
// state file is a replay). Valid at any time; read it once promoted, before loading the state.
func (l *Lock) MinSeq() uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.minSeq
}

// publishSeqIfNeeded writes the content when the noted write_seq is ahead of the published one.
func (l *Lock) publishSeqIfNeeded() {
	l.mu.Lock()
	need := l.master && !l.lost && l.notedSeq > l.publishedSeq
	l.mu.Unlock()
	if !need {
		return
	}
	if err := l.writeContent(false); err != nil && !errors.Is(err, ErrNotMaster) {
		l.warn("seq publication failed", "error", err)
	}
}

// Phases reported by Status.
const (
	PhaseSecondary = "secondary"
	PhaseCandidate = "candidate"
	PhaseMaster    = "master"
	PhaseLost      = "lost"
)

// Status is the observable state of the lock (the local status file, #163).
type Status struct {
	Phase      string
	InstanceID string
	Beat       uint64
	// LastBeatOK: last successful write of the master's content (zero before promotion).
	LastBeatOK time.Time
	// LastCheck: last secondary poll or master identity check (zero before the first one).
	LastCheck  time.Time
	LostReason string
	MinSeq     uint64
	Params     Params
}

// Status returns a consistent copy.
func (l *Lock) Status() Status {
	l.mu.Lock()
	defer l.mu.Unlock()
	phase := l.phase
	if phase == "" {
		phase = PhaseSecondary
	}
	st := Status{Phase: phase, InstanceID: l.id, Beat: l.beat, LastBeatOK: l.lastBeatOK, LastCheck: l.lastCheck, MinSeq: l.minSeq, Params: l.p}
	if l.lost && l.lostErr != nil {
		st.LostReason = l.lostErr.Error()
	}
	return st
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
	// The write_seq publication runs on its OWN goroutine: a write that blocks on a lost mount must
	// never keep the identity check (and so the self-retire) from running.
	l.cfg.Spawn(func() {
		for {
			if err := l.cfg.Clock.Sleep(ctx, l.p.Check); err != nil {
				return
			}
			l.publishSeqIfNeeded()
		}
	})
	var lostErr error
	for {
		if err := l.cfg.Clock.Sleep(ctx, l.p.Check); err != nil {
			break
		}
		err := l.CheckOwnership()
		if err == nil { // only a CONFIRMED identity check counts as fresh
			l.mu.Lock()
			l.lastCheck = l.cfg.Clock.Now()
			l.mu.Unlock()
		}
		if err != nil {
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
