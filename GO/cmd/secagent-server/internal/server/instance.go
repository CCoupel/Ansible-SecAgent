package server

// Active/passive life cycle of one secagent-server process (#163, epic #157):
//
//	validate the configuration and the TLS certificates → lock loop (secondary: NO port, no state,
//	no link, no hook, nothing written in STATE_DIR but the lock itself) → promoted: heartbeat and
//	identity checks start, the state is loaded (a replay is refused), the node is built, the ports
//	open → serve → exit.
//
// Exits:
//   - SIGTERM / SIGINT: graceful stop (ports, hooks drained), then the lock is deleted so that a
//     secondary takes over at once;
//   - loss of the lock: Node.Abort (listeners and WebSockets closed with 1001, hooks NOT drained,
//     no state write) and the process exits with ExitLockLost; the restart policy of the container
//     relaunches it as a secondary. There is no demotion in memory: no residual state;
//   - start failure (state invalid, certificate, replay): the lock we hold is deleted and the exit
//     code is non-zero.

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"secagent-server/cmd/secagent-server/internal/localstatus"
	"secagent-server/cmd/secagent-server/internal/lock"
	"secagent-server/cmd/secagent-server/internal/state"
)

// Process exit codes.
const (
	ExitOK       = 0
	ExitFailure  = 1  // start refused (configuration, state, certificate, replay) or server error
	ExitLockLost = 75 // the master lock was lost (EX_TEMPFAIL): restart as a secondary
)

// runningNode is the node built by RunInstance once this process is the master (nil while waiting).
var runningNode atomic.Pointer[Node]

// ReloadHooksOfCurrentNode is the SIGHUP handler of main: it reloads the hooks of the running node;
// while the process is a secondary (no node) it only logs.
func ReloadHooksOfCurrentNode() {
	if n := runningNode.Load(); n != nil {
		n.ReloadHooks()
		return
	}
	log.Println("[HOOKS] SIGHUP received while waiting for the lock: nothing to reload")
}

// statusKeeper maintains the local status file from the lock's own observations. One mutex covers
// the read of the state AND the write of the file: a periodic refresh can never overwrite a later
// "failed" / "lost" with an older "ready".
type statusKeeper struct {
	path string
	lk   *lock.Lock

	mu     sync.Mutex
	state  string
	detail string
	mode   func() (mode string, seq uint64) // set once the node exists
	warned time.Time

	stop context.CancelFunc
	done chan struct{}
}

func (k *statusKeeper) set(state, detail string) {
	k.mu.Lock()
	k.state, k.detail = state, detail
	k.writeLocked()
	k.mu.Unlock()
}

func (k *statusKeeper) setMode(fn func() (string, uint64)) {
	k.mu.Lock()
	k.mode = fn
	k.mu.Unlock()
}

func (k *statusKeeper) write() {
	k.mu.Lock()
	k.writeLocked()
	k.mu.Unlock()
}

func (k *statusKeeper) writeLocked() {
	st := k.lk.Status()
	f := localstatus.File{
		Role: st.Phase, InstanceID: st.InstanceID, State: k.state, Detail: k.detail, Beat: st.Beat,
		BeatPeriodMS: st.Params.Beat.Milliseconds(), CheckPeriodMS: st.Params.Check.Milliseconds(),
		StateMode: localstatus.ModeReadOnly,
	}
	if k.mode != nil && k.state == localstatus.StateReady {
		f.StateMode, f.WriteSeq = k.mode()
	}
	if !st.LastBeatOK.IsZero() {
		f.LastBeatAt = st.LastBeatOK.UnixMilli()
	}
	if !st.LastCheck.IsZero() {
		f.LastCheckAt = st.LastCheck.UnixMilli()
	}
	if err := localstatus.Write(k.path, f); err != nil && time.Since(k.warned) > time.Minute {
		k.warned = time.Now()
		log.Printf("[WARN] cannot write the local status file %s: %v (`status --local` will report this process unhealthy)", k.path, err)
	}
}

// start refreshes the file until close.
func (k *statusKeeper) start(ctx context.Context, every time.Duration) {
	ctx, k.stop = context.WithCancel(ctx)
	k.done = make(chan struct{})
	k.write()
	go func() {
		defer close(k.done)
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				k.write()
			}
		}
	}()
}

// close stops the refresh and WAITS for it: nothing writes the file after close returns.
func (k *statusKeeper) close() {
	if k.stop != nil {
		k.stop()
		<-k.done
	}
}

// RunInstance runs one secagent-server process through its whole active/passive life and returns
// the process exit code (and the error that explains a non-zero one).
func RunInstance(ctx context.Context, cfg Config) (int, error) {
	// 1. configuration and certificates, BEFORE the lock loop and any port
	cfg.StateDir = stateDirOf(cfg)
	if err := validateTLSConfig(cfg); err != nil {
		return ExitFailure, err
	}
	if cfg.TLSCert != "" {
		cs, err := newCertStore(cfg.TLSCert, cfg.TLSKey, cfg.tlsNow)
		if err != nil {
			return ExitFailure, err
		}
		cfg.certs = cs
	}

	// 2. the lock
	lostCh := make(chan error, 1)
	lk, err := lock.New(lock.Config{
		Dir: cfg.StateDir, Params: cfg.LockParams, Hooks: cfg.LockHooks,
		OnLost: func(err error) { // never blocks: it can run inside a state write
			select {
			case lostCh <- err:
			default:
			}
		},
	})
	if err != nil {
		return ExitFailure, err
	}
	var keeper *statusKeeper
	cleanExit := false
	if cfg.StatusFile != "" {
		keeper = &statusKeeper{path: cfg.StatusFile, lk: lk, state: localstatus.StateWaiting}
		every := lk.Status().Params.Check / 2
		if every < 50*time.Millisecond {
			every = 50 * time.Millisecond
		}
		keeper.start(ctx, every)
		// On a clean exit the file is removed (no stale "healthy"), after the refresh has stopped;
		// after a failure or a loss it stays, so that `status --local` reports failed / lost.
		defer func() {
			keeper.close()
			if cleanExit {
				_ = os.Remove(cfg.StatusFile)
			}
		}()
	}
	setState := func(s, detail string) {
		if keeper != nil {
			keeper.set(s, detail)
		}
	}

	// 3. secondary: wait for the lock. No port, no state, nothing started.
	log.Printf("[INIT] waiting for the master lock (instance_id=%s, STATE_DIR=%s)", lk.InstanceID(), cfg.StateDir)
	if err := lk.Acquire(ctx); err != nil {
		if ctx.Err() != nil {
			cleanExit = true
			return ExitOK, nil // asked to stop while waiting
		}
		setState(localstatus.StateFailed, "lock loop failed")
		return ExitFailure, fmt.Errorf("lock: %w", err)
	}
	log.Printf("[INIT] promoted to master (instance_id=%s)", lk.InstanceID())
	setState(localstatus.StateLoading, "")

	mctx, stopMaintain := context.WithCancel(ctx)
	defer stopMaintain()
	go func() { _ = lk.Maintain(mctx) }() // heartbeat and identity checks until the end

	lostNow := func() (error, bool) {
		select {
		case lerr := <-lostCh:
			return lerr, true
		default:
			return nil, false
		}
	}
	// lost: the lock is gone. Whatever the process was doing, this is exit 75 (restart as secondary).
	lost := func(lerr error) (int, error) {
		setState(localstatus.StateLost, shortReason(lerr))
		log.Printf("[SECURITY WARNING] the master lock was lost (%v): exiting with code %d, the restart policy relaunches this instance as a secondary", lerr, ExitLockLost)
		return ExitLockLost, fmt.Errorf("%w: %v", ErrLockLost, lerr)
	}
	fail := func(err error) (int, error) {
		if lerr, isLost := lostNow(); isLost { // a start that failed BECAUSE the lock was lost
			return lost(lerr)
		}
		setState(localstatus.StateFailed, shortReason(err))
		if rerr := lk.Release(); rerr != nil {
			log.Printf("[WARN] releasing the lock after a failed start: %v", rerr)
		}
		return ExitFailure, err
	}

	// 4. state load (inside Build), guarded by the lock; the ports open only in Run
	cfg.WriteGuard = lk.CheckOwnership
	cfg.minWriteSeq = lk.MinSeq()
	cfg.onStateWrite = lk.NoteSeq
	node, err := Build(cfg)
	if err != nil {
		return fail(err)
	}
	node.SetInstance(lock.PhaseMaster, lk.InstanceID())
	node.SetLockStatus(lk.Status)
	if keeper != nil {
		keeper.setMode(func() (string, uint64) { m, _ := node.StateMode(); return m, node.store.WriteSeq() })
	}
	runningNode.Store(node)
	defer runningNode.Store(nil)

	// From here ANY loss of the lock aborts the node at once, in whatever phase it is (serving, or
	// in the graceful shutdown: no hook may run on behalf of a former master).
	var lostErr atomic.Pointer[error]
	watchDone := make(chan struct{})
	defer close(watchDone)
	go func() {
		select {
		case lerr := <-lostCh:
			lostErr.Store(&lerr)
			node.Abort()
		case <-watchDone:
		}
	}()
	if lerr := lostErr.Load(); lerr != nil {
		node.Close()
		return lost(*lerr)
	}

	// cleanStop: the ports are closed and the store is closed (Run's deferred Close): delete the lock
	// now so that a secondary takes over immediately
	cleanStop := func() (int, error) {
		stopMaintain()
		if err := lk.Release(); err != nil {
			log.Printf("[WARN] releasing the lock: %v", err)
		}
		cleanExit = true
		return ExitOK, nil
	}

	// 5. serve
	runDone := make(chan error, 1)
	go func() { runDone <- node.Run(ctx) }()
	select {
	case <-node.Ready():
		setState(localstatus.StateReady, "")
		if cfg.OnReady != nil {
			cfg.OnReady(node)
		}
	case rerr := <-runDone: // Run ended before serving: a port conflict, a stop request, or the loss
		return finish(rerr, ctx, lostErr.Load, lost, fail, cleanStop)
	}
	return finish(<-runDone, ctx, lostErr.Load, lost, fail, cleanStop)
}

// finish maps the end of Run to the process outcome: a recorded loss wins over everything.
func finish(rerr error, ctx context.Context, lostErr func() *error, lost func(error) (int, error),
	fail func(error) (int, error), cleanStop func() (int, error)) (int, error) {
	if lerr := lostErr(); lerr != nil || errors.Is(rerr, ErrLockLost) {
		var e error = ErrLockLost
		if lerr != nil {
			e = *lerr
		}
		return lost(e)
	}
	if rerr != nil {
		return fail(rerr)
	}
	if ctx.Err() == nil {
		return fail(errors.New("the server stopped unexpectedly"))
	}
	return cleanStop()
}

// stateDirOf resolves STATE_DIR.
func stateDirOf(cfg Config) string {
	if cfg.StateDir != "" {
		return cfg.StateDir
	}
	return state.DefaultStateDir
}

// shortReason keeps the status detail on one short line, without anything but the error text.
func shortReason(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}
