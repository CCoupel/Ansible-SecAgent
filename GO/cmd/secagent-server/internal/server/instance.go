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

// statusKeeper maintains the local status file from the lock's own observations.
type statusKeeper struct {
	path string
	lk   *lock.Lock

	mu     sync.Mutex
	state  string
	detail string
	warned time.Time
}

func (k *statusKeeper) set(state, detail string) {
	k.mu.Lock()
	k.state, k.detail = state, detail
	k.mu.Unlock()
	k.write()
}

func (k *statusKeeper) write() {
	st := k.lk.Status()
	k.mu.Lock()
	state, detail := k.state, k.detail
	k.mu.Unlock()
	f := localstatus.File{
		Role: st.Phase, InstanceID: st.InstanceID, State: state, Detail: detail, Beat: st.Beat,
		BeatPeriodMS: st.Params.Beat.Milliseconds(), CheckPeriodMS: st.Params.Check.Milliseconds(),
	}
	if !st.LastBeatOK.IsZero() {
		f.LastBeatAt = wall(st.LastBeatOK)
	}
	if !st.LastCheck.IsZero() {
		f.LastCheckAt = wall(st.LastCheck)
	}
	if err := localstatus.Write(k.path, f); err != nil {
		k.mu.Lock()
		due := time.Since(k.warned) > time.Minute
		if due {
			k.warned = time.Now()
		}
		k.mu.Unlock()
		if due {
			log.Printf("[WARN] cannot write the local status file %s: %v (`status --local` will report this process unhealthy)", k.path, err)
		}
	}
}

// wall converts a lock clock reading (monotonic-carrying) to unix milliseconds.
func wall(t time.Time) int64 { return t.UnixMilli() }

// run refreshes the file until ctx ends.
func (k *statusKeeper) run(ctx context.Context, every time.Duration) {
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
		p := lk.Status().Params
		every := p.Check / 2
		if every < 50*time.Millisecond {
			every = 50 * time.Millisecond
		}
		sctx, stopStatus := context.WithCancel(ctx)
		defer stopStatus()
		keeper.write()
		go keeper.run(sctx, every)
		// removed on a clean exit only (no stale "healthy"); kept after a failure or a loss so that
		// `status --local` reports the failed / lost state instead of "absent"
		defer func() {
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

	fail := func(err error) (int, error) {
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
	runningNode.Store(node)
	defer runningNode.Store(nil)

	select {
	case lerr := <-lostCh: // lost while loading
		node.Abort()
		node.Close()
		setState(localstatus.StateLost, shortReason(lerr))
		return ExitLockLost, fmt.Errorf("%w: %v", ErrLockLost, lerr)
	default:
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
	lost := func(lerr error) (int, error) {
		node.Abort()
		<-runDone
		setState(localstatus.StateLost, shortReason(lerr))
		log.Printf("[SECURITY WARNING] the master lock was lost (%v): exiting with code %d, the restart policy relaunches this instance as a secondary", lerr, ExitLockLost)
		return ExitLockLost, fmt.Errorf("%w: %v", ErrLockLost, lerr)
	}
	select {
	case <-node.Ready():
		setState(localstatus.StateReady, "")
		if cfg.OnReady != nil {
			cfg.OnReady(node)
		}
	case lerr := <-lostCh:
		return lost(lerr)
	case rerr := <-runDone: // Run ended before serving: a port conflict, or a stop request
		if rerr == nil && ctx.Err() != nil {
			return cleanStop()
		}
		if rerr == nil {
			rerr = errors.New("the server stopped before being ready")
		}
		return fail(rerr)
	}
	select {
	case lerr := <-lostCh:
		return lost(lerr)
	case rerr := <-runDone:
		select {
		case lerr := <-lostCh: // the loss raced with the stop
			setState(localstatus.StateLost, shortReason(lerr))
			return ExitLockLost, fmt.Errorf("%w: %v", ErrLockLost, lerr)
		default:
		}
		if rerr != nil && !errors.Is(rerr, ErrLockLost) {
			return fail(rerr)
		}
		return cleanStop()
	}
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
