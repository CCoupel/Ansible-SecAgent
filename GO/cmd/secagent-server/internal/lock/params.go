package lock

import (
	"errors"
	"fmt"
	"time"
)

// FileName is the single lock file, next to relay.state in STATE_DIR.
const FileName = "relay.lock"

// Roles written in the lock content (the content, not the file mode, is authoritative).
const (
	RoleCandidate = "candidate"
	RoleMaster    = "master"
)

// File modes: only a hint for an operator looking at the directory (0755 candidate, 0700
// master). The logic NEVER reads them: a mount that ignores modes must not change anything.
const (
	ModeCandidate = 0o755
	ModeMaster    = 0o700
)

// Params are the timings of the protocol. They are named constants (DefaultParams) and are only
// overridden by tests: there is no operator variable, so a too aggressive setting can not be
// deployed by mistake.
type Params struct {
	// Beat: the master increments its counter this often (write in place + fsync).
	Beat time.Duration
	// Check: the master verifies its identity this often; a secondary polls at this pace.
	Check time.Duration
	// SelfRetire: the master gives the lock up when no heartbeat succeeded for this long.
	SelfRetire time.Duration
	// MasterStale: a master whose counter did not change for this long (observed on the local
	// monotonic clock) is considered dead.
	MasterStale time.Duration
	// CandidateStale: a candidate lock whose content did not change for this long is abandoned.
	CandidateStale time.Duration
	// PauseMin/PauseMax: random pause between the creation of the lock and the re-read.
	PauseMin, PauseMax time.Duration
	// MaxWriteLatency: a creation or a write slower than this aborts the candidacy.
	MaxWriteLatency time.Duration
}

// DefaultParams are the production values (decision #158 Q3, variant A).
func DefaultParams() Params {
	return Params{
		Beat:            30 * time.Second,
		Check:           5 * time.Second,
		SelfRetire:      3 * time.Minute,
		MasterStale:     5 * time.Minute,
		CandidateStale:  10 * time.Second,
		PauseMin:        1 * time.Second,
		PauseMax:        2 * time.Second,
		MaxWriteLatency: 500 * time.Millisecond,
	}
}

// Validate checks the calibration invariants; the server refuses to start when they are violated:
//
//	check < beat < self-retire < master stale
//	max write latency < pause min
//	pause max < candidate stale
func (p Params) Validate() error {
	for name, d := range map[string]time.Duration{
		"Beat": p.Beat, "Check": p.Check, "SelfRetire": p.SelfRetire, "MasterStale": p.MasterStale,
		"CandidateStale": p.CandidateStale, "PauseMin": p.PauseMin, "PauseMax": p.PauseMax, "MaxWriteLatency": p.MaxWriteLatency,
	} {
		if d <= 0 {
			return fmt.Errorf("lock: %s must be positive", name)
		}
	}
	var errs []error
	if p.Check >= p.Beat || p.Beat >= p.SelfRetire || p.SelfRetire >= p.MasterStale {
		errs = append(errs, fmt.Errorf("lock: need check (%v) < beat (%v) < self-retire (%v) < master stale (%v)", p.Check, p.Beat, p.SelfRetire, p.MasterStale))
	}
	if p.MaxWriteLatency >= p.PauseMin {
		errs = append(errs, fmt.Errorf("lock: max write latency (%v) must be below the minimum pause (%v)", p.MaxWriteLatency, p.PauseMin))
	}
	if p.PauseMin > p.PauseMax || p.PauseMax >= p.CandidateStale {
		errs = append(errs, fmt.Errorf("lock: need pause min (%v) <= pause max (%v) < candidate stale (%v)", p.PauseMin, p.PauseMax, p.CandidateStale))
	}
	return errors.Join(errs...)
}
