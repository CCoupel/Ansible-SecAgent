package lock

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// ProbeState is what an observer (an operator command, not a candidate) learns about relay.lock.
type ProbeState int

const (
	// ProbeAbsent: there is no relay.lock.
	ProbeAbsent ProbeState = iota
	// ProbeActive: the content changed while observed (an instance is alive), or the observation
	// could not conclude (context ended before the staleness limit): treated as held.
	ProbeActive
	// ProbeStale: the content did not change for the staleness limit of its role, observed on the
	// local monotonic clock: nobody maintains it (same rule as the secondaries of the protocol).
	ProbeStale
)

// ProbeInfo describes the observed lock (no secret: ids and counters).
type ProbeInfo struct {
	InstanceID string
	Role       string
	Beat       uint64
	Waited     time.Duration
}

// Probe observes relay.lock in dir WITHOUT ever writing or removing anything and without taking the
// lock: it reads it (reopened each time), and judges freshness exactly like a secondary does: the
// lock is stale when its content stayed identical for p.CandidateStale (candidate, or unreadable
// content) or p.MasterStale (master), measured on clock; any change means a live instance. It polls
// every p.Check and returns as soon as it can conclude. ctx bounds the observation: when it ends
// first, the answer is ProbeActive (fail closed).
func Probe(ctx context.Context, fs FS, clock Clock, dir string, p Params) (ProbeState, ProbeInfo, error) {
	if fs == nil {
		fs = OSFS{}
	}
	if clock == nil {
		clock = RealClock{}
	}
	if p == (Params{}) {
		p = DefaultParams()
	}
	path := filepath.Join(dir, FileName)
	first, err := fs.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return ProbeAbsent, ProbeInfo{}, nil
	}
	if err != nil {
		return ProbeActive, ProbeInfo{}, fmt.Errorf("lock probe: cannot read %s: %w", path, err)
	}
	start := clock.Now()
	info := func(raw []byte) ProbeInfo {
		c, _ := parseContent(raw)
		return ProbeInfo{InstanceID: c.InstanceID, Role: c.Role, Beat: c.Beat, Waited: clock.Now().Sub(start)}
	}
	limit := func(raw []byte) time.Duration {
		if c, ok := parseContent(raw); ok && c.Role == RoleMaster {
			return p.MasterStale
		}
		return p.CandidateStale
	}
	last := string(first)
	for {
		if err := clock.Sleep(ctx, p.Check); err != nil {
			return ProbeActive, info([]byte(last)), nil // undecided: held
		}
		raw, err := fs.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) {
			return ProbeAbsent, info([]byte(last)), nil // released while we watched
		}
		if err != nil {
			return ProbeActive, info([]byte(last)), fmt.Errorf("lock probe: cannot read %s: %w", path, err)
		}
		if string(raw) != last {
			return ProbeActive, info(raw), nil
		}
		if clock.Now().Sub(start) >= limit(raw) {
			return ProbeStale, info(raw), nil
		}
	}
}
