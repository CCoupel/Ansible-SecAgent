package lock

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func probeParams() Params {
	return Params{Check: 5 * time.Millisecond, CandidateStale: 40 * time.Millisecond, MasterStale: 120 * time.Millisecond}
}

func writeLock(t *testing.T, dir string, c content) string {
	t.Helper()
	path := filepath.Join(dir, FileName)
	if err := os.WriteFile(path, encodeContent(c), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestProbe_AbsentLock(t *testing.T) {
	st, _, err := Probe(context.Background(), nil, nil, t.TempDir(), probeParams())
	if err != nil || st != ProbeAbsent {
		t.Fatalf("%v %v", st, err)
	}
}

func TestProbe_UnchangedMasterLockIsStaleOnlyAfterTheMasterLimit(t *testing.T) {
	dir := t.TempDir()
	writeLock(t, dir, content{InstanceID: "dead", Role: RoleMaster, Beat: 7})
	start := time.Now()
	st, info, err := Probe(context.Background(), nil, nil, dir, probeParams())
	if err != nil || st != ProbeStale {
		t.Fatalf("%v %v", st, err)
	}
	if el := time.Since(start); el < 120*time.Millisecond {
		t.Errorf("a master lock is stale only after MasterStale, concluded after %v", el)
	}
	if info.Role != RoleMaster || info.Beat != 7 || info.InstanceID != "dead" {
		t.Errorf("info %+v", info)
	}
}

func TestProbe_CandidateLockUsesTheShortLimit(t *testing.T) {
	dir := t.TempDir()
	writeLock(t, dir, content{InstanceID: "c", Role: RoleCandidate})
	clock := &stepClock{now: time.Unix(1000, 0)}
	st, info, _ := Probe(context.Background(), nil, clock, dir, probeParams())
	// virtual time: concluded after exactly CandidateStale (40 ms, polled every 5 ms), never after the master limit
	if st != ProbeStale || info.Waited < 40*time.Millisecond || info.Waited > 45*time.Millisecond {
		t.Fatalf("candidate: %v after %v (virtual), want stale after the 40 ms candidate limit", st, info.Waited)
	}
}

// stepClock is a virtual clock: Sleep advances the time instantly and then runs onSleep(n), n = the
// number of sleeps so far — the "other instance" of a test acts at a precise poll of the probe, never
// at a wall-clock instant a loaded machine could stretch.
type stepClock struct {
	now     time.Time
	n       int
	onSleep func(n int)
}

func (c *stepClock) Now() time.Time { return c.now }

func (c *stepClock) Sleep(ctx context.Context, d time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.n++
	c.now = c.now.Add(d)
	if c.onSleep != nil {
		c.onSleep(c.n)
	}
	return nil
}

// A lock whose content changes is a live instance, whatever the beat period relative to the limit:
// the probe polls every 5 ms and judges a master stale after 120 ms (24 polls) without any change.
// The change happens at an exact poll of a virtual clock (the former version used a goroutine writing
// every 20 ms of real time: a stalled goroutine on a loaded machine let the 120 ms elapse -> stale).
func TestProbe_AChangingLockIsActive(t *testing.T) {
	for _, tc := range []struct {
		name     string
		changeAt int // poll number at which the other instance rewrites the lock
		want     ProbeState
	}{
		{"beat after 20 ms", 4, ProbeActive},
		{"beat at the very last poll before the limit", 23, ProbeActive},
		{"beat during the poll that reaches the limit", 24, ProbeActive}, // the content is compared BEFORE the limit
		{"beat only after the limit was reached", 25, ProbeStale},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := writeLock(t, dir, content{InstanceID: "alive", Role: RoleMaster, Beat: 1})
			clock := &stepClock{now: time.Unix(1000, 0)}
			clock.onSleep = func(n int) {
				if n == tc.changeAt {
					if err := os.WriteFile(path, encodeContent(content{InstanceID: "alive", Role: RoleMaster, Beat: 2}), 0o700); err != nil {
						t.Error(err)
					}
				}
			}
			st, info, err := Probe(context.Background(), nil, clock, dir, probeParams())
			if err != nil || st != tc.want || info.InstanceID != "alive" {
				t.Fatalf("%v %+v %v, want %v", st, info, err, tc.want)
			}
		})
	}
}

func TestProbe_UndecidedIsActiveAndNothingIsWritten(t *testing.T) {
	dir := t.TempDir()
	path := writeLock(t, dir, content{InstanceID: "x", Role: RoleMaster})
	before, _ := os.ReadFile(path)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	st, _, _ := Probe(ctx, nil, nil, dir, probeParams())
	if st != ProbeActive {
		t.Fatalf("an observation cut short must fail closed (active), got %v", st)
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Error("the probe modified the lock")
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 1 {
		t.Errorf("the probe created files: %v", ents)
	}
}

func TestProbe_ReleasedWhileWatching(t *testing.T) {
	dir := t.TempDir()
	path := writeLock(t, dir, content{InstanceID: "x", Role: RoleMaster})
	go func() { time.Sleep(25 * time.Millisecond); _ = os.Remove(path) }()
	st, _, _ := Probe(context.Background(), nil, nil, dir, probeParams())
	if st != ProbeAbsent {
		t.Fatalf("got %v", st)
	}
}
