package lock

import (
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
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
	start := time.Now()
	st, _, _ := Probe(context.Background(), nil, nil, dir, probeParams())
	if st != ProbeStale || time.Since(start) > 110*time.Millisecond {
		t.Fatalf("candidate: %v after %v", st, time.Since(start))
	}
}

func TestProbe_AChangingLockIsActive(t *testing.T) {
	dir := t.TempDir()
	path := writeLock(t, dir, content{InstanceID: "alive", Role: RoleMaster, Beat: 1})
	var beat atomic.Uint64
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		for {
			select {
			case <-stop:
				return
			case <-time.After(20 * time.Millisecond):
				_ = os.WriteFile(path, encodeContent(content{InstanceID: "alive", Role: RoleMaster, Beat: 2 + beat.Add(1)}), 0o700)
			}
		}
	}()
	st, info, err := Probe(context.Background(), nil, nil, dir, probeParams())
	if err != nil || st != ProbeActive || info.InstanceID != "alive" {
		t.Fatalf("%v %+v %v", st, info, err)
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
