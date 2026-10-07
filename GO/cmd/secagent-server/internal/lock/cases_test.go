package lock

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

// The seven limit cases of #162, on the production calibration, virtual time and an in-memory FS,
// each replayed with a FS that honors modes and a FS that ignores them (the instance_id inside
// the file is the only reference).

func plantDeadMaster(fs *memFS, beat uint64) {
	h, _ := fs.CreateExclusive(lockPath, ModeMaster)
	_ = h.Rewrite(encodeContent(content{InstanceID: "dead-master", Role: RoleMaster, Beat: beat, Host: "gone"}))
	fs.chmods = nil
}

func step(t *testing.T, in *inst) bool {
	t.Helper()
	ok, err := in.l.step(context.Background())
	if err != nil {
		t.Fatalf("%s step: %v", in.name, err)
	}
	return ok
}

func assertOwner(t *testing.T, fs *memFS, want string, wantRole string) {
	t.Helper()
	c, ok := fs.content(lockPath)
	if !ok || c.InstanceID != want || c.Role != wantRole {
		t.Fatalf("lock = %+v (present %v), want %s/%s", c, ok, want, wantRole)
	}
}

func assertModes(t *testing.T, fs *memFS, want os.FileMode) {
	t.Helper()
	if m, _ := fs.Mode(lockPath); fs.ignoreModes && m != 0o644 || !fs.ignoreModes && m != want {
		t.Errorf("mode %o (ignoreModes=%v), want %o", m, fs.ignoreModes, want)
	}
}

// Case 1: a single secondary, the master is dead.
func TestCase1_DeadMasterIsReplacedAfterTheStalenessDelay(t *testing.T) {
	forBothModes(t, func(t *testing.T, fs *memFS) {
		s := newSim()
		plantDeadMaster(fs, 41)
		sec := newInst(t, s, fs, "secondary", 1, true, nil)

		if step(t, sec) { // first observation: the age of the counter is unknown, so it is fresh
			t.Fatal("promoted on a lock it has just seen")
		}
		s.Advance(DefaultParams().MasterStale - 5*time.Second)
		if step(t, sec) {
			t.Fatal("promoted before the staleness delay")
		}
		assertOwner(t, fs, "dead-master", RoleMaster) // not deleted before ~5 min
		s.Advance(10 * time.Second)
		if !step(t, sec) {
			t.Fatal("must take over once the beat did not change for 5 minutes")
		}
		assertOwner(t, fs, "secondary-id", RoleMaster)
		assertModes(t, fs, ModeMaster)
		if !sec.l.IsMaster() || sec.l.CheckOwnership() != nil {
			t.Error("the new master must pass its own guard")
		}
	})
}

// A moving beat keeps a master alive however long we watch.
func TestBeatingMasterIsNeverTakenOver(t *testing.T) {
	forBothModes(t, func(t *testing.T, fs *memFS) {
		s := newSim()
		plantDeadMaster(fs, 1)
		sec := newInst(t, s, fs, "secondary", 1, true, nil)
		for i := uint64(2); i < 30; i++ {
			step(t, sec)
			s.Advance(60 * time.Second)
			plantBeat(fs, i)
		}
		if sec.l.IsMaster() {
			t.Fatal("a master whose beat moves must not be replaced")
		}
		assertOwner(t, fs, "dead-master", RoleMaster)
	})
}

func plantBeat(fs *memFS, beat uint64) {
	fs.mu.Lock()
	fs.files[lockPath].data = encodeContent(content{InstanceID: "dead-master", Role: RoleMaster, Beat: beat})
	fs.mu.Unlock()
}

// Case 2: two secondaries collide on a stale lock: exactly one gets the exclusive creation.
func TestCase2_TwoSecondariesCollideOnAStaleLock(t *testing.T) {
	forBothModes(t, func(t *testing.T, fs *memFS) {
		s := newSim()
		plantDeadMaster(fs, 3)
		var b *inst
		a := newInst(t, s, fs, "a", 1, true, func(c *Config) {
			c.Hooks.BeforeCreate = func() { // A removed the stale lock; B was just as fast
				if b != nil && !b.l.IsMaster() {
					step(t, b) // B creates first, pauses, re-reads its own id, promotes
				}
			}
		})
		b = newInst(t, s, fs, "b", 2, true, nil)
		step(t, a)
		step(t, b) // both have observed the lock
		s.Advance(DefaultParams().MasterStale + time.Second)

		if step(t, a) {
			t.Fatal("A lost the exclusive creation: it must not be promoted")
		}
		if !b.l.IsMaster() || a.l.IsMaster() {
			t.Fatalf("a master=%v b master=%v: exactly B must be master", a.l.IsMaster(), b.l.IsMaster())
		}
		assertOwner(t, fs, "b-id", RoleMaster)
		for _, c := range fs.chmods {
			if c.ino != lockInode(t, fs) {
				t.Errorf("fchmod on inode %d, which is not the live lock: A touched a file that is not its own", c.ino)
			}
		}
		if err := a.l.CheckOwnership(); err == nil {
			t.Error("the loser must not pass the guard")
		}
	})
}

func lockInode(t *testing.T, fs *memFS) uint64 {
	t.Helper()
	id, err := fs.StatPath(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	return id.Ino
}

// Case 3: a candidate frozen right after creating its lock: the lock is judged stale (10 s),
// replaced, and the candidate never becomes master nor touches the other's file.
func TestCase3_FrozenCandidateNeverBecomesMaster(t *testing.T) {
	forBothModes(t, func(t *testing.T, fs *memFS) {
		s := newSim()
		var b *inst
		a := newInst(t, s, fs, "a", 1, true, func(c *Config) {})
		// A freezes during its pause; meanwhile B watches A's candidate lock go stale and replaces it
		a.clk.onSleep = func(time.Duration) {
			step(t, b)                  // B observes A's fresh candidate
			s.Advance(11 * time.Second) // A is frozen for longer than the candidate staleness
			step(t, b)                  // B: stale → delete → create → pause → re-read → master
		}
		b = newInst(t, s, fs, "b", 2, true, nil)

		aInode := uint64(0)
		a.l.cfg.Hooks.BeforeCreate = func() { aInode = fs.next + 1 }
		if step(t, a) {
			t.Fatal("a frozen candidate must not become master")
		}
		if !b.l.IsMaster() {
			t.Fatal("B must be master")
		}
		assertOwner(t, fs, "b-id", RoleMaster)
		assertModes(t, fs, ModeMaster)
		for _, c := range fs.chmods {
			if c.ino == aInode {
				t.Errorf("A did fchmod on its own (replaced) inode %d: it must stop at the re-read", aInode)
			}
		}
		if a.l.IsMaster() || a.l.h != nil {
			t.Error("A kept a descriptor or a master flag")
		}
	})
}

// Case 4: frozen between the re-read (our id is there) and the promotion: the fchmod hits OUR
// descriptor, the inode check detects the path is another file now, the promotion is abandoned
// and the active lock is untouched.
func TestCase4_FreezeBetweenReadAndPromotionLeavesTheActiveLockAlone(t *testing.T) {
	forBothModes(t, func(t *testing.T, fs *memFS) {
		s := newSim()
		var b *inst
		a := newInst(t, s, fs, "a", 1, true, func(c *Config) {
			c.Hooks.BeforePromote = func() {
				step(t, b)
				s.Advance(11 * time.Second)
				step(t, b) // A's candidate lock is stale: B replaces it and becomes master
			}
		})
		b = newInst(t, s, fs, "b", 2, true, nil)
		if step(t, a) {
			t.Fatal("A must abandon the promotion")
		}
		if !b.l.IsMaster() || a.l.IsMaster() {
			t.Fatalf("a=%v b=%v", a.l.IsMaster(), b.l.IsMaster())
		}
		assertOwner(t, fs, "b-id", RoleMaster)
		assertModes(t, fs, ModeMaster)
		live := lockInode(t, fs)
		onLive, other := 0, 0
		for _, c := range fs.chmods {
			if c.ino == live {
				onLive++
			} else {
				other++
			}
		}
		// B's own promotion is the only fchmod the live lock received; A's went to ITS descriptor
		// (an inode that was deleted), whatever the path designates
		if onLive != 1 || other != 1 {
			t.Errorf("fchmod on the live lock: %d (want B's only), on A's replaced inode: %d (want 1): %+v", onLive, other, fs.chmods)
		}
		if b.l.CheckOwnership() != nil {
			t.Error("B must still own its lock")
		}
	})
}

// Case 5: a delayed deletion of a stale lock erases a FRESH lock. Accepted overlap, bounded:
// (a) no state write by the evicted instance, (b) one master after one check, (c) <= one check period.
func TestCase5_DelayedStaleDeletionErasesAFreshLock(t *testing.T) {
	forAllFS(t, func(t *testing.T, fs *memFS) {
		s := newSim()
		plantDeadMaster(fs, 9)
		eng := &engine{}
		ctxB, cancelB := context.WithCancel(context.Background())
		defer cancelB()
		var a, b *inst
		a = newInst(t, s, fs, "a", 1, true, func(c *Config) {
			c.Hooks.BeforeRemove = func() { // A judged the lock stale, then got frozen before unlink
				step(t, b) // B, equally sure it is stale, removes it and becomes master
				if !b.l.IsMaster() {
					t.Error("setup: B should be master")
				}
				eng.write(b, s) // B writes normally
				b.clk.immediate = false
				s.Go(func() { _ = b.l.Maintain(ctxB) }) // B's own identity check, every Check period
			}
		})
		b = newInst(t, s, fs, "b", 2, true, nil)
		step(t, a)
		step(t, b)
		s.Advance(DefaultParams().MasterStale + time.Second)

		if !step(t, a) { // A's delayed unlink erases B's fresh lock; A creates its own and promotes
			t.Fatal("setup: A should win the second round")
		}
		promotedAt := s.Now()
		// overlap: B still believes it is master. B's guard refuses (a): no write by the evicted one
		before := eng.count("b")
		if eng.write(b, s) {
			t.Fatal("(a) the evicted instance passed the write guard during the overlap")
		}
		if eng.count("b") != before {
			t.Fatal("(a) a state write happened during the overlap")
		}
		if !eng.write(a, s) {
			t.Fatal("the new master must be able to write")
		}
		// (b)+(c): B's maintenance loop checks every Check period; one cycle later only A is master
		s.Advance(DefaultParams().Check)
		if len(b.lost) != 1 {
			t.Fatalf("(b) B must lose the lock at its next check, OnLost called %d times", len(b.lost))
		}
		if overlap := b.lostT[0].Sub(promotedAt); overlap > DefaultParams().Check {
			t.Errorf("(c) overlap %v exceeds one check period %v", overlap, DefaultParams().Check)
		}
		if b.l.IsMaster() || !a.l.IsMaster() {
			t.Fatalf("(b) one master expected: a=%v b=%v", a.l.IsMaster(), b.l.IsMaster())
		}
		assertOwner(t, fs, "a-id", RoleMaster)
	})
}

// Case 6: the old master is frozen longer than the staleness, another instance took over; at
// wake-up its first check (or its write guard) detects it: loss, and no write.
func TestCase6_FrozenOldMasterWakesUpAfterATakeover(t *testing.T) {
	forAllFS(t, func(t *testing.T, fs *memFS) {
		s := newSim()
		eng := &engine{}
		old := newInst(t, s, fs, "old", 1, true, nil)
		neu := newInst(t, s, fs, "new", 2, true, nil)
		if !step(t, old) {
			t.Fatal("setup: old becomes master")
		}
		if !eng.write(old, s) {
			t.Fatal("setup")
		}
		step(t, neu)                                           // observes the master
		s.Advance(DefaultParams().MasterStale + 2*time.Second) // old is frozen: no beat
		if !step(t, neu) {
			t.Fatal("the secondary must take over a master that stopped beating")
		}
		eng.write(neu, s)
		before := eng.count("old")
		// the old master wakes up: its write guard refuses
		if eng.write(old, s) || eng.count("old") != before {
			t.Fatal("the awakened old master wrote")
		}
		if len(old.lost) != 1 || old.l.IsMaster() {
			t.Fatalf("loss not reported: lost=%d master=%v", len(old.lost), old.l.IsMaster())
		}
		if err := old.l.CheckOwnership(); err == nil {
			t.Error("a lost lock stays lost")
		}
		assertOwner(t, fs, "new-id", RoleMaster)
	})
}

// Case 7: the master loses its storage: heartbeats fail, it retires at 3 min, BEFORE the
// secondaries judge it dead (5 min), and a secondary then takes over.
func TestCase7_StorageLostSelfRetireBeforeStaleness(t *testing.T) {
	forAllFS(t, func(t *testing.T, fs *memFS) {
		s := newSim()
		m := newInst(t, s, fs, "m", 1, true, nil)
		sec := newInst(t, s, fs, "sec", 2, true, nil)
		if !step(t, m) {
			t.Fatal("setup")
		}
		start := s.Now()
		// the master's maintenance loop runs as an actor
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		m.clk.immediate = false // from now on its sleeps are scheduled by the simulation
		done := make(chan error, 1)
		s.Go(func() { done <- m.l.Maintain(ctx) })
		step(t, sec)         // the secondary watches
		m.l.NoteSeq(9)       // a state write is waiting to be published: it must not delay the self-retire
		fs.failWrites = true // storage lost: beats fail from now on
		for s.Now().Sub(start) < DefaultParams().MasterStale-time.Second && len(m.lost) == 0 {
			s.Advance(time.Second)
			if sec.l.IsMaster() {
				t.Fatal("the secondary took over before the master retired")
			}
			if len(m.lost) == 0 && s.Now().Sub(start) > DefaultParams().SelfRetire+DefaultParams().Check+time.Second {
				t.Fatal("the master did not retire")
			}
		}
		if len(m.lost) != 1 {
			t.Fatalf("OnLost called %d times", len(m.lost))
		}
		if at := m.lostT[0].Sub(start); at < DefaultParams().SelfRetire || at >= DefaultParams().MasterStale {
			t.Errorf("retired after %v, want [%v, %v)", at, DefaultParams().SelfRetire, DefaultParams().MasterStale)
		}
		if !strings.Contains(m.lost[0].Error(), "self-retire") {
			t.Errorf("reason: %v", m.lost[0])
		}
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("Maintain did not return after the loss")
		}
		fs.failWrites = false // storage back: the secondary can take over once the beat is stale
		s.Advance(DefaultParams().MasterStale + time.Second)
		if !step(t, sec) {
			t.Fatal("the secondary must take over after the master retired and stopped beating")
		}
		assertOwner(t, fs, "sec-id", RoleMaster)
	})
}

// A candidate that cannot create its lock fast enough abandons (write latency > max).
func TestSlowStorageAbortsTheCandidacyAndRemovesOnlyItsOwnFile(t *testing.T) {
	forBothModes(t, func(t *testing.T, fs *memFS) {
		s := newSim()
		slow := newInst(t, s, fs, "slow", 1, true, nil)
		fs.before = func(op string) {
			if op == "write" {
				s.Advance(DefaultParams().MaxWriteLatency + 100*time.Millisecond)
			}
		}
		if step(t, slow) {
			t.Fatal("a candidacy slower than the maximum write latency must be abandoned")
		}
		if _, ok := fs.content(lockPath); ok {
			t.Error("the abandoned candidate must remove its own file")
		}
	})
}

// Clean shutdown deletes the lock (immediate takeover), but never somebody else's.
func TestReleaseDeletesOnlyOurLock(t *testing.T) {
	forAllFS(t, func(t *testing.T, fs *memFS) {
		s := newSim()
		a := newInst(t, s, fs, "a", 1, true, nil)
		if !step(t, a) {
			t.Fatal("setup")
		}
		if err := a.l.Release(); err != nil {
			t.Fatal(err)
		}
		if _, ok := fs.content(lockPath); ok {
			t.Error("the lock must be gone after a clean release")
		}
		b := newInst(t, s, fs, "b", 2, true, nil)
		if !step(t, b) { // no staleness wait: the slot is free
			t.Fatal("immediate takeover expected")
		}
		// a stale Release (after being evicted) must not delete B's lock
		c := newInst(t, s, fs, "c", 3, true, nil)
		c.l.h, c.l.master = &memHandle{fs: fs, ino: &inode{id: 9999}}, true
		if err := c.l.Release(); err != nil {
			t.Fatal(err)
		}
		assertOwner(t, fs, "b-id", RoleMaster)
	})
}

func TestInconsistentCalibrationRefusesToStart(t *testing.T) {
	good := DefaultParams()
	if _, err := New(Config{Dir: simDir, FS: newMemFS(), Params: good}); err != nil {
		t.Fatal(err)
	}
	for name, mut := range map[string]func(*Params){
		"check >= beat":                func(p *Params) { p.Check = p.Beat },
		"beat >= self-retire":          func(p *Params) { p.Beat = p.SelfRetire },
		"self-retire >= master stale":  func(p *Params) { p.SelfRetire = p.MasterStale },
		"latency >= pause min":         func(p *Params) { p.MaxWriteLatency = p.PauseMin },
		"pause max >= candidate stale": func(p *Params) { p.PauseMax = p.CandidateStale },
		"pause min > pause max":        func(p *Params) { p.PauseMin = p.PauseMax + time.Second },
		"zero value":                   func(p *Params) { p.Beat = -1 },
	} {
		p := good
		mut(&p)
		if _, err := New(Config{Dir: simDir, FS: newMemFS(), Params: p}); err == nil {
			t.Errorf("%s: an inconsistent calibration must be refused", name)
		}
	}
}
