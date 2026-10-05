package lock

import (
	"testing"
	"time"
)

// #163 anti-replay: the highest write_seq ever read in the lock is remembered by a secondary, even in
// a stale lock it deletes right away, and the new master carries it on.
func TestSeq_SecondaryRemembersTheHighestSeqEvenOfAStaleLock(t *testing.T) {
	forBothModes(t, func(t *testing.T, fs *memFS) {
		s := newSim()
		h, _ := fs.CreateExclusive(lockPath, ModeMaster)
		_ = h.Rewrite(encodeContent(content{InstanceID: "dead-master", Role: RoleMaster, Beat: 3, Seq: 42, Host: "gone"}))
		sec := newInst(t, s, fs, "secondary", 1, true, nil)

		step(t, sec) // first observation
		if got := sec.l.MinSeq(); got != 42 {
			t.Fatalf("MinSeq = %d, want 42", got)
		}
		s.Advance(DefaultParams().MasterStale + time.Second)
		if !step(t, sec) {
			t.Fatal("must take over the dead master")
		}
		if got := sec.l.MinSeq(); got != 42 {
			t.Fatalf("MinSeq after the takeover = %d, want 42 (read just before the deletion)", got)
		}
		if c, _ := fs.content(lockPath); c.Seq != 42 {
			t.Errorf("the new master's lock carries write_seq %d, want 42 (the guard must survive the takeover)", c.Seq)
		}
	})
}

func TestSeq_MasterPublishesNotedSeqAndNeverLowersIt(t *testing.T) {
	forBothModes(t, func(t *testing.T, fs *memFS) {
		s := newSim()
		m := newInst(t, s, fs, "master", 1, true, nil)
		if !step(t, m) {
			t.Fatal("no promotion on a free lock")
		}
		m.l.NoteSeq(7)
		m.l.publishSeqIfNeeded()
		if c, _ := fs.content(lockPath); c.Seq != 7 {
			t.Fatalf("published write_seq = %d, want 7", c.Seq)
		}
		m.l.NoteSeq(3) // a lower value never lowers the published one
		m.l.publishSeqIfNeeded()
		if err := m.l.doBeat(); err != nil {
			t.Fatal(err)
		}
		if c, _ := fs.content(lockPath); c.Seq != 7 {
			t.Fatalf("the beat lowered the write_seq to %d", c.Seq)
		}
		m.l.NoteSeq(9)
		if err := m.l.doBeat(); err != nil {
			t.Fatal(err)
		}
		if c, _ := fs.content(lockPath); c.Seq != 9 {
			t.Fatalf("the beat must carry the latest noted write_seq, got %d", c.Seq)
		}
	})
}

func TestStatus_PhasesAndTimestamps(t *testing.T) {
	forBothModes(t, func(t *testing.T, fs *memFS) {
		s := newSim()
		plantDeadMaster(fs, 1)
		sec := newInst(t, s, fs, "secondary", 1, true, nil)
		if st := sec.l.Status(); st.Phase != PhaseSecondary || !st.LastCheck.IsZero() {
			t.Fatalf("before any poll: %+v", st)
		}
		step(t, sec)
		st := sec.l.Status()
		if st.Phase != PhaseSecondary || st.LastCheck.IsZero() || st.InstanceID != "secondary-id" {
			t.Fatalf("after a poll: %+v", st)
		}
		s.Advance(DefaultParams().MasterStale + time.Second)
		if !step(t, sec) {
			t.Fatal("must take over")
		}
		if st := sec.l.Status(); st.Phase != PhaseMaster || st.LastBeatOK.IsZero() || st.Beat != 1 {
			t.Fatalf("master: %+v", st)
		}
		_ = fs.Remove(lockPath) // the lock vanishes: the next check loses it
		_ = sec.l.CheckOwnership()
		if st := sec.l.Status(); st.Phase != PhaseLost || st.LostReason == "" {
			t.Fatalf("after the loss: %+v", st)
		}
	})
}
