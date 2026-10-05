package lock

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// A reader that sees an empty or partial content (a write in progress, a slow mount) must treat it
// as INCONCLUSIVE: the guard refuses the write for this call, the lock is not lost, and it is lost
// only on a complete foreign content or after a bounded uncertainty (#162b).

func TestGuard_PartialContentIsInconclusiveNotALoss(t *testing.T) {
	forAllFS(t, func(t *testing.T, fs *memFS) {
		s := newSim()
		m := newInst(t, s, fs, "m", 1, true, nil)
		if !step(t, m) {
			t.Fatal("setup")
		}
		fs.mu.Lock()
		good := append([]byte(nil), fs.files[lockPath].data...)
		fs.mu.Unlock()
		for name, partial := range map[string][]byte{"empty": nil, "half": good[:20], "garbage": []byte("{\"inst")} {
			fs.mu.Lock()
			fs.files[lockPath].data = partial
			fs.mu.Unlock()
			err := m.l.CheckOwnership()
			if err == nil {
				t.Fatalf("%s: a partial content must not authorize a write", name)
			}
			if !m.l.IsMaster() || len(m.lost) != 0 {
				t.Fatalf("%s: the lock was LOST on a partial read: %v", name, err)
			}
		}
		// the write completes: the guard passes again
		fs.mu.Lock()
		fs.files[lockPath].data = good
		fs.mu.Unlock()
		if err := m.l.CheckOwnership(); err != nil {
			t.Fatalf("after the content is complete again: %v", err)
		}
	})
}

func TestGuard_UnreadableContentIsLostOnlyAfterABoundedUncertainty(t *testing.T) {
	forAllFS(t, func(t *testing.T, fs *memFS) {
		s := newSim()
		m := newInst(t, s, fs, "m", 1, true, nil)
		if !step(t, m) {
			t.Fatal("setup")
		}
		fs.mu.Lock()
		fs.files[lockPath].data = nil
		fs.mu.Unlock()
		limit := DefaultParams().SelfRetire / 2
		start := s.Now()
		for s.Now().Sub(start) < limit+10*time.Second && len(m.lost) == 0 {
			_ = m.l.CheckOwnership()
			s.Advance(5 * time.Second)
		}
		if len(m.lost) != 1 {
			t.Fatal("a content unreadable for ever must end in a loss (fail closed)")
		}
		if at := m.lostT[0].Sub(start); at < limit || at >= DefaultParams().SelfRetire {
			t.Errorf("lost after %v, want [%v, %v)", at, limit, DefaultParams().SelfRetire)
		}
	})
}

func TestGuard_CompleteForeignContentIsAnImmediateLoss(t *testing.T) {
	forAllFS(t, func(t *testing.T, fs *memFS) {
		s := newSim()
		m := newInst(t, s, fs, "m", 1, true, nil)
		if !step(t, m) {
			t.Fatal("setup")
		}
		fs.mu.Lock()
		fs.files[lockPath].data = encodeContent(content{InstanceID: "someone-else", Role: RoleMaster, Beat: 3})
		fs.mu.Unlock()
		if err := m.l.CheckOwnership(); err == nil || len(m.lost) != 1 {
			t.Fatalf("a complete foreign content must be an immediate loss: %v lost=%d", err, len(m.lost))
		}
	})
}

// R3: the inode comparison is what protects against a COPY of our content on another file.
func TestGuard_SameContentOnAnotherFileIsALoss(t *testing.T) {
	forBothModes(t, func(t *testing.T, fs *memFS) {
		s := newSim()
		m := newInst(t, s, fs, "m", 1, true, nil)
		if !step(t, m) {
			t.Fatal("setup")
		}
		fs.mu.Lock()
		data := append([]byte(nil), fs.files[lockPath].data...)
		delete(fs.files, lockPath)
		fs.next++
		fs.files[lockPath] = &inode{id: fs.next, data: data, mode: ModeMaster} // a different file, identical content
		fs.mu.Unlock()
		if err := m.l.CheckOwnership(); err == nil || len(m.lost) != 1 {
			t.Fatalf("an identical content on ANOTHER inode must be a loss: %v lost=%d", err, len(m.lost))
		}
	})
}

func TestEncodedContentHasAFixedSize(t *testing.T) {
	for _, c := range []content{
		{InstanceID: strings.Repeat("a", 32), Role: RoleCandidate},
		{InstanceID: strings.Repeat("b", 32), Role: RoleMaster, Beat: 1, Host: "h"},
		{InstanceID: strings.Repeat("c", 32), Role: RoleMaster, Beat: 1<<63 - 1, Host: strings.Repeat("x", 500)},
	} {
		b := encodeContent(c)
		if len(b) != contentSize {
			t.Errorf("size %d, want %d", len(b), contentSize)
		}
		got, ok := parseContent(b)
		if !ok || got.InstanceID != c.InstanceID || got.Role != c.Role || got.Beat != c.Beat {
			t.Errorf("round trip: %+v ok=%v", got, ok)
		}
	}
}

// ── real file system ─────────────────────────────────────────────────────────

// The heartbeat (rewrite in place) and the guard (read) run concurrently on a real file: the
// guard must never see a partial content from our own beat, hence never lose the lock.
func TestRealFS_HeartbeatAndGuardRunningTogetherNeverLoseTheLock(t *testing.T) {
	dir := t.TempDir()
	p := realParams()
	l, err := New(Config{Dir: dir, Params: p})
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Acquire(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Release() }()

	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				if err := l.doBeat(); err != nil {
					return
				}
			}
		}
	}()
	// raw reads of the file: every read must be a complete, parseable content
	partial := 0
	deadline := time.Now().Add(1500 * time.Millisecond)
	for n := 0; time.Now().Before(deadline); n++ {
		if err := l.CheckOwnership(); err != nil {
			close(stop)
			wg.Wait()
			t.Fatalf("the guard failed after %d checks while only OUR heartbeat was writing: %v", n, err)
		}
		raw, err := os.ReadFile(filepath.Join(dir, FileName))
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := parseContent(raw); !ok {
			partial++
		}
	}
	close(stop)
	wg.Wait()
	if partial != 0 {
		t.Errorf("%d reads saw a partial content of our own heartbeat", partial)
	}
	if !l.IsMaster() {
		t.Error("the lock was lost")
	}
}

func TestRealFS_SymlinkAtTheLockPathIsRefusedNotFollowed(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim.txt")
	if err := os.WriteFile(victim, []byte("do not touch"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, filepath.Join(dir, FileName)); err != nil {
		t.Fatal(err)
	}
	l, err := New(Config{Dir: dir, Params: realParams()})
	if err != nil {
		t.Fatal(err)
	}
	ok, err := l.step(context.Background())
	if ok || err == nil {
		t.Fatalf("a symlink at relay.lock must not be followed nor promote: ok=%v err=%v", ok, err)
	}
	if b, _ := os.ReadFile(victim); string(b) != "do not touch" {
		t.Errorf("the link target was modified: %q", b)
	}
	if _, err := (OSFS{}).ReadFile(filepath.Join(dir, FileName)); err == nil {
		t.Error("ReadFile followed a symlink")
	}

	// a master whose lock path was replaced by a symlink loses (the path designates another file)
	dir2 := t.TempDir()
	m, _ := New(Config{Dir: dir2, Params: realParams()})
	if err := m.Acquire(context.Background()); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir2, FileName)
	_ = os.Remove(path)
	if err := os.Symlink(victim, path); err != nil {
		t.Fatal(err)
	}
	if err := m.CheckOwnership(); err == nil || m.IsMaster() {
		t.Errorf("a symlinked lock path must be a loss: %v", err)
	}
}
