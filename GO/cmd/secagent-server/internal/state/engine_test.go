package state

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// ── atomic write: crash at every step ────────────────────────────────────────

func TestCrashAtEveryStepAlwaysLeavesAValidState(t *testing.T) {
	for _, variant := range []struct {
		name   string
		noLink bool
		torn   bool
	}{{"hard link rotation", false, false}, {"rename rotation (no links)", true, false}, {"torn write", false, true}} {
		t.Run(variant.name, func(t *testing.T) {
			for k := 1; ; k++ {
				dir := t.TempDir()
				seedState(t, dir)
				base := openEngine(t, dir, nil)
				if err := base.Mutate(addAgent("old")); err != nil { // seq 2, so a .prev exists
					t.Fatal(err)
				}

				fs := &faultFS{failAt: k, noLink: variant.noLink}
				if variant.torn {
					fs.tornAt = k
				}
				e := openEngine(t, dir, func(o *Options) { o.FS = fs })
				err := e.Mutate(addAgent("new"))
				if err == nil {
					if k == 1 {
						t.Fatal("the first step must fail")
					}
					return // went past the last step: every step was exercised
				}
				if !errors.Is(err, errInjected) {
					t.Fatalf("step %d: error %v", k, err)
				}
				// memory never runs ahead of the disk
				if _, ok := e.Snapshot().Agent("new"); ok {
					t.Fatalf("step %d: the failed mutation is visible in memory", k)
				}
				// "crash": a fresh process reads the directory
				buf := captureSlog(t)
				r, oerr := Open(Options{Dir: dir})
				if oerr != nil {
					t.Fatalf("step %d: the directory must always hold a valid state: %v\n%s", k, oerr, buf.String())
				}
				snap := r.Snapshot()
				if _, ok := snap.Agent("old"); !ok {
					t.Fatalf("step %d: committed data lost", k)
				}
				_, hasNew := snap.Agent("new")
				if (snap.WriteSeq() == 3) != hasNew {
					t.Fatalf("step %d: seq %d and presence of the new agent (%v) disagree: not coherent", k, snap.WriteSeq(), hasNew)
				}
				if snap.WriteSeq() != 2 && snap.WriteSeq() != 3 {
					t.Fatalf("step %d: write_seq %d", k, snap.WriteSeq())
				}
				if k > 40 {
					t.Fatal("the write never completes")
				}
			}
		})
	}
}

// renameStep returns the index of the rename(tmp → relay.state) among the file operations of a
// normal write (when a previous generation exists).
func renameStep(t *testing.T) int {
	t.Helper()
	dir := t.TempDir()
	seedState(t, dir)
	if err := openEngine(t, dir, nil).Mutate(addAgent("warm")); err != nil {
		t.Fatal(err)
	}
	fs := &faultFS{}
	if err := openEngine(t, dir, func(o *Options) { o.FS = fs }).Mutate(addAgent("probe")); err != nil {
		t.Fatal(err)
	}
	last := 0
	for i, op := range fs.ops {
		if op == "rename" {
			last = i + 1
		}
	}
	if last == 0 {
		t.Fatalf("no rename in %v", fs.ops)
	}
	return last
}

func TestStateFilesAreOwnerOnly(t *testing.T) {
	dir := t.TempDir()
	seedState(t, dir)
	e := openEngine(t, dir, nil)
	for i := 0; i < 2; i++ {
		if err := e.Mutate(addAgent(uniq("perm"))); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{StateFile, PrevFile} {
		if m := mode(t, filepath.Join(dir, f)); m != 0o600 {
			t.Errorf("%s mode %o, want 600", f, m)
		}
	}
	// a crash right before the rename leaves relay.state.tmp: it is 0600 too
	fs := &faultFS{failAt: renameStep(t)}
	e2 := openEngine(t, dir, func(o *Options) { o.FS = fs })
	if err := e2.Mutate(addAgent("crash")); err == nil {
		t.Fatal("expected the injected failure")
	}
	if m := mode(t, filepath.Join(dir, TmpFile)); m != 0o600 {
		t.Errorf("%s mode %o, want 600 (ops: %v)", TmpFile, m, fs.ops)
	}
}

// ── load: corruption, fallback, refusal ──────────────────────────────────────

func TestInvalidStateFallsBackOnPrevWithSecurityWarning(t *testing.T) {
	for name, damage := range map[string]func([]byte) []byte{
		"truncated": func(b []byte) []byte { return b[:len(b)/2] },
		"bad checksum": func(b []byte) []byte {
			return []byte(strings.Replace(string(b), "oldAoldA", "oldBoldA", 1))
		},
		"not json": func([]byte) []byte { return []byte("garbage") },
		"empty":    func([]byte) []byte { return nil },
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			seedState(t, dir)
			e := openEngine(t, dir, nil)
			if err := e.Mutate(addAgent("old")); err != nil {
				t.Fatal(err)
			}
			if err := e.Mutate(addAgent("newer")); err != nil { // state=seq3, prev=seq2
				t.Fatal(err)
			}
			sp := filepath.Join(dir, StateFile)
			if err := os.WriteFile(sp, damage(mustFile(t, sp)), 0o600); err != nil {
				t.Fatal(err)
			}
			buf := captureSlog(t)
			r, err := Open(Options{Dir: dir, BeforeWrite: allowAll})
			if err != nil {
				t.Fatalf("must recover from relay.state.prev: %v", err)
			}
			if !strings.Contains(buf.String(), "[SECURITY WARNING]") {
				t.Errorf("no SECURITY WARNING logged:\n%s", buf.String())
			}
			if r.Snapshot().WriteSeq() != 2 {
				t.Errorf("recovered seq %d, want 2 (the previous generation)", r.Snapshot().WriteSeq())
			}
			// the first write after a recovery must NOT rotate the corrupt file over the good prev
			if err := r.Mutate(addAgent("after")); err != nil {
				t.Fatal(err)
			}
			again, err := Open(Options{Dir: dir})
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := again.Snapshot().Agent("after"); !ok {
				t.Error("the post-recovery write is not in relay.state")
			}
			if _, err := decodeFile(t, filepath.Join(dir, PrevFile)); err != nil {
				t.Errorf("relay.state.prev must still be the valid generation: %v", err)
			}
		})
	}
}

func decodeFile(t testing.TB, path string) (*model, error) {
	m, _, err := decode(mustFile(t, path), time.Now())
	return m, err
}

func TestBothFilesInvalidRefusesToStartWithoutReinitializing(t *testing.T) {
	dir := t.TempDir()
	seedState(t, dir)
	e := openEngine(t, dir, nil)
	if err := e.Mutate(addAgent("a")); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{StateFile, PrevFile} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte(`{"truncated`), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	_, err := Open(Options{Dir: dir})
	if err == nil || !strings.Contains(err.Error(), "both relay.state") {
		t.Fatalf("both invalid must refuse to start, got %v", err)
	}
	var nf *NotFoundError
	if errors.As(err, &nf) {
		t.Fatal("must not be reported as 'not found' (that would invite state init)")
	}
}

func TestMissingStateRefusesToStartWithTheExactMessage(t *testing.T) {
	dir := t.TempDir()
	_, err := Open(Options{Dir: dir})
	want := fmt.Sprintf("FATAL: relay.state not found in STATE_DIR=%s — run 'secagent-server state init' to initialize", dir)
	if err == nil || err.Error() != want {
		t.Fatalf("error = %v, want %q", err, want)
	}
	var nf *NotFoundError
	if !errors.As(err, &nf) {
		t.Fatal("expected *NotFoundError")
	}
	if names := listDir(t, dir); len(names) != 0 {
		t.Errorf("opening must never create anything: %v", names)
	}
}

func TestSchemaVersionUnknownRefusesWithoutFallback(t *testing.T) {
	dir := t.TempDir()
	seedState(t, dir)
	e := openEngine(t, dir, nil)
	if err := e.Mutate(addAgent("a")); err != nil { // prev is valid
		t.Fatal(err)
	}
	sp := filepath.Join(dir, StateFile)
	b := mustFile(t, sp)
	if err := os.WriteFile(sp, []byte(strings.Replace(string(b), `"schema_version":1`, `"schema_version":2`, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(Options{Dir: dir}); !errors.Is(err, ErrSchemaVersion) {
		t.Fatalf("a newer schema must refuse to start (no silent downgrade), got %v", err)
	}
}

// ── write guard: no write before promotion ───────────────────────────────────

func TestNoGuardNoWriteNotEvenATmpFile(t *testing.T) {
	dir := t.TempDir()
	seedState(t, dir)
	before := listDir(t, dir)
	// two engines on the same directory, neither promoted (no guard / refusing guard)
	e1 := openEngine(t, dir, func(o *Options) { o.BeforeWrite = nil })
	e2 := openEngine(t, dir, func(o *Options) { o.BeforeWrite = func() error { return errors.New("not the master") } })
	if err := e1.Mutate(addAgent("a")); !errors.Is(err, ErrNoWriteGuard) {
		t.Fatalf("no guard: %v", err)
	}
	if err := e2.Mutate(addAgent("b")); err == nil || !strings.Contains(err.Error(), "not the master") {
		t.Fatalf("refusing guard: %v", err)
	}
	if after := listDir(t, dir); strings.Join(after, ",") != strings.Join(before, ",") {
		t.Errorf("files changed: %v → %v", before, after)
	}
	for _, e := range []*Engine{e1, e2} {
		if _, ok := e.Snapshot().Agent("a"); ok {
			t.Error("memory changed")
		}
		if e.Snapshot().WriteSeq() != 1 {
			t.Error("seq changed")
		}
	}
	// connecting the guard later enables writes
	e1.SetBeforeWrite(allowAll)
	if err := e1.Mutate(addAgent("a")); err != nil {
		t.Fatal(err)
	}
}

func TestGuardErrorLeavesDiskAndMemoryUntouched(t *testing.T) {
	dir := t.TempDir()
	seedState(t, dir)
	fail := false
	e := openEngine(t, dir, func(o *Options) {
		o.BeforeWrite = func() error {
			if fail {
				return errors.New("lost the lock")
			}
			return nil
		}
	})
	if err := e.Mutate(addAgent("ok")); err != nil {
		t.Fatal(err)
	}
	disk := mustFile(t, filepath.Join(dir, StateFile))
	fail = true
	if err := e.Mutate(addAgent("blocked")); err == nil {
		t.Fatal("the guard error must cancel the write")
	}
	if string(mustFile(t, filepath.Join(dir, StateFile))) != string(disk) {
		t.Error("disk changed")
	}
	if _, ok := e.Snapshot().Agent("blocked"); ok {
		t.Error("memory changed")
	}
	if _, err := os.Stat(filepath.Join(dir, TmpFile)); err == nil {
		t.Error("a tmp file was created before the guard decided")
	}
}

// ── group commit and atomicity ───────────────────────────────────────────────

func TestGroupCommitThousandConcurrentMutations(t *testing.T) {
	dir := t.TempDir()
	seedState(t, dir)
	e := openEngine(t, dir, nil)
	const n = 1000
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs <- e.Mutate(addAgent(fmt.Sprintf("host-%04d", i)))
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if got := e.Snapshot().AgentCount(); got != n {
		t.Fatalf("memory holds %d agents, want %d", got, n)
	}
	r, err := Open(Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if got := r.Snapshot().AgentCount(); got != n {
		t.Fatalf("disk holds %d agents, want %d: a mutation reported durable was lost", got, n)
	}
	if w := e.Writes(); w >= n/4 {
		t.Errorf("%d file replacements for %d mutations: not grouped", w, n)
	}
	t.Logf("%d mutations → %d writes", n, e.Writes())
}

// blockingGuard lets a test hold the writer inside the guard while mutations queue up.
func blockingGuard() (guard func() error, release func(), entered chan struct{}) {
	gate, entered := make(chan struct{}), make(chan struct{}, 8)
	var once sync.Once
	return func() error {
			entered <- struct{}{}
			<-gate
			return nil
		},
		func() { once.Do(func() { close(gate) }) }, entered
}

func TestBatchEachMutationIsAllOrNothing(t *testing.T) {
	dir := t.TempDir()
	seedState(t, dir)
	guard, release, entered := blockingGuard()
	e := openEngine(t, dir, func(o *Options) { o.BeforeWrite = guard })

	first := make(chan error, 1)
	go func() { first <- e.Mutate(addAgent("first")) }()
	<-entered // the writer is inside the guard: everything below is queued into ONE batch

	fails := func(tx *Tx) error {
		if err := tx.PutAgent(Agent{Hostname: "ghost", PublicKeyPEM: "p"}); err != nil {
			return err
		}
		if err := tx.SetConfig("half", "done"); err != nil {
			return err
		}
		return errors.New("business error after two writes")
	}
	results := make(chan error, 3)
	for _, fn := range []func(*Tx) error{addAgent("second"), fails, addAgent("third")} {
		go func(fn func(*Tx) error) { results <- e.Mutate(fn) }(fn)
	}
	for len(e.queueLenForTest()) < 3 {
		time.Sleep(time.Millisecond)
	}
	release()
	if err := <-first; err != nil {
		t.Fatal(err)
	}
	var failed, ok int
	for i := 0; i < 3; i++ {
		if err := <-results; err != nil {
			failed++
		} else {
			ok++
		}
	}
	if failed != 1 || ok != 2 {
		t.Fatalf("failed=%d ok=%d, want exactly the failing mutation to fail", failed, ok)
	}
	snap := e.Snapshot()
	for _, h := range []string{"first", "second", "third"} {
		if _, found := snap.Agent(h); !found {
			t.Errorf("%s missing", h)
		}
	}
	if _, found := snap.Agent("ghost"); found {
		t.Error("the failed mutation left an agent behind (partial application)")
	}
	if _, found := snap.Config("half"); found {
		t.Error("the failed mutation left a config value behind (partial application)")
	}
	if e.Writes() > 2 {
		t.Errorf("%d writes: the three queued mutations must share one", e.Writes())
	}
}

func (e *Engine) queueLenForTest() []*request {
	e.qmu.Lock()
	defer e.qmu.Unlock()
	return append([]*request(nil), e.queue...)
}

func enrollment(tokenID, hash, host string) func(*Tx) error {
	return func(tx *Tx) error {
		tok, ok := tx.EnrollmentToken(tokenID)
		if !ok {
			return errors.New("unknown token")
		}
		tok.UseCount++
		if err := tx.PutEnrollmentToken(tok); err != nil {
			return err
		}
		if err := tx.PutAuthorizedKey(AuthorizedKey{Hostname: host, PublicKeyPEM: testPEM(host), ApprovedAt: time.Now(), ApprovedBy: "enrollment_token:" + tokenID}); err != nil {
			return err
		}
		return addAgent(host)(tx)
	}
}

func TestMultiEntityMutationIsAllOrNothingOnFailedRename(t *testing.T) {
	dir := t.TempDir()
	seedState(t, dir)
	e := openEngine(t, dir, nil)
	if err := e.Mutate(func(tx *Tx) error {
		return tx.PutEnrollmentToken(EnrollmentToken{ID: "tok1", TokenHash: "h1", HostnamePattern: "*", CreatedAt: time.Now()})
	}); err != nil {
		t.Fatal(err)
	}
	fs := &faultFS{failAt: renameStep(t)}
	e2 := openEngine(t, dir, func(o *Options) { o.FS = fs })
	if err := e2.Mutate(enrollment("tok1", "h1", "host-x")); !errors.Is(err, errInjected) {
		t.Fatalf("expected the injected rename failure, got %v (ops %v)", err, fs.ops)
	}
	snap := e2.Snapshot()
	tok, _ := snap.EnrollmentToken("tok1")
	_, hasKey := snap.AuthorizedKey("host-x")
	_, hasAgent := snap.Agent("host-x")
	if tok.UseCount != 0 || hasKey || hasAgent {
		t.Fatalf("partial enrollment in memory: use_count=%d key=%v agent=%v", tok.UseCount, hasKey, hasAgent)
	}
	r, err := Open(Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	tok, _ = r.Snapshot().EnrollmentToken("tok1")
	_, hasKey = r.Snapshot().AuthorizedKey("host-x")
	if tok.UseCount != 0 || hasKey {
		t.Fatalf("partial enrollment on disk: use_count=%d key=%v", tok.UseCount, hasKey)
	}
	// and the same mutation succeeds as a whole when the disk works
	if err := e.Mutate(enrollment("tok1", "h1", "host-x")); err != nil {
		t.Fatal(err)
	}
	r, _ = Open(Options{Dir: dir})
	tok, _ = r.Snapshot().EnrollmentToken("tok1")
	_, hasKey = r.Snapshot().AuthorizedKey("host-x")
	_, hasAgent = r.Snapshot().Agent("host-x")
	if tok.UseCount != 1 || !hasKey || !hasAgent {
		t.Fatalf("enrollment not complete: %d %v %v", tok.UseCount, hasKey, hasAgent)
	}
}

func TestSizeCeilingRefusesTheWrite(t *testing.T) {
	dir := t.TempDir()
	seedState(t, dir)
	e := openEngine(t, dir, func(o *Options) { o.MaxBytes = 4096 })
	var err error
	for i := 0; i < 100 && err == nil; i++ {
		err = e.Mutate(addAgent(fmt.Sprintf("big-%d", i)))
	}
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("expected ErrTooLarge, got %v", err)
	}
	if fi, _ := os.Stat(filepath.Join(dir, StateFile)); fi.Size() > 4096 {
		t.Errorf("the file grew past the ceiling: %d", fi.Size())
	}
	// the failed mutation is not in memory
	n := e.Snapshot().AgentCount()
	r, _ := Open(Options{Dir: dir})
	if r.Snapshot().AgentCount() != n {
		t.Errorf("memory %d agents, disk %d", n, r.Snapshot().AgentCount())
	}
}

func TestReloadAndSnapshotIsolation(t *testing.T) {
	dir := t.TempDir()
	seedState(t, dir)
	a := openEngine(t, dir, nil)
	b := openEngine(t, dir, nil)
	before := a.Snapshot()
	if err := a.Mutate(addAgent("late")); err != nil {
		t.Fatal(err)
	}
	if _, ok := before.Agent("late"); ok {
		t.Error("a snapshot must not change under a later mutation")
	}
	if _, ok := b.Snapshot().Agent("late"); ok {
		t.Error("b has not reloaded")
	}
	if err := b.Reload(); err != nil {
		t.Fatal(err)
	}
	if _, ok := b.Snapshot().Agent("late"); !ok || b.Snapshot().WriteSeq() != 2 {
		t.Errorf("Reload must pick up the new write (seq %d)", b.Snapshot().WriteSeq())
	}
	// values handed out are copies
	if err := a.Mutate(func(tx *Tx) error {
		return tx.PutAgent(Agent{Hostname: "v", PublicKeyPEM: "p", Vars: map[string]any{"k": map[string]any{"n": 1}}})
	}); err != nil {
		t.Fatal(err)
	}
	ag, _ := a.Snapshot().Agent("v")
	ag.Vars["k"].(map[string]any)["n"] = 99
	again, _ := a.Snapshot().Agent("v")
	if again.Vars["k"].(map[string]any)["n"] != 1 {
		t.Error("the snapshot shares memory with the caller")
	}
}

func TestPiggybackMergesVolatileDataOnlyWhenWriting(t *testing.T) {
	dir := t.TempDir()
	seedState(t, dir)
	seen := time.Unix(1700001234, 0).UTC()
	e := openEngine(t, dir, func(o *Options) {
		o.Piggyback = func(p *Payload) {
			if a, ok := p.Agents["h"]; ok {
				a.LastSeen = &seen
				p.Agents["h"] = a
			}
		}
	})
	if err := e.Mutate(addAgent("h")); err != nil {
		t.Fatal(err)
	}
	r, _ := Open(Options{Dir: dir})
	if a, _ := r.Snapshot().Agent("h"); a.LastSeen == nil || !a.LastSeen.Equal(seen) {
		t.Errorf("last_seen not piggybacked: %+v", a.LastSeen)
	}
}
