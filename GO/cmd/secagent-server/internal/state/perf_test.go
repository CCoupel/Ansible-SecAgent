package state

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// Dimensioning (> 3000 hosts, target 10 000): load, full write and a burst of enrollments.

func rsaLikePEM(i int) string {
	// an RSA-4096 public key PEM is about 800 bytes
	return "-----BEGIN PUBLIC KEY-----\n" + strings.Repeat(fmt.Sprintf("%08d", i), 100) + "\n-----END PUBLIC KEY-----\n"
}

func bigAgent(i int) Agent {
	return Agent{
		Hostname: fmt.Sprintf("host-%05d.example.org", i), PublicKeyPEM: rsaLikePEM(i), TokenJTI: fmt.Sprintf("jti-%05d-0000-0000", i),
		EnrolledAt: time.Unix(1700000000, 0).UTC(),
		Vars:       map[string]any{"env": "prod", "site": "paris", "tier": float64(i % 5), "tags": []any{"a", "b", "c"}},
	}
}

func fillAgents(t testing.TB, e *Engine, n int) {
	t.Helper()
	if err := e.Mutate(func(tx *Tx) error {
		for i := 0; i < n; i++ {
			if err := tx.PutAgent(bigAgent(i)); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestPerf10000Agents(t *testing.T) {
	if testing.Short() {
		t.Skip("dimensioning test")
	}
	dir := t.TempDir()
	seedState(t, dir)
	e := openEngine(t, dir, nil)

	start := time.Now()
	fillAgents(t, e, 10000)
	full := time.Since(start)
	size := int64(len(mustFile(t, dir+"/"+StateFile)))
	t.Logf("10 000 agents: file %.1f MiB, full write (clone+marshal+sha256+fsync+rename) %v", float64(size)/(1<<20), full)
	if size > 20<<20 {
		t.Errorf("file %d bytes: far above the ~15 MiB target", size)
	}
	if limit := 500 * time.Millisecond * raceFactor; full > limit {
		t.Errorf("full write took %v, limit %v", full, limit)
	}

	start = time.Now()
	r, err := Open(Options{Dir: dir})
	load := time.Since(start)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("load of 10 000 agents: %v", load)
	if limit := 2 * time.Second * raceFactor; load > limit {
		t.Errorf("load took %v, limit %v", load, limit)
	}
	if r.Snapshot().AgentCount() != 10000 {
		t.Fatalf("loaded %d agents", r.Snapshot().AgentCount())
	}

	// a single enrollment on a big state: the write cost of one mutation
	if err := r.Mutate(addAgent("single")); err == nil {
		t.Fatal("a loaded engine without a guard must refuse")
	}
	r.SetBeforeWrite(allowAll)
	start = time.Now()
	if err := r.Mutate(addAgent("single")); err != nil {
		t.Fatal(err)
	}
	t.Logf("one mutation on 10 000 agents: %v", time.Since(start))
}

func TestPerf100ConcurrentEnrollmentsAreGrouped(t *testing.T) {
	if testing.Short() {
		t.Skip("dimensioning test")
	}
	dir := t.TempDir()
	seedState(t, dir)
	e := openEngine(t, dir, nil)
	fillAgents(t, e, 10000)
	if err := e.Mutate(func(tx *Tx) error {
		return tx.PutEnrollmentToken(EnrollmentToken{ID: "reuse", TokenHash: "rh", HostnamePattern: "*", Reusable: true, CreatedAt: time.Now()})
	}); err != nil {
		t.Fatal(err)
	}
	writes0 := e.Writes()
	start := time.Now()
	var wg sync.WaitGroup
	errs := make(chan error, 100)
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs <- e.Mutate(enrollment("reuse", "rh", fmt.Sprintf("new-%03d", i)))
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	took := time.Since(start)
	w := e.Writes() - writes0
	t.Logf("100 concurrent enrollments on 10 000 agents: %v, %d file writes", took, w)
	if limit := 5 * time.Second * raceFactor; took > limit {
		t.Errorf("took %v, limit %v", took, limit)
	}
	if w >= 100 {
		t.Errorf("%d writes for 100 enrollments: not grouped", w)
	}
	tok, _ := e.Snapshot().EnrollmentToken("reuse")
	if tok.UseCount != 100 {
		t.Errorf("use_count %d, want 100 (lost updates)", tok.UseCount)
	}
}
