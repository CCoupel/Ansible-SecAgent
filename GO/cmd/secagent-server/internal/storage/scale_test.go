package storage

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"secagent-server/cmd/secagent-server/internal/state"
)

// Dimensioning (#160): a fleet beyond 3000 hosts. A burst of enrollments is grouped by the engine,
// the file stays small, a restart reloads everything quickly and the hot reads never touch the disk.
func TestScale_ThreeThousandFiveHundredHosts(t *testing.T) {
	if testing.Short() {
		t.Skip("dimensioning test")
	}
	const hosts = 3500
	ctx := context.Background()
	dir := t.TempDir()
	s, err := OpenTestDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	pem := "-----BEGIN PUBLIC KEY-----\n" + strings.Repeat("A", 780) + "\n-----END PUBLIC KEY-----\n" // ~RSA-4096 public key
	if err := s.CreateEnrollmentToken(ctx, EnrollmentToken{ID: "bulk", TokenHash: "h-bulk", HostnamePattern: ".*", Reusable: true, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}

	writes0 := s.Engine().Writes()
	start := time.Now()
	var wg sync.WaitGroup
	errs := make(chan error, hosts)
	sem := make(chan struct{}, 500) // a burst of 500 enrollments in flight
	for i := 0; i < hosts; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			host := fmt.Sprintf("host-%05d.example.org", i)
			errs <- s.EnrollAgent(ctx, "bulk", host, pem, fmt.Sprintf("jti-%05d", i), "enrollment_token:bulk")
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
	writes := s.Engine().Writes() - writes0
	fi, _ := os.Stat(filepath.Join(dir, state.StateFile))
	t.Logf("%d hosts enrolled in %v with %d file writes; relay.state = %.1f MiB", hosts, took, writes, float64(fi.Size())/(1<<20))
	if writes >= hosts/10 {
		t.Errorf("%d writes for %d enrollments: the burst is not grouped", writes, hosts)
	}
	if fi.Size() > 20<<20 {
		t.Errorf("state file %d bytes for %d hosts", fi.Size(), hosts)
	}
	if limit := 60 * time.Second * raceFactor; took > limit {
		t.Errorf("enrolment burst took %v (limit %v)", took, limit)
	}
	if tok, _ := s.GetEnrollmentTokenByID(ctx, "bulk"); tok.UseCount != hosts {
		t.Errorf("use_count %d, want %d (lost updates)", tok.UseCount, hosts)
	}

	// hot reads: memory only, whatever the size
	w := s.Engine().Writes()
	t0 := time.Now()
	for i := 0; i < 20000; i++ {
		_, _ = s.IsJTIBlacklisted(ctx, "x")
		_, _ = s.GetAgent(ctx, fmt.Sprintf("host-%05d.example.org", i%hosts))
		_ = s.UpdateAgentStatus(ctx, fmt.Sprintf("host-%05d.example.org", i%hosts), "connected", "")
	}
	t.Logf("20000 hot reads+status updates in %v", time.Since(t0))
	if s.Engine().Writes() != w {
		t.Error("hot paths wrote to the disk")
	}
	if agents, _ := s.ListAgents(ctx, true); len(agents) != hosts {
		t.Errorf("%d connected agents, want %d", len(agents), hosts)
	}

	// restart: everything comes back, quickly
	_ = s.Close()
	t0 = time.Now()
	r, err := OpenTestDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	load := time.Since(t0)
	t.Logf("reload of %d hosts: %v", hosts, load)
	if limit := 3 * time.Second * raceFactor; load > limit {
		t.Errorf("reload took %v (limit %v)", load, limit)
	}
	if agents, _ := r.ListAgents(ctx, false); len(agents) != hosts {
		t.Errorf("%d agents after the restart, want %d", len(agents), hosts)
	}
	if k, _ := r.GetAuthorizedKey(ctx, "host-03499.example.org"); k == nil {
		t.Error("authorized key lost")
	}
}
