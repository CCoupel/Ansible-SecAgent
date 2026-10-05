package storage

// #160 (QA R1): multi-entity operations are ONE state mutation = ONE file write. A guard that
// accepts exactly one write and refuses every later one must therefore let such an operation
// complete entirely; an implementation split into two mutations (token consumed, THEN agent)
// would leave a partial result, or fail after a first write that stays on disk. These tests
// fail on such a split.

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"secagent-server/cmd/secagent-server/internal/state"
)

// writeBudget is a write guard that lets `allowed` file writes through, then refuses. The engine
// consults the guard twice per write (before the batch and again right before the rename, #159b
// R4), so a write consumes two calls; a refusal at either point leaves nothing on disk.
type writeBudget struct{ calls, allowed atomic.Int64 }

func (b *writeBudget) setWrites(n int) { b.calls.Store(0); b.allowed.Store(int64(2 * n)) }

func (b *writeBudget) guard() error {
	if b.calls.Add(1) > b.allowed.Load() {
		return errors.New("write budget exhausted")
	}
	return nil
}

// budgetStore opens dir with a guard governed by the returned budget (unlimited at first).
func budgetStore(t *testing.T, dir string) (*Store, *writeBudget) {
	t.Helper()
	b := &writeBudget{}
	b.allowed.Store(1 << 40)
	if _, err := OpenTestDir(dir); err != nil { // creates the initial state
		t.Fatal(err)
	}
	s, err := Open(state.Options{Dir: dir, InsecureTestMode: true, BeforeWrite: b.guard, Instance: "budget"})
	if err != nil {
		t.Fatal(err)
	}
	return s, b
}

func TestEnrollAgent_IsOneWriteNotTwo(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	s, b := budgetStore(t, dir)
	if err := s.CreateEnrollmentToken(ctx, EnrollmentToken{ID: "e1", TokenHash: "he1", HostnamePattern: ".*", CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}

	// exactly ONE write allowed: the enrollment (token consumed + key authorized + agent) must
	// complete, durably
	b.setWrites(1)
	if err := s.EnrollAgent(ctx, "e1", "h1", "PEM", "jti", "enrollment_token:e1"); err != nil {
		t.Fatalf("the enrollment is one mutation, one write: it must fit in a budget of one write: %v", err)
	}
	r := reopen(t, dir)
	tok, _ := r.GetEnrollmentTokenByID(ctx, "e1")
	a, _ := r.GetAgent(ctx, "h1")
	k, _ := r.GetAuthorizedKey(ctx, "h1")
	if tok == nil || tok.UseCount != 1 || a == nil || k == nil {
		t.Fatalf("incomplete after a single write: token=%+v agent=%v key=%v", tok, a, k)
	}
}

func TestEnrollAgent_RefusedWriteLeavesNothingNotEvenTheToken(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	s, b := budgetStore(t, dir)
	if err := s.CreateEnrollmentToken(ctx, EnrollmentToken{ID: "e1", TokenHash: "he1", HostnamePattern: ".*", CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	b.setWrites(0)
	if err := s.EnrollAgent(ctx, "e1", "h1", "PEM", "jti", "enrollment_token:e1"); err == nil {
		t.Fatal("the write is refused: the enrollment must fail")
	}
	// neither in memory nor on disk: no token consumed, no key authorized, no agent
	for name, st := range map[string]*Store{"memory": s, "disk": reopen(t, dir)} {
		tok, _ := st.GetEnrollmentTokenByID(ctx, "e1")
		a, _ := st.GetAgent(ctx, "h1")
		k, _ := st.GetAuthorizedKey(ctx, "h1")
		if tok == nil || tok.UseCount != 0 || a != nil || k != nil {
			t.Fatalf("%s: partial enrollment: token=%+v agent=%v key=%v", name, tok, a, k)
		}
	}
}

func TestRevokeRelayNode_FlagAndBlacklistAreOneWrite(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	s, b := budgetStore(t, dir)
	seedNodes(t, s, "dmz1")
	exp := time.Now().Add(24 * time.Hour).Unix()
	if err := s.SetRelayTokenInfo("dmz1", "jti-dmz1", exp); err != nil {
		t.Fatal(err)
	}

	b.setWrites(1) // one write: flag + blacklist together
	if _, found, err := s.RevokeRelayNode(ctx, "dmz1", "admin revoke"); err != nil || !found {
		t.Fatalf("the revocation is one mutation, one write: %v %v", found, err)
	}
	r := reopen(t, dir)
	if bl, _ := r.IsJTIBlacklisted(ctx, "jti-dmz1"); !bl {
		t.Error("JTI not blacklisted after a single write")
	}
	if info, _ := r.GetRelayTokenInfo("dmz1"); !info.Revoked {
		t.Error("relay not flagged revoked after a single write")
	}
}

func TestRevokeRelayNode_RefusedWriteLeavesNeitherFlagNorBlacklist(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	s, b := budgetStore(t, dir)
	seedNodes(t, s, "dmz1")
	if err := s.SetRelayTokenInfo("dmz1", "jti-dmz1", time.Now().Add(24*time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}
	b.setWrites(0)
	if _, _, err := s.RevokeRelayNode(ctx, "dmz1", "admin revoke"); err == nil {
		t.Fatal("the write is refused: the revocation must fail")
	}
	for name, st := range map[string]*Store{"memory": s, "disk": reopen(t, dir)} {
		bl, _ := st.IsJTIBlacklisted(ctx, "jti-dmz1")
		info, _ := st.GetRelayTokenInfo("dmz1")
		if bl || info.Revoked {
			t.Fatalf("%s: partial revocation: blacklisted=%v revoked=%v", name, bl, info.Revoked)
		}
	}
}

// the same property for the relay-parent token revocation (token flag + blacklist).
func TestRevokeRelayParentToken_FlagAndBlacklistAreOneWrite(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	s, b := budgetStore(t, dir)
	seedNodes(t, s, "parent1")
	if err := s.CreateRelayParentToken(ctx, RelayParentToken{ID: "rp1", ParentID: "parent1", JTI: "jti-rp1", ExpiresAt: time.Now().Add(24 * time.Hour), CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	b.setWrites(1)
	if _, found, err := s.RevokeRelayParentToken(ctx, "rp1"); err != nil || !found {
		t.Fatalf("revocation in one write: %v %v", found, err)
	}
	r := reopen(t, dir)
	if bl, _ := r.IsJTIBlacklisted(ctx, "jti-rp1"); !bl {
		t.Error("JTI not blacklisted after a single write")
	}
}
