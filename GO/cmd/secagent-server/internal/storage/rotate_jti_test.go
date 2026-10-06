package storage

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func rotateStore(t *testing.T) *Store {
	t.Helper()
	s, err := OpenTemp()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if err := s.UpsertAgent(context.Background(), "h1", "pem", "jti-1"); err != nil {
		t.Fatal(err)
	}
	return s
}

func jtiOf(t *testing.T, s *Store) string {
	t.Helper()
	a, err := s.GetAgent(context.Background(), "h1")
	if err != nil || a == nil {
		t.Fatalf("agent: %v %v", a, err)
	}
	return a.TokenJTI
}

func TestRotateAgentJTI_ReplacesAndBlacklistsTheOldOneInOneWrite(t *testing.T) {
	s := rotateStore(t)
	ctx := context.Background()
	writes := s.Engine().Writes()
	if err := s.RotateAgentJTI(ctx, "h1", "jti-1", "jti-2", true, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if jtiOf(t, s) != "jti-2" {
		t.Error("the new JTI is not stored")
	}
	if bl, _ := s.IsJTIBlacklisted(ctx, "jti-1"); !bl {
		t.Error("the old JTI must be blacklisted")
	}
	if bl, _ := s.IsJTIBlacklisted(ctx, "jti-2"); bl {
		t.Error("the new JTI must not be blacklisted")
	}
	if got := s.Engine().Writes() - writes; got != 1 {
		t.Errorf("%d state writes, want exactly ONE", got)
	}
}

func TestRotateAgentJTI_Refusals(t *testing.T) {
	ctx := context.Background()
	until := time.Now().Add(time.Hour)
	t.Run("revoked", func(t *testing.T) {
		s := rotateStore(t)
		reason := "admin_revoke"
		_ = s.AddToBlacklist(ctx, "jti-1", "h1", until.Format(time.RFC3339), &reason)
		if err := s.RotateAgentJTI(ctx, "h1", "jti-1", "jti-2", true, until); !errors.Is(err, ErrRefreshRevoked) {
			t.Fatalf("err = %v", err)
		}
		if jtiOf(t, s) != "jti-1" {
			t.Error("a refused refresh must change nothing")
		}
	})
	t.Run("replaced (not the current JTI)", func(t *testing.T) {
		s := rotateStore(t)
		if err := s.RotateAgentJTI(ctx, "h1", "jti-0", "jti-2", true, until); !errors.Is(err, ErrRefreshReplaced) {
			t.Fatalf("err = %v", err)
		}
		if jtiOf(t, s) != "jti-1" {
			t.Error("nothing may change")
		}
	})
	t.Run("previous-secret token: an older JTI is accepted", func(t *testing.T) {
		s := rotateStore(t)
		if err := s.RotateAgentJTI(ctx, "h1", "jti-0", "jti-2", false, until); err != nil {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("suspended", func(t *testing.T) {
		s := rotateStore(t)
		if _, err := s.SetSuspended(ctx, "h1", true); err != nil {
			t.Fatal(err)
		}
		if err := s.RotateAgentJTI(ctx, "h1", "jti-1", "jti-2", true, until); !errors.Is(err, ErrRefreshSuspended) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("unknown agent", func(t *testing.T) {
		s := rotateStore(t)
		if err := s.RotateAgentJTI(ctx, "nobody", "jti-1", "jti-2", true, until); !errors.Is(err, ErrRefreshUnknownAgent) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("write refused (guard): nothing changes", func(t *testing.T) {
		s := rotateStore(t)
		s.SetWriteGuard(func() error { return ErrReadOnly })
		if err := s.RotateAgentJTI(ctx, "h1", "jti-1", "jti-2", true, until); err == nil {
			t.Fatal("a refused write must fail the rotation")
		}
		s.SetWriteGuard(func() error { return nil })
		if jtiOf(t, s) != "jti-1" {
			t.Error("the JTI changed although the write was refused")
		}
		if bl, _ := s.IsJTIBlacklisted(ctx, "jti-1"); bl {
			t.Error("the old JTI was blacklisted although the write was refused")
		}
	})
}

// Two refreshes with the same token: exactly one wins.
func TestRotateAgentJTI_ConcurrentRefreshesOnlyOneWins(t *testing.T) {
	s := rotateStore(t)
	until := time.Now().Add(time.Hour)
	var wg sync.WaitGroup
	results := make([]error, 8)
	for i := range results {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i] = s.RotateAgentJTI(context.Background(), "h1", "jti-1", "jti-new-"+string(rune('a'+i)), true, until)
		}()
	}
	wg.Wait()
	wins := 0
	for _, e := range results {
		if e == nil {
			wins++
		} else if !errors.Is(e, ErrRefreshReplaced) && !errors.Is(e, ErrRefreshRevoked) {
			t.Errorf("unexpected error %v", e)
		}
	}
	if wins != 1 {
		t.Fatalf("%d refreshes succeeded, want exactly 1", wins)
	}
}
