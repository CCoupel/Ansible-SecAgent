// chaining_test.go — Tests for proxy anti-loop hop counting.
//
// The push-mode HTTP chaining tests (RelayClient propagation, three-level
// chain, loop detection via HTTP 508) have been removed in v3.0 (#123) along
// with RelayClient itself.  The context helpers survive because exec.go uses
// them for incoming-request anti-loop detection regardless of topology.
package proxy

import (
	"context"
	"testing"
)

// ── Context helpers ───────────────────────────────────────────────────────────

func TestWithRelayHops_DefaultWhenAbsent(t *testing.T) {
	got := RelayHopsFromContext(context.Background())
	if got != DefaultMaxHops {
		t.Errorf("expected DefaultMaxHops=%d, got %d", DefaultMaxHops, got)
	}
}

func TestWithRelayHops_Roundtrip(t *testing.T) {
	for _, hops := range []int{0, 1, 3, DefaultMaxHops, 100} {
		ctx := WithRelayHops(context.Background(), hops)
		got := RelayHopsFromContext(ctx)
		if got != hops {
			t.Errorf("hops=%d: roundtrip got %d", hops, got)
		}
	}
}

func TestWithRelayHops_ParentNotAffected(t *testing.T) {
	parent := context.Background()
	_ = WithRelayHops(parent, 3)
	// parent should still return DefaultMaxHops
	if got := RelayHopsFromContext(parent); got != DefaultMaxHops {
		t.Errorf("parent context was mutated: expected %d, got %d", DefaultMaxHops, got)
	}
}
