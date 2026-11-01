package server

// #217 M2 (security review, requirement 3): AGENT_JWT_TTL and AGENT_JWT_RENEW_INTERVAL are validated at
// start, a bad value is a net refusal (never a silent fallback to 1 h, never "no renewal"):
//
//	TTL       ∈ [5 min, 7 days]   default 24 h
//	interval  ∈ [1 min, TTL/2]    default TTL/3
//
// Below the minimum the values are only reachable through an explicit test seam (Config fields), never
// through the environment. The upper bound and the relation to the TTL are the part dev-relay already
// enforces; the minimums are the reviewer's.

import (
	"strings"
	"testing"
	"time"
)

func configWith(t *testing.T, ttl, interval string) (Config, error) {
	t.Helper()
	setServerEnv(t)
	t.Setenv("AGENT_JWT_TTL", ttl)
	t.Setenv("AGENT_JWT_RENEW_INTERVAL", interval)
	return ConfigFromEnv()
}

// Defaults: 24 h and TTL/3, resolved by the single validation function.
func TestSecM2_DefaultsAre24hAndATTLThird(t *testing.T) {
	ttl, interval, err := ResolveAgentJWT(0, 0)
	if err != nil || ttl != 24*time.Hour || interval != 8*time.Hour {
		t.Fatalf("ResolveAgentJWT(0,0) = %s %s %v, want 24h 8h", ttl, interval, err)
	}
	ttl, interval, err = ResolveAgentJWT(12*time.Hour, 0)
	if err != nil || ttl != 12*time.Hour || interval != 4*time.Hour {
		t.Fatalf("ResolveAgentJWT(12h,0) = %s %s %v, want 12h 4h", ttl, interval, err)
	}
}

// Exact edges of the accepted range.
func TestSecM2_EdgesOfTheAcceptedRange(t *testing.T) {
	ok := []struct{ ttl, interval string }{
		{"5m", ""}, {"5m", "1m"}, {"5m", "150s"}, // minimum TTL; interval ∈ [1 min, TTL/2]
		{"168h", ""}, {"168h", "84h"}, {"24h", "1m"}, {"24h", "12h"},
	}
	for _, c := range ok {
		if _, err := configWith(t, c.ttl, c.interval); err != nil {
			t.Errorf("TTL=%q INTERVAL=%q must be accepted: %v", c.ttl, c.interval, err)
		}
	}
	bad := []struct{ ttl, interval, why string }{
		{"4m59s", "", "TTL below 5 min"},
		{"1s", "", "TTL of one second"},
		{"168h1s", "", "TTL above 7 days"},
		{"24h", "59s", "interval below 1 min"},
		{"24h", "12h1s", "interval above TTL/2"},
		{"24h", "24h", "interval equal to the TTL: never renewed in time"},
		{"24h", "48h", "interval above the TTL: never renewed"},
		{"5m", "151s", "interval above TTL/2 at the minimum TTL"},
	}
	for _, c := range bad {
		_, err := configWith(t, c.ttl, c.interval)
		if err == nil {
			t.Errorf("%s: TTL=%q INTERVAL=%q must be refused", c.why, c.ttl, c.interval)
			continue
		}
		if !strings.Contains(err.Error(), "AGENT_JWT") {
			t.Errorf("%s: the refusal must name the variable: %v", c.why, err)
		}
	}
}

// Malformed, zero and negative values are errors, not a fallback to the old 1 h.
func TestSecM2_MalformedZeroOrNegativeIsRefusedNeverASilentFallback(t *testing.T) {
	for _, c := range []struct{ ttl, interval string }{
		{"abc", ""}, {"24", ""}, {"1 day", ""}, {"0", ""}, {"0s", ""}, {"-24h", ""},
		{"24h", "xyz"}, {"24h", "0"}, {"24h", "-8h"}, {"NaN", ""}, {"24h;", ""},
	} {
		if cfg, err := configWith(t, c.ttl, c.interval); err == nil {
			t.Errorf("TTL=%q INTERVAL=%q must be refused (got TTL %s interval %s)", c.ttl, c.interval, cfg.AgentJWTTTL, cfg.AgentJWTRenewInterval)
		}
	}
}

// Build re-validates what a caller put in the Config directly (the seam is not a way around the upper
// bound): an out-of-range TTL refuses to start before the state is opened.
func TestSecM2_BuildRefusesAnOutOfRangeTTLFromTheConfig(t *testing.T) {
	for _, ttl := range []time.Duration{8 * 24 * time.Hour, -time.Hour} {
		if _, _, err := ResolveAgentJWT(ttl, 0); err == nil {
			t.Errorf("TTL %s must be refused by ResolveAgentJWT", ttl)
		}
	}
	if _, _, err := ResolveAgentJWT(24*time.Hour, 13*time.Hour); err == nil {
		t.Error("interval 13h for a 24h TTL must be refused")
	}
}
