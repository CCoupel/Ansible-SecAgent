package server

// #217 (v3.0.5, D1) — AGENT_JWT_TTL (default 24 h, was 1 h hard-coded) and AGENT_JWT_RENEW_INTERVAL
// (default TTL/3). Plan validation: TTL ≥ 2 × interval, TTL ≤ 7 days, durations must parse. Only
// the accept / refuse contract is tested here (the config field names are the developer's).

import (
	"strings"
	"testing"
)

func TestSpec217_AgentJWTConfigurationValidation(t *testing.T) {
	cases := []struct {
		name, ttl, interval string
		ok                  bool
	}{
		{"defaults", "", "", true},
		{"nominal 24h / 8h", "24h", "8h", true},
		{"ttl only: interval derived", "12h", "", true},
		{"exactly twice the interval", "10m", "5m", true},
		{"upper bound 7 days", "168h", "", true},
		{"above 7 days", "169h", "", false},
		{"interval above TTL/2", "10m", "6m", false},
		{"interval equal to TTL", "10m", "10m", false},
		{"unparsable TTL", "tomorrow", "", false},
		{"unparsable interval", "24h", "often", false},
		{"zero TTL", "0s", "", false},
		{"negative TTL", "-1h", "", false},
		{"negative interval", "24h", "-1s", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			setServerEnv(t)
			t.Setenv("AGENT_JWT_TTL", c.ttl)
			t.Setenv("AGENT_JWT_RENEW_INTERVAL", c.interval)
			_, err := ConfigFromEnv()
			if c.ok && err != nil {
				t.Fatalf("TTL=%q INTERVAL=%q must be accepted: %v", c.ttl, c.interval, err)
			}
			if !c.ok {
				if err == nil {
					t.Fatalf("TTL=%q INTERVAL=%q must be refused", c.ttl, c.interval)
				}
				if !strings.Contains(err.Error(), "AGENT_JWT") {
					t.Errorf("the refusal must name the variable: %v", err)
				}
			}
		})
	}
}
