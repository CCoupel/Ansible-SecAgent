// SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"testing"
	"time"
)

// AGENT_WS_PING_INTERVAL in [5 s, 60 s] (default 30 s), AGENT_WS_PROBE_TIMEOUT in [1 s, 30 s] (default 5 s).
func TestResolveAgentWS(t *testing.T) {
	if p, q, err := ResolveAgentWS(0, 0); err != nil || p != 30*time.Second || q != 5*time.Second {
		t.Fatalf("defaults: %s %s %v", p, q, err)
	}
	for _, c := range []struct {
		ping, probe time.Duration
		ok          bool
	}{
		{5 * time.Second, time.Second, true}, {time.Minute, 30 * time.Second, true},
		{4 * time.Second, 0, false}, {61 * time.Second, 0, false}, {0, 500 * time.Millisecond, false}, {0, time.Minute, false}, {-time.Second, 0, false},
	} {
		if _, _, err := ResolveAgentWS(c.ping, c.probe); (err == nil) != c.ok {
			t.Errorf("ping %s probe %s: err=%v want ok=%v", c.ping, c.probe, err, c.ok)
		}
	}
}

func TestConfigFromEnv_AgentWSValidation(t *testing.T) {
	for _, c := range []struct {
		ping, probe string
		ok          bool
	}{{"", "", true}, {"45s", "10s", true}, {"1s", "", false}, {"abc", "", false}, {"0s", "", false}, {"", "0", false}, {"", "2m", false}} {
		setServerEnv(t)
		t.Setenv("AGENT_WS_PING_INTERVAL", c.ping)
		t.Setenv("AGENT_WS_PROBE_TIMEOUT", c.probe)
		if _, err := ConfigFromEnv(); (err == nil) != c.ok {
			t.Errorf("ping=%q probe=%q: err=%v want ok=%v", c.ping, c.probe, err, c.ok)
		}
	}
}
