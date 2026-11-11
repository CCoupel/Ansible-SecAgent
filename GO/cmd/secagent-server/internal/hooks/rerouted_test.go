// SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
// SPDX-License-Identifier: AGPL-3.0-or-later

package hooks

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// host.rerouted / relay.rerouted: old_relay / new_relay are the LAST element of the top-down chains,
// exported to shell hooks, and the webhook body carries a `change` object.
func TestRerouted_VarsEnvAndWebhookChange(t *testing.T) {
	d := Detail{Cause: "moved", OldChain: []string{"dmz1", "zone-a"}, NewChain: []string{"dmz1", "zone-b"}}
	job := dispatchJob{event: "host.rerouted", hostname: "h", timestamp: "ts", relayChain: []string{"zone-b", "dmz1"}, detail: d}
	v := job.vars()
	for k, want := range map[string]string{"old_relay": "zone-a", "new_relay": "zone-b", "old_chain": "dmz1,zone-a",
		"new_chain": "dmz1,zone-b", "cause": "moved"} {
		if v[k] != want {
			t.Errorf("vars[%q] = %q, want %q", k, v[k], want)
		}
	}
	env := strings.Join(shellEnvironment(nil, nil, v), "\n")
	for _, want := range []string{"SECAGENT_OLD_RELAY=zone-a", "SECAGENT_NEW_RELAY=zone-b", "SECAGENT_OLD_CHAIN=dmz1,zone-a", "SECAGENT_NEW_CHAIN=dmz1,zone-b", "SECAGENT_CAUSE=moved"} {
		if !strings.Contains(env, want) {
			t.Errorf("shell environment lacks %s:\n%s", want, env)
		}
	}
	ch := changeOf(v)
	if ch == nil || !reflect.DeepEqual(*ch, webhookChange{OldRelay: "zone-a", NewRelay: "zone-b", OldChain: []string{"dmz1", "zone-a"},
		NewChain: []string{"dmz1", "zone-b"}, Cause: "moved"}) {
		t.Fatalf("change = %+v", ch)
	}
	body, _ := json.Marshal(webhookPayload{Event: "host.rerouted", Host: &webhookHost{Hostname: "h"}, Change: ch})
	if !strings.Contains(string(body), `"change":{"old_relay":"zone-a","new_relay":"zone-b"`) || strings.Contains(string(body), `"relay":`) {
		t.Errorf("body = %s", body)
	}

	// relay.rerouted keeps its relay object AND gets the change object (no cause)
	rj := dispatchJob{event: "relay.rerouted", relayID: "zone-a", relayChain: []string{"zone-a", "dmz1"},
		detail: Detail{OldChain: []string{"dmz1", "zone-a"}, NewChain: []string{"zone-a"}, HostsRouted: 3}}
	rv := rj.vars()
	if rv["old_relay"] != "zone-a" || rv["new_relay"] != "zone-a" || rv["hosts_routed"] != "3" {
		t.Errorf("relay.rerouted vars = %v", rv)
	}
	if o := relayObjOf(rv); o == nil || o.RelayID != "zone-a" {
		t.Errorf("relay object = %+v", o)
	}
	if c := changeOf(rv); c == nil || c.OldRelay != "zone-a" || c.Cause != "" {
		t.Errorf("relay.rerouted change = %+v", c)
	}
}

// Other events carry no change object and no old_relay / new_relay.
func TestRerouted_OtherEventsHaveNoChange(t *testing.T) {
	job := dispatchJob{event: "host.up", hostname: "h", detail: Detail{ConnSeq: 2, OldChain: []string{"x"}}}
	v := job.vars()
	if _, ok := v["old_relay"]; ok {
		t.Errorf("host.up has old_relay: %v", v)
	}
	if changeOf(v) != nil {
		t.Error("host.up must have no change object")
	}
	if (Detail{}).OldRelay() != "" || (Detail{}).NewRelay() != "" {
		t.Error("empty chains: empty relay")
	}
}
