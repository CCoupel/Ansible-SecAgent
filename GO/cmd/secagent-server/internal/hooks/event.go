// SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
// SPDX-License-Identifier: AGPL-3.0-or-later

package hooks

import (
	"encoding/json"
	"strconv"
	"strings"
)

// Detail carries the fields of the v3.0.6 events that go beyond host name, status and chain. It is
// embedded in the wire structures (ws.RelayMessage, repeater.Event) so that its fields flatten into
// the event_forward JSON. Mode has no JSON tag of its own ("-"): both wire structures already own a
// "mode" key and copy it by hand.
type Detail struct {
	Mode                       string   `json:"-"` // relay.*: pull | push
	Cause                      string   `json:"cause,omitempty"`
	Reason                     string   `json:"reason,omitempty"`
	InstanceID                 string   `json:"instance_id,omitempty"`
	PreviousInstanceID         string   `json:"previous_instance_id,omitempty"`
	ConnSeq                    Seq      `json:"conn_seq,omitempty"`
	HostsRouted                int      `json:"hosts_routed,omitempty"`
	RelaysBelow                int      `json:"relays_below,omitempty"`
	RelaysBelowIDs             []string `json:"relays_below_ids,omitempty"`
	OldChain                   []string `json:"old_chain,omitempty"`
	NewChain                   []string `json:"new_chain,omitempty"`
	RelaysConnected            int      `json:"relays_connected,omitempty"`
	RelaysMissing              int      `json:"relays_missing,omitempty"`
	HostsDirect                int      `json:"hosts_direct,omitempty"`
	UpstreamDroppedEventsTotal int64    `json:"upstream_dropped_events_total,omitempty"`
	FirstSeenAt                string   `json:"first_seen_at,omitempty"`
}

// OldRelay is the relay a re-routed host or relay lived on: the last element of the top-down
// old_chain ("" when there is no old chain).
func (dt Detail) OldRelay() string { return lastOf(dt.OldChain) }

// NewRelay is the relay it lives on now: the last element of the top-down new_chain.
func (dt Detail) NewRelay() string { return lastOf(dt.NewChain) }

func lastOf(c []string) string {
	if len(c) == 0 {
		return ""
	}
	return c[len(c)-1]
}

// Seq is a conn_seq on the wire. Decoding is fail-safe: anything that is not a JSON integer (a
// string, a float, a boolean, null, an integer too large for int64) decodes to 0, i.e. "absent",
// which every consumer treats as 1 (host.up / relay.up) instead of failing the whole frame.
type Seq int

// UnmarshalJSON never fails.
func (s *Seq) UnmarshalJSON(b []byte) error {
	var n int64
	if err := json.Unmarshal(b, &n); err != nil {
		*s = 0
		return nil
	}
	*s = Seq(n)
	return nil
}

// Event is an event of this node for the dispatcher: Name + the subject (Hostname for host.*,
// RelayID for relay.*, never both) + Detail. RelayChain is origin first (empty for an event about
// this node itself).
type Event struct {
	Name       string
	Hostname   string
	RelayID    string
	Status     string
	EnrolledAt string
	Timestamp  string
	RelayChain []string
	Detail     Detail
}

// RelayKinds are the relay.* kinds that carry a relay_id and no hostname.
var relayKinds = map[string]bool{
	"relay.failover": true, "relay.discover": true, "relay.up": true, "relay.reconnect": true,
	"relay.down": true, "relay.rerouted": true, "relay.removed": true, "relay.converged": true,
}

// IsRelayEvent reports whether name is one of the relay.* lifecycle kinds (keyed by relay_id).
func IsRelayEvent(name string) bool { return relayKinds[name] }

// vars renders the detail as template variables; counters that are always meaningful for a relay
// kind are always present, the others only when set.
func (dt Detail) vars(event, relayID string) map[string]string {
	out := map[string]string{}
	set := func(k, v string) {
		if v != "" {
			out[k] = v
		}
	}
	num := func(k string, n int, always bool) {
		if n != 0 || always {
			out[k] = strconv.Itoa(n)
		}
	}
	rel := IsRelayEvent(event)
	set("relay_id", relayID)
	set("mode", dt.Mode)
	set("cause", dt.Cause)
	set("reason", dt.Reason)
	set("instance_id", dt.InstanceID)
	set("previous_instance_id", dt.PreviousInstanceID)
	set("first_seen_at", dt.FirstSeenAt)
	set("relays_below_ids", strings.Join(dt.RelaysBelowIDs, ","))
	set("old_chain", strings.Join(dt.OldChain, ","))
	set("new_chain", strings.Join(dt.NewChain, ","))
	if strings.HasSuffix(event, ".rerouted") { // derived: the relay each chain ends on
		set("old_relay", dt.OldRelay())
		set("new_relay", dt.NewRelay())
	}
	num("conn_seq", int(dt.ConnSeq), false)
	num("hosts_routed", dt.HostsRouted, rel && event != "relay.failover")
	num("relays_below", dt.RelaysBelow, event == "relay.up" || event == "relay.reconnect")
	num("relays_connected", dt.RelaysConnected, event == "relay.converged")
	num("relays_missing", dt.RelaysMissing, event == "relay.converged")
	num("hosts_direct", dt.HostsDirect, event == "relay.converged")
	if dt.UpstreamDroppedEventsTotal != 0 || event == "relay.converged" {
		out["upstream_dropped_events_total"] = strconv.FormatInt(dt.UpstreamDroppedEventsTotal, 10)
	}
	return out
}

// eventEnvKeys are the template variables exported to shell hooks as SECAGENT_<NAME> when set.
var eventEnvKeys = []string{
	"relay_id", "mode", "cause", "reason", "instance_id", "previous_instance_id", "first_seen_at",
	"relays_below_ids", "old_relay", "new_relay", "old_chain", "new_chain", "conn_seq", "hosts_routed", "relays_below",
	"relays_connected", "relays_missing", "hosts_direct", "upstream_dropped_events_total",
}

var knownEvents = map[string]bool{
	"host.new": true, "host.up": true, "host.down": true, "host.reconnect": true, "host.discover": true,
	"host.rerouted": true, "host.removed": true, "host.conflict": true, "host.suspended": true, "host.resumed": true,
	"host.revoked": true, "host.deleted": true,
}

// KnownEvent reports whether a hook can ever fire for this event name (a warning, not an error, when
// not: a configuration may be written ahead of a later version).
func KnownEvent(name string) bool { return knownEvents[name] || relayKinds[name] }
