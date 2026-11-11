// SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
// SPDX-License-Identifier: AGPL-3.0-or-later

package ws

// Rerouting events (#244): host.rerouted (a host changed route: moved | direct | indirect) and
// relay.rerouted (a relay below this node changed path between two snapshots).
//
// Chains are TOP-DOWN, as stored in relay_routing / relay_chains: they start at the direct peer of
// this node and end at the relay the host (or the relay itself) lives on. The "old_relay" and
// "new_relay" variables are therefore the LAST element of old_chain / new_chain.
//
// Nothing is remembered across a restart or a failover: the routes are volatile, a first route is
// never a re-route, so a failover (a -> b) gives no event at all.

import (
	"sort"
	"sync"

	"secagent-server/cmd/secagent-server/internal/hooks"
)

var (
	rerouteHooksMu sync.RWMutex
	relayChainsFn2 func() map[string][]string
)

// SetRelayChainsFunc sets the reader of the recorded top-down chains of the relays below this node,
// read BEFORE a snapshot rewrites them (relay.rerouted).
func SetRelayChainsFunc(fn func() map[string][]string) {
	rerouteHooksMu.Lock()
	relayChainsFn2 = fn
	rerouteHooksMu.Unlock()
}

// maxRerouteMemory bounds the in-memory sets below (hostnames come from authenticated peers and
// agents, but a fleet is finite: past the bound an arbitrary entry is forgotten, which can only
// cost one event).
const maxRerouteMemory = 100000

// hostRoute is the last route this process saw for a host: the relay it lives on and the top-down chain.
type hostRoute struct {
	relayID string
	chain   []string
}

var (
	rerouteMemMu  sync.Mutex
	lastRoutes    = map[string]hostRoute{} // host -> last route seen by THIS process (survives the route's removal from the store)
	recentlyLocal = map[string]struct{}{}  // hosts that were connected HERE and are not any more
)

func boundLocked[V any](m map[string]V) {
	for len(m) >= maxRerouteMemory {
		for k := range m {
			delete(m, k)
			break
		}
	}
}

// The route memory is deliberately NOT the store: the store forgets a host as soon as its relay's next
// agent_list no longer lists it (a few milliseconds after the host left), so a move could never be told
// from a first route. The memory lives as long as the process and is empty after a restart or a
// failover: a first route is never a re-route, so a failover (a -> b) gives no event at all.

// noteSnapshotRoute records a route declared by a snapshot, silently (a snapshot never gives a
// host.rerouted: a reparent is one relay.rerouted per relay).
func noteSnapshotRoute(hostname, relayID string, chain []string) {
	rerouteMemMu.Lock()
	boundLocked(lastRoutes)
	lastRoutes[hostname] = hostRoute{relayID: relayID, chain: append([]string(nil), chain...)}
	rerouteMemMu.Unlock()
}

// noteRoute records the route of a host that came up (host.up/new/reconnect) or was listed by a relay
// (agent_list) and decides whether it is a re-route: it returns the cause and the old chain, "" when
// there is nothing to report (first route, same route). A host that was connected here and comes back
// through a relay is "indirect" whatever the previous route.
func noteRoute(hostname, relayID string, chain []string) (string, []string) {
	rerouteMemMu.Lock()
	prev, had := lastRoutes[hostname]
	boundLocked(lastRoutes)
	lastRoutes[hostname] = hostRoute{relayID: relayID, chain: append([]string(nil), chain...)}
	_, wasLocal := recentlyLocal[hostname]
	delete(recentlyLocal, hostname)
	rerouteMemMu.Unlock()
	if wasLocal {
		return "indirect", []string{localRelayID()}
	}
	if !had {
		return "", nil
	}
	old := prev.chain
	if len(old) == 0 {
		old = []string{prev.relayID}
	}
	if prev.relayID == relayID && (len(prev.chain) == 0 || sameChain(prev.chain, chain)) {
		return "", nil
	}
	return "moved", old
}

// noteLocalConnect runs when an agent connects here. A host this process knew behind a relay has just
// moved from that relay to this node: host.rerouted cause=direct.
func noteLocalConnect(hostname string) {
	rerouteMemMu.Lock()
	prev, had := lastRoutes[hostname]
	delete(lastRoutes, hostname)
	delete(recentlyLocal, hostname)
	rerouteMemMu.Unlock()
	if !had {
		return
	}
	old := prev.chain
	if len(old) == 0 {
		old = []string{prev.relayID}
	}
	emitEvent(hooks.Event{Name: "host.rerouted", Hostname: hostname, Detail: hooks.Detail{
		Cause: "direct", OldChain: old, NewChain: []string{localRelayID()}}})
}

// noteLocalDisconnect remembers a host that was connected here: if it comes back through a relay
// the route change is an "indirect".
func noteLocalDisconnect(hostname string) {
	rerouteMemMu.Lock()
	boundLocked(recentlyLocal)
	recentlyLocal[hostname] = struct{}{}
	rerouteMemMu.Unlock()
}

func sameChain(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func reversed(c []string) []string {
	out := make([]string, len(c))
	for i, id := range c {
		out[len(c)-1-i] = id
	}
	return out
}

// emitHostRerouted emits host.rerouted for a host that came up through a relay. relayChain is the
// event chain as received (origin first, peer last).
func emitHostRerouted(hostname, cause string, relayChain, oldChain, newChain []string) {
	emitEvent(hooks.Event{Name: "host.rerouted", Hostname: hostname, RelayChain: append([]string(nil), relayChain...),
		Detail: hooks.Detail{Cause: cause, OldChain: append([]string(nil), oldChain...), NewChain: append([]string(nil), newChain...)}})
}

// chainMove is a relay whose path changed between two snapshots.
type chainMove struct {
	RelayID string
	Old     []string
	New     []string
}

// snapshotDiff compares the chains the node knew (before) with the ones a snapshot declares (after)
// and returns, sorted by relay id, the relays whose chain changed. A relay with no known chain is
// new (a first route is not a re-route); a relay absent from the snapshot is not moved. It compares
// the chain TABLE of the node, not one link: a relay that went from descendant of a peer to direct
// peer (old [dmz1 dmz2], new [dmz2]) is a move.
func snapshotDiff(before, after map[string][]string) []chainMove {
	var moves []chainMove
	for id, nc := range after {
		oc := before[id]
		if len(oc) == 0 || len(nc) == 0 || sameChain(oc, nc) {
			continue
		}
		moves = append(moves, chainMove{RelayID: id, Old: append([]string(nil), oc...), New: append([]string(nil), nc...)})
	}
	sort.Slice(moves, func(i, j int) bool { return moves[i].RelayID < moves[j].RelayID })
	return moves
}

// knownRelayChains returns a copy of the recorded chains (nil when not wired).
func knownRelayChains() map[string][]string {
	rerouteHooksMu.RLock()
	fn := relayChainsFn2
	rerouteHooksMu.RUnlock()
	if fn == nil {
		return nil
	}
	return fn()
}

// hostsThrough counts, per relay, the hosts of a snapshot whose path goes through it (the relay is in
// the host's chain: the hosts behind its own children count for it too).
func hostsThrough(agents []RelayAgentInfo) map[string]int {
	out := map[string]int{}
	for _, a := range agents {
		for _, id := range a.RelayChain {
			out[id]++
		}
	}
	return out
}

// emitRelayRerouted emits one relay.rerouted per moved relay. hostsRouted gives the number of hosts
// the snapshot routes through each relay.
func emitRelayRerouted(moves []chainMove, hostsRouted func(id string) int) {
	for _, m := range moves {
		emitEvent(hooks.Event{Name: "relay.rerouted", RelayID: m.RelayID, RelayChain: reversed(m.New), Detail: hooks.Detail{
			OldChain: m.Old, NewChain: m.New, HostsRouted: hostsRouted(m.RelayID)}})
	}
}

var (
	linkEstablishedMu sync.RWMutex
	linkEstablishedFn func(relayID string, below []string)
)

// SetRelayLinkEstablishedFunc sets the notification of the FIRST accepted snapshot of a child link
// (the moment relay.up / relay.reconnect is emitted): the peer and the relays it declares below it.
// The convergence tracker (relay.converged) counts the relays that are back through it. fn must not block.
func SetRelayLinkEstablishedFunc(fn func(relayID string, below []string)) {
	linkEstablishedMu.Lock()
	linkEstablishedFn = fn
	linkEstablishedMu.Unlock()
}

func notifyLinkEstablished(relayID string, relays []RelayTopoEntry) {
	linkEstablishedMu.RLock()
	fn := linkEstablishedFn
	linkEstablishedMu.RUnlock()
	if fn == nil {
		return
	}
	below := make([]string, 0, len(relays))
	for _, r := range relays {
		below = append(below, r.RelayID)
	}
	fn(relayID, below)
}
