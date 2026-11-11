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

// PrevRoute is the route of a host before an upsert replaced it.
type PrevRoute struct {
	RelayID string
	Chain   []string // top-down; may be empty for a route written by a snapshot that carried no chain
}

var (
	rerouteHooksMu    sync.RWMutex
	routeUpsertPrevFn func(hostname, relayID string, chain []string) (*PrevRoute, error)
	relayChainsFn2    func() map[string][]string
	hostRouteChainFn  func(hostname string) (string, []string)
)

// SetRelayRouteUpsertPrevFunc sets a route upsert that returns the previous route (nil if none). It
// takes precedence over SetRelayRouteUpsertFunc: without the previous route nothing can be re-routed.
func SetRelayRouteUpsertPrevFunc(fn func(hostname, relayID string, chain []string) (*PrevRoute, error)) {
	rerouteHooksMu.Lock()
	routeUpsertPrevFn = fn
	rerouteHooksMu.Unlock()
}

// SetRelayChainsFunc sets the reader of the recorded top-down chains of the relays below this node,
// read BEFORE a snapshot rewrites them (relay.rerouted).
func SetRelayChainsFunc(fn func() map[string][]string) {
	rerouteHooksMu.Lock()
	relayChainsFn2 = fn
	rerouteHooksMu.Unlock()
}

// SetRelayHostRouteChainFunc sets the reader of the recorded route of a host: the relay it lives on
// and the top-down chain ("" when unrouted). Used to describe the old route of a host.rerouted direct.
func SetRelayHostRouteChainFunc(fn func(hostname string) (string, []string)) {
	rerouteHooksMu.Lock()
	hostRouteChainFn = fn
	rerouteHooksMu.Unlock()
}

// maxRerouteMemory bounds the two in-memory sets below (hostnames come from authenticated peers and
// agents, but a fleet is finite: past the bound an arbitrary entry is forgotten, which can only
// cost one event).
const maxRerouteMemory = 65536

var (
	rerouteMemMu   sync.Mutex
	recentlyLocal  = map[string]struct{}{} // hosts that were connected HERE and are not any more
	directReported = map[string]string{}   // host -> relay of the stale route a direct was already reported for
)

func boundLocked[V any](m map[string]V) {
	for len(m) >= maxRerouteMemory {
		for k := range m {
			delete(m, k)
			break
		}
	}
}

// noteLocalConnect runs when an agent connects here. A host that still has a route through a relay
// has just moved from that relay to this node: host.rerouted cause=direct (once per stale route).
func noteLocalConnect(hostname string) {
	rerouteMemMu.Lock()
	delete(recentlyLocal, hostname)
	rerouteMemMu.Unlock()
	rid, _ := lookupHostRoute(hostname)
	if rid == "" {
		return
	}
	rerouteMemMu.Lock()
	if directReported[hostname] == rid {
		rerouteMemMu.Unlock()
		return
	}
	boundLocked(directReported)
	directReported[hostname] = rid
	rerouteMemMu.Unlock()

	old := []string{rid}
	rerouteHooksMu.RLock()
	fn := hostRouteChainFn
	rerouteHooksMu.RUnlock()
	if fn != nil {
		if _, ch := fn(hostname); len(ch) > 0 {
			old = ch
		}
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

// takeRecentlyLocal reports (and forgets) that hostname was connected here before.
func takeRecentlyLocal(hostname string) bool {
	rerouteMemMu.Lock()
	defer rerouteMemMu.Unlock()
	_, ok := recentlyLocal[hostname]
	delete(recentlyLocal, hostname)
	return ok
}

// rerouteCause decides the cause of the route change of a host that comes up through a relay.
// prev is the route before the upsert (nil: none). It returns the cause and the old chain, "" when
// there is nothing to report (first route, same route).
func rerouteCause(hostname, origin string, newChain []string, prev *PrevRoute) (string, []string) {
	rerouteMemMu.Lock()
	delete(directReported, hostname) // the route is rewritten: a later direct is a new change
	rerouteMemMu.Unlock()
	if takeRecentlyLocal(hostname) {
		return "indirect", []string{localRelayID()}
	}
	if prev == nil {
		return "", nil
	}
	old := prev.Chain
	if len(old) == 0 {
		// route written by a snapshot without chain: only the owner is known
		if prev.RelayID == origin {
			return "", nil
		}
		old = []string{prev.RelayID}
	}
	if sameChain(old, newChain) {
		return "", nil
	}
	return "moved", old
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
