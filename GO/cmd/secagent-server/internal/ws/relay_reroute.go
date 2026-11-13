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
	"log"
	"sort"
	"strings"
	"sync"
	"time"

	"secagent-server/cmd/secagent-server/internal/dropreport"
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

// leftCarrier remembers, for a host that moved away from a relay (to another carrier, or to this node), the
// relay it left and when: a late host.down / host.removed of THAT relay is a legitimate echo of the move, not
// an attack, so its refusal is logged at [RELAY] level (recentMoveWindow).
type leftCarrier struct {
	relayID string
	at      time.Time
}

const recentMoveWindow = 10 * time.Minute

var (
	rerouteMemMu  sync.Mutex
	leftCarriers  = map[string]leftCarrier{}
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
	rememberLeftLocked(hostname, relayID)
	boundLocked(lastRoutes)
	lastRoutes[hostname] = hostRoute{relayID: relayID, chain: append([]string(nil), chain...)}
	rerouteMemMu.Unlock()
}

// rememberLeftLocked records the carrier a host is leaving when its route changes to another one.
func rememberLeftLocked(hostname, newRelay string) {
	if prev, ok := lastRoutes[hostname]; ok && prev.relayID != newRelay {
		boundLocked(leftCarriers)
		leftCarriers[hostname] = leftCarrier{relayID: prev.relayID, at: time.Now()}
	}
}

// noteRoute records the route of a host that came up (host.up/new/reconnect) or was listed by a relay
// (agent_list) and decides whether it is a re-route: it returns the cause and the old chain, "" when
// there is nothing to report (first route, same route). A host that was connected here and comes back
// through a relay is "indirect" whatever the previous route.
func noteRoute(hostname, relayID string, chain []string) (string, []string) {
	rerouteMemMu.Lock()
	prev, had := lastRoutes[hostname]
	rememberLeftLocked(hostname, relayID)
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
	if prev.relayID == relayID {
		// Same carrier (the relay the host lives on): only the path ABOVE it may have changed, which is a
		// reparent of that relay. It is announced once, as relay.rerouted, never as a host event (#244).
		return "", nil
	}
	// One event per change along the tree: when the old and the new route go through the SAME direct
	// peer, the move happened inside that peer's subtree, and the relay that saw it (the nearest common
	// ancestor of the two routes, at or below the peer) emits host.rerouted itself: this node trusts
	// the event the peer forwards (validated by reroutedRefusal) instead of announcing it twice. When
	// the two routes leave through different peers, this node is the nearest common ancestor and the
	// only one that can see the change: it emits. (The first hop of a route written without chain is
	// its owner.)
	if len(chain) > 0 && old[0] == chain[0] {
		return "", nil
	}
	return "moved", old
}

// noteLocalConnect runs when an agent connects here. A host this process knew behind a relay has just
// moved from that relay to this node: host.rerouted cause=direct.
func noteLocalConnect(hostname string) {
	rerouteMemMu.Lock()
	prev, had := lastRoutes[hostname]
	if had {
		boundLocked(leftCarriers)
		leftCarriers[hostname] = leftCarrier{relayID: prev.relayID, at: time.Now()}
	}
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

func copyChains(m map[string][]string) map[string][]string {
	out := make(map[string][]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
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

// ── Validation of a re-route announced by a child (T16b) ─────────────────────

// reasonNoKnownRoute is the refusal of a host.rerouted about a host this node has no route for.
const reasonNoKnownRoute = "has no route"

// Reasons of a refused host event (the wording is what operators and tests grep for).
const (
	reasonLocal     = "is connected locally"
	reasonElsewhere = "is routed through another relay"
)

// reasonLateElsewhere is the refusal of a replayed (late) host event for a host another peer or this node owns now.
const reasonLateElsewhere = "late event for a host owned elsewhere"

// rerouteRefuseInterval is the period of the aggregated "re-route refused" log.
const rerouteRefuseInterval = time.Minute

var (
	rerouteRefuseMu  sync.Mutex
	rerouteRefusals  = map[string]int64{} // "relay_id: reason" -> refused since the last report
	rerouteRefuseAgg = dropreport.New(rerouteRefuseInterval, flushRerouteRefusals)
)

func noteRerouteRefused(relayID, event, subject, reason string) {
	noteHostRefused(relayID, event, subject, reason, reason != reasonNoKnownRoute && reason != reasonLateElsewhere)
}

// rerouteImmediate remembers, per (level, relay, kind, reason), when the first occurrence was logged at once:
// an alarm is not held back for a minute, the repetitions are what gets aggregated.
var (
	rerouteImmediateMu sync.Mutex
	rerouteImmediate   = map[string]time.Time{}
)

// maxImmediateKeys bounds rerouteImmediate.
const maxImmediateKeys = 1024

// immediateRefusalLog reports whether this occurrence of key is the first of the current minute (it is then
// logged at once). The table is bounded AND purged: entries older than the minute are dropped when it fills up;
// if it is still full of live keys, a new key is NOT logged at once (it is only counted and aggregated), so a
// flood of distinct refusals can never turn into one log line per event.
func immediateRefusalLog(key string, now time.Time) bool {
	rerouteImmediateMu.Lock()
	defer rerouteImmediateMu.Unlock()
	if last, ok := rerouteImmediate[key]; ok {
		if now.Sub(last) < rerouteRefuseInterval {
			return false
		}
		rerouteImmediate[key] = now
		return true
	}
	if len(rerouteImmediate) >= maxImmediateKeys {
		for k, at := range rerouteImmediate {
			if now.Sub(at) >= rerouteRefuseInterval {
				delete(rerouteImmediate, k)
			}
		}
		if len(rerouteImmediate) >= maxImmediateKeys {
			return false
		}
	}
	rerouteImmediate[key] = now
	return true
}

// noteHostRefused counts a refused event; severe ones are logged as [SECURITY WARNING], the transient ones
// (a route this node does not know yet) as [RELAY], once per minute and per (relay, kind, reason).
func noteHostRefused(relayID, event, subject, reason string, severe bool) {
	level, prefix := "R|", "[RELAY]"
	if severe {
		level, prefix = "S|", "[SECURITY WARNING]"
	}
	key := level + relayID + ": " + event + ": " + reason
	now := time.Now()
	first := immediateRefusalLog(key, now)
	if first {
		log.Printf("%s event_forward %s refused: relay_id=%q subject=%q %s", prefix, event, relayID, subject, reason)
	}
	rerouteRefuseMu.Lock()
	if _, known := rerouteRefusals[key]; known || len(rerouteRefusals) < maxRefusalTriplets {
		rerouteRefusals[key]++
	} else {
		rerouteRefuseOverflow++ // a refusal that does not fit the tracked triplets is still COUNTED
	}
	rerouteRefuseMu.Unlock()
	rerouteRefuseAgg.Add(1)
}

// maxRefusalTriplets bounds the (relay, kind, reason) triplets tracked per minute; beyond it refusals are
// counted in one overflow counter.
const maxRefusalTriplets = 256

var rerouteRefuseOverflow int64

func flushRerouteRefusals(int64) {
	rerouteRefuseMu.Lock()
	r := rerouteRefusals
	rerouteRefusals = map[string]int64{}
	overflow := rerouteRefuseOverflow
	rerouteRefuseOverflow = 0
	rerouteRefuseMu.Unlock()
	if overflow > 0 {
		log.Printf("[SECURITY WARNING] %d refused event(s) in the last minute beyond the %d tracked (relay, kind, reason) triplets: counted here only", overflow, maxRefusalTriplets)
	}
	for k, n := range r {
		prefix := "[RELAY]"
		if strings.HasPrefix(k, "S|") {
			prefix = "[SECURITY WARNING]"
		}
		log.Printf("%s event refused (%s): %d event(s) in the last minute", prefix, k[2:], n)
	}
}

// hostSubtreeRefusal applies the T34 rule to a host event received from a child: the host must be in the
// subtree of that child. It returns the reason ("" = accepted) and whether it is a security alarm.
//   - a host connected HERE or routed through ANOTHER peer is out of the child's path: alarm ([SECURITY WARNING]);
//   - a host this node has no route for is refused too, but at [RELAY] level (normal after a restart of the
//     parent, before its snapshot, or while a relay is reparented): the route comes with the snapshot, the
//     agent_list or the host.up of the owner;
//   - host.conflict is informative and concerns relays BELOW the child: this node may never have routed the
//     host, so an unrouted host is accepted (routed elsewhere or local: refused);
//   - host.discover is the other exception: it precedes host.up (the route does not exist yet), so an UNROUTED
//     host is accepted if its relay_chain is coherent with the sender (already checked by handleEventForward:
//     it ends at the authenticated peer, every other element is a relay the peer declared). This grants the
//     child nothing it did not have (it can already claim any unrouted host with host.up) and the discover
//     writes no route and no state; it is still refused when the host is routed elsewhere or local.
//
// The route owner is the store's route, else the last route this process saw (the store forgets a host at the
// next agent_list of its relay).
func hostSubtreeRefusal(conn *RelayConnection, m RelayMessage) (string, bool) {
	if _, err := GetConnection(m.Hostname); err == nil {
		return reasonLocal, !leftBy(conn, m.Hostname)
	}
	owner, _ := lookupHostRoute(m.Hostname)
	if owner == "" {
		rerouteMemMu.Lock()
		owner = lastRoutes[m.Hostname].relayID
		rerouteMemMu.Unlock()
	}
	if owner == "" {
		if m.Event == "host.discover" || m.Event == "host.conflict" {
			return "", false
		}
		return reasonNoKnownRoute, false
	}
	if owner == conn.RelayID {
		return "", false
	}
	if _, mine := conn.descendants[owner]; mine {
		return "", false
	}
	return reasonElsewhere, !leftBy(conn, m.Hostname)
}

// leftBy reports whether the host recently moved away from the sender or from a relay below it: its late
// events are then the echo of a legitimate move.
func leftBy(conn *RelayConnection, hostname string) bool {
	rerouteMemMu.Lock()
	l, ok := leftCarriers[hostname]
	rerouteMemMu.Unlock()
	if !ok || time.Since(l.at) > recentMoveWindow {
		return false
	}
	if l.relayID == conn.RelayID {
		return true
	}
	_, below := conn.descendants[l.relayID]
	return below
}

// reroutedRefusal returns why a host.rerouted / relay.rerouted received from a child must be refused
// ("" = accepted). The shape (identifiers, lengths) was checked by eventShapeError; here the event is
// checked against what the sender is allowed to speak about:
//  1. relay.rerouted: new_chain is the reverse of the event's relay_chain (origin first);
//  2. every element of old_chain / new_chain is the peer or a relay it declared below it;
//  3. host.rerouted: the host has a route this node knows (a child cannot invent a re-route);
//  4. host.rerouted: old_relay / new_relay are the last element of the matching chain.
func reroutedRefusal(conn *RelayConnection, m RelayMessage) string {
	if m.Event == "relay.rerouted" && !sameChain(m.NewChain, reversed(m.RelayChain)) {
		return "new_chain is not the reverse of relay_chain"
	}
	for _, ch := range [][]string{m.OldChain, m.NewChain} {
		for _, id := range ch {
			if id == conn.RelayID {
				continue
			}
			if _, ok := conn.descendants[id]; !ok {
				return "chain element outside the sender's subtree"
			}
		}
	}
	if m.Event == "host.rerouted" {
		if m.OldRelay != m.Detail.OldRelay() || m.NewRelay != m.Detail.NewRelay() {
			return "old_relay/new_relay differ from the chains"
		}
		if !knownHostRoute(m.Hostname) {
			return reasonNoKnownRoute
		}
	}
	return ""
}

// knownHostRoute reports whether this node knows a route for the host: remembered by the process
// (survives the store dropping it at the next agent_list) or recorded in the store.
func knownHostRoute(hostname string) bool {
	rerouteMemMu.Lock()
	_, ok := lastRoutes[hostname]
	rerouteMemMu.Unlock()
	if ok {
		return true
	}
	rid, _ := lookupHostRoute(hostname)
	return rid != ""
}

// ── Memory of the relay chains (MAJEUR-2) ────────────────────────────────────

var (
	relayChainMemMu sync.Mutex
	lastRelayChains = map[string][]string{} // relay -> last top-down chain a snapshot declared for it
)

// mergeRememberedChains completes the chains the store knows (before is modified and returned) with the
// last ones this process saw: when the OLD parent of a reparented relay retires it (its replacing
// snapshot, or its link closing, clears the stored chain) before the NEW link's snapshot arrives, the
// store no longer remembers the old path, and the move would read as a first route.
func mergeRememberedChains(before map[string][]string) map[string][]string {
	if before == nil {
		before = map[string][]string{}
	}
	relayChainMemMu.Lock()
	defer relayChainMemMu.Unlock()
	for id, c := range lastRelayChains {
		if len(before[id]) == 0 {
			before[id] = append([]string(nil), c...)
		}
	}
	return before
}

// rememberRelayChains records the chains a snapshot declares (bounded like the route memory).
func rememberRelayChains(after map[string][]string) {
	relayChainMemMu.Lock()
	defer relayChainMemMu.Unlock()
	for id, c := range after {
		if len(c) == 0 {
			continue
		}
		boundLocked(lastRelayChains)
		lastRelayChains[id] = append([]string(nil), c...)
	}
}

// ── Timestamp of origin of a received event ──────────────────────────────────

// Bounds of an accepted timestamp of origin: not beyond now + timestampFutureSkew; and, for an event that is
// not a replay (late), not older than timestampMaxAge (a replayed event legitimately waited for the cut link).
const (
	timestampFutureSkew = 5 * time.Minute
	timestampMaxAge     = 7 * 24 * time.Hour
)

// originTimestamp returns the origin date of an event, normalized to RFC 3339 UTC, and whether it is usable.
func originTimestamp(raw string, late bool, now time.Time) (string, bool) {
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return "", false
	}
	if t.After(now.Add(timestampFutureSkew)) || (!late && t.Before(now.Add(-timestampMaxAge))) {
		return "", false
	}
	return t.UTC().Format(time.RFC3339), true
}

var (
	timestampClampMu  sync.Mutex
	timestampClamped  = map[string]int64{} // event kind -> count since the last report
	timestampClampAgg = dropreport.New(time.Minute, flushTimestampClamped)
)

func noteTimestampClamped(event string) {
	timestampClampMu.Lock()
	if _, known := timestampClamped[event]; known || len(timestampClamped) < 64 {
		timestampClamped[event]++
	}
	timestampClampMu.Unlock()
	timestampClampAgg.Add(1)
}

func flushTimestampClamped(int64) {
	timestampClampMu.Lock()
	c := timestampClamped
	timestampClamped = map[string]int64{}
	timestampClampMu.Unlock()
	for ev, n := range c {
		log.Printf("[RELAY] %s: %d event(s) in the last minute had a timestamp out of bounds (beyond now+%s, or older than %s and not replayed): replaced by the arrival time", ev, n, timestampFutureSkew, timestampMaxAge)
	}
}

// ── Routes created by an event survive a stale agent_list ────────────────────

// recentEventRouteGrace is how long a route created by a host.up / host.new / host.reconnect of a relay is kept
// when that relay's next agent_list does not list the host yet. An agent_list REPLACES all the routes of its
// relay, and is computed before the event it overtakes: the empty list a relay built just before one of its
// agents connected used to wipe the route the host.new had just created, until the host.up (the next, paced,
// event) restored it; an exec landing in that window failed with host_not_found. It is a variable for tests.
var recentEventRouteGrace = 300 * time.Millisecond

type recentEventRoute struct {
	host, relay string
	at          time.Time
}

var (
	recentRoutesMu    sync.Mutex
	recentEventRoutes []recentEventRoute // in arrival order, pruned from the front
)

// noteEventRoute remembers that a host.up / host.new / host.reconnect of relay just routed host.
func noteEventRoute(host, relay string) {
	recentRoutesMu.Lock()
	defer recentRoutesMu.Unlock()
	pruneRecentRoutesLocked(time.Now())
	// another relay routes the host now: the protection granted to the previous one ends (the host MOVED)
	out := recentEventRoutes[:0]
	for _, r := range recentEventRoutes {
		if r.host != host || r.relay == relay {
			out = append(out, r)
		}
	}
	recentEventRoutes = out
	if len(recentEventRoutes) < maxRerouteMemory {
		recentEventRoutes = append(recentEventRoutes, recentEventRoute{host: host, relay: relay, at: time.Now()})
	}
}

func pruneRecentRoutesLocked(now time.Time) {
	i := 0
	for i < len(recentEventRoutes) && now.Sub(recentEventRoutes[i].at) >= recentEventRouteGrace {
		i++
	}
	if i > 0 {
		recentEventRoutes = append(recentEventRoutes[:0], recentEventRoutes[i:]...)
	}
}

// agentListVersion numbers the agent_lists of each relay: a deferred expiry only applies if no newer list came.
var (
	agentListVersionMu sync.Mutex
	agentListVersion   = map[string]uint64{}
	agentListKept      = map[string][]string{} // relay -> its last agent_list, while a recent event route is being kept
)

// withRecentEventRoutes returns the agent_list of relay completed with the hosts an event routed to it less
// than recentEventRouteGrace ago (the list is the truth, but it can be older than the event). When hosts were
// kept this way, the route is dropped when the grace ends even if no further list arrives (the list of a quiet
// relay can be minutes away): staleness is bounded by the grace, never by the list interval.
func withRecentEventRoutes(relay string, listed []string, apply func(relay string, hosts []string)) []string {
	recentRoutesMu.Lock()
	now := time.Now()
	pruneRecentRoutesLocked(now)
	out := listed
	kept := false
	if len(recentEventRoutes) > 0 {
		have := make(map[string]struct{}, len(listed))
		for _, h := range listed {
			have[h] = struct{}{}
		}
		for _, r := range recentEventRoutes {
			if r.relay != relay {
				continue
			}
			// only a route that still belongs to this relay is protected: a host that has moved to another
			// relay must not be written back to this one (and then lost when the grace ends)
			if owner, _ := lookupHostRoute(r.host); owner != "" && owner != relay {
				continue
			}
			if _, ok := have[r.host]; !ok {
				have[r.host] = struct{}{}
				out = append(out[:len(out):len(out)], r.host)
				kept = true
			}
		}
	}
	recentRoutesMu.Unlock()

	agentListVersionMu.Lock()
	agentListVersion[relay]++
	v := agentListVersion[relay]
	delete(agentListKept, relay) // a copy of an OLDER list must not survive a newer one
	var original []string
	if kept {
		original = append([]string(nil), listed...)
		agentListKept[relay] = original
	}
	agentListVersionMu.Unlock()
	if kept {
		time.AfterFunc(recentEventRouteGrace+20*time.Millisecond, func() {
			// the check and the write are ONE step under the lock: a newer list increments the version under it
			// BEFORE it writes, so it is never overwritten by this expiry
			agentListVersionMu.Lock()
			defer agentListVersionMu.Unlock()
			if agentListVersion[relay] != v {
				return
			}
			delete(agentListKept, relay)
			if IsRelayConnected(relay) {
				apply(relay, original) // the grace is over and no newer list came: the list stands as it was
			}
		})
	}
	return out
}

// dropRecentEventRoute ends the protection of a route when the relay reports the host DOWN: the host that has
// just disconnected must not stay routed for the rest of the grace. If the route was being kept, the relay's last
// agent_list is applied at once.
func dropRecentEventRoute(host, relay string) {
	recentRoutesMu.Lock()
	found := false
	out := recentEventRoutes[:0]
	for _, r := range recentEventRoutes {
		if r.host == host && r.relay == relay {
			found = true
			continue
		}
		out = append(out, r)
	}
	recentEventRoutes = out
	recentRoutesMu.Unlock()
	if !found {
		return
	}
	agentListVersionMu.Lock()
	list, kept := agentListKept[relay]
	if kept {
		delete(agentListKept, relay)
		agentListVersion[relay]++ // the deferred expiry is now useless
	}
	agentListVersionMu.Unlock()
	if kept && IsRelayConnected(relay) {
		applyAgentListRoutes(relay, list)
	}
}
