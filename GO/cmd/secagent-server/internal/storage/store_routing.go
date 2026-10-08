// store_routing.go — hostname routing of the relay tree. The routes are VOLATILE: rebuilt by the
// topology snapshots when the children (re)connect, never written to the state file.
package storage

import (
	"fmt"
	"sort"
	"time"
)

// HopTypeRelay is the only hop type: the next hop of a route is a relay.
const HopTypeRelay = "relay"

// RelayRoute is one routing entry: hostname → declaring relay, with the path to reach it.
type RelayRoute struct {
	Hostname   string
	RelayID    string   // declaring relay
	HopType    string   // "relay"
	RelayChain []string // top-down path from this node's direct child to RelayID
	UpdatedAt  int64
	// Suspended is what the relay holding the agent reported (informative, #180): this node never
	// refuses a task on the strength of it.
	Suspended bool
}

// NextHop returns the direct child relay a task for this host is sent to.
func (r RelayRoute) NextHop() string {
	if len(r.RelayChain) > 0 {
		return r.RelayChain[0]
	}
	return r.RelayID
}

func (r RelayRoute) clone() RelayRoute {
	r.RelayChain = append([]string(nil), r.RelayChain...)
	return r
}

// requireRelay: a route needs its relay node to exist (what the former foreign key enforced).
func (s *Store) requireRelay(relayID string) error {
	if _, ok := s.snap().RelayNode(relayID); !ok {
		return fmt.Errorf("unknown relay %q", relayID)
	}
	return nil
}

// UpsertRelayRouting sets hostname → relayID (chain [relayID]).
func (s *Store) UpsertRelayRouting(hostname, relayID string) error {
	if err := s.requireRelay(relayID); err != nil {
		return fmt.Errorf("UpsertRelayRouting %q→%q: %w", hostname, relayID, err)
	}
	s.mu.Lock()
	s.routes[hostname] = RelayRoute{Hostname: hostname, RelayID: relayID, HopType: HopTypeRelay, RelayChain: []string{relayID}, UpdatedAt: time.Now().UTC().Unix()}
	s.mu.Unlock()
	return nil
}

// GetRelayForHostname returns the relay that routes hostname, or "" when unrouted.
func (s *Store) GetRelayForHostname(hostname string) (string, error) {
	s.mu.RLock()
	r, ok := s.routes[hostname]
	s.mu.RUnlock()
	if !ok {
		return "", nil
	}
	if !hostnameShape.MatchString(hostname) || !ValidRelayID(r.RelayID) {
		warnIgnoredOnce("relay route", hostname)
		return "", nil
	}
	return r.RelayID, nil
}

// BulkUpsertRelayRouting replaces ALL the routes of relayID by hostnames (atomically, under the
// store mutex). A hostname already routed to another relay is taken over.
func (s *Store) BulkUpsertRelayRouting(relayID string, hostnames []string) error {
	if err := s.requireRelay(relayID); err != nil {
		return fmt.Errorf("BulkUpsertRelayRouting: %w", err)
	}
	now := time.Now().UTC().Unix()
	s.mu.Lock()
	var old []string
	for h, r := range s.routes {
		if r.RelayID == relayID {
			delete(s.routes, h)
			old = append(old, h)
		}
	}
	kept := make(map[string]struct{}, len(hostnames))
	for _, h := range hostnames {
		if h == "" {
			continue
		}
		kept[h] = struct{}{}
		s.routes[h] = RelayRoute{Hostname: h, RelayID: relayID, HopType: HopTypeRelay, RelayChain: []string{relayID}, UpdatedAt: now}
	}
	for _, h := range old { // the flag of a host that stays survives the periodic agent_list
		if _, still := kept[h]; !still {
			delete(s.remoteSuspended, h)
		}
	}
	s.mu.Unlock()
	return nil
}

// DeleteRelayRoutingByRelay removes every route of relayID.
func (s *Store) DeleteRelayRoutingByRelay(relayID string) error {
	s.mu.Lock()
	for h, r := range s.routes {
		if r.RelayID == relayID {
			delete(s.routes, h)
			delete(s.remoteSuspended, h)
		}
	}
	s.mu.Unlock()
	return nil
}

// ListRelayRouting returns the hostnames routed to relayID, sorted.
func (s *Store) ListRelayRouting(relayID string) ([]string, error) {
	var out []string
	s.mu.RLock()
	for h, r := range s.routes {
		if r.RelayID != relayID {
			continue
		}
		if !hostnameShape.MatchString(h) {
			warnIgnoredOnce("relay route", h)
			continue
		}
		out = append(out, h)
	}
	s.mu.RUnlock()
	sort.Strings(out)
	return out, nil
}

// GetRelayRoute returns the route of hostname, or (nil, nil).
func (s *Store) GetRelayRoute(hostname string) (*RelayRoute, error) {
	s.mu.RLock()
	r, ok := s.routes[hostname]
	s.mu.RUnlock()
	if !ok {
		return nil, nil
	}
	if !validRoute(r.Hostname, r.RelayID, r.RelayChain) { // hostile entry: never served
		warnIgnoredOnce("relay route", hostname)
		return nil, nil
	}
	c := r.clone()
	return &c, nil
}

// GetNextHopForHostname returns the direct child relay to dispatch a task for hostname to.
// Returns ("", nil) when the hostname is unrouted.
func (s *Store) GetNextHopForHostname(hostname string) (string, error) {
	r, err := s.GetRelayRoute(hostname)
	if err != nil || r == nil {
		return "", err
	}
	return r.NextHop(), nil
}

// UpsertRelayRoute sets hostname → (declaring relay, chain); last arrival wins. It returns the
// previous route (nil if none) so the caller can detect a next-hop change.
func (s *Store) UpsertRelayRoute(hostname, relayID string, chain []string) (prev *RelayRoute, err error) {
	if err := s.requireRelay(relayID); err != nil {
		return nil, fmt.Errorf("UpsertRelayRoute %q→%q: %w", hostname, relayID, err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if old, ok := s.routes[hostname]; ok && validRoute(old.Hostname, old.RelayID, old.RelayChain) {
		c := old.clone()
		prev = &c
	}
	s.routes[hostname] = RelayRoute{Hostname: hostname, RelayID: relayID, HopType: HopTypeRelay, RelayChain: append([]string(nil), chain...), UpdatedAt: time.Now().UTC().Unix()}
	return prev, nil
}

// RouteChain sets the chain of an existing route.
type RouteChain struct {
	Hostname string
	RelayID  string
	Chain    []string
	// Suspended is the flag carried by the snapshot (the child's snapshot is authoritative: an agent
	// absent from the flag is not suspended; a child that does not know the field sends false).
	Suspended bool
}

// SetRelayRouteChains updates the chains of existing routes (all or none: memory, one lock).
func (s *Store) SetRelayRouteChains(entries []RouteChain) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range entries {
		if r, ok := s.routes[e.Hostname]; ok && r.RelayID == e.RelayID {
			r.RelayChain = append([]string(nil), e.Chain...)
			s.routes[e.Hostname] = r
		}
		if e.Suspended {
			s.remoteSuspended[e.Hostname] = true
		} else {
			delete(s.remoteSuspended, e.Hostname)
		}
	}
	return nil
}

// SetRemoteSuspended records the suspension of a host below this node, as reported by the relay that
// holds it (event host.suspended / host.resumed). Informative only (#180).
func (s *Store) SetRemoteSuspended(hostname string, suspended bool) {
	s.mu.Lock()
	if suspended {
		s.remoteSuspended[hostname] = true
	} else {
		delete(s.remoteSuspended, hostname)
	}
	s.mu.Unlock()
}

// IsRemoteSuspended reports the suspension reported for a host below this node (informative).
func (s *Store) IsRemoteSuspended(hostname string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.remoteSuspended[hostname]
}

// ListRelayRoutes returns every valid route, sorted by hostname.
func (s *Store) ListRelayRoutes() ([]RelayRoute, error) {
	var out []RelayRoute
	s.mu.RLock()
	for _, r := range s.routes {
		if !validRoute(r.Hostname, r.RelayID, r.RelayChain) {
			warnIgnoredOnce("relay route", r.Hostname)
			continue
		}
		c := r.clone()
		c.Suspended = s.remoteSuspended[r.Hostname]
		out = append(out, c)
	}
	s.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Hostname < out[j].Hostname })
	return out, nil
}
