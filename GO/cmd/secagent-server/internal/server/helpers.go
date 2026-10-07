package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"

	"secagent-server/cmd/secagent-server/internal/handlers"
	"secagent-server/cmd/secagent-server/internal/repeater"
	"secagent-server/cmd/secagent-server/internal/storage"
	"secagent-server/cmd/secagent-server/internal/ws"
)

// handleHealth answers the liveness probe. It is PUBLIC (no authentication): it exposes only the
// boolean "degraded" (a link was refused permanently), never relay ids, states or reasons, which
// would disclose the topology. The detail is in the admin status (port 7771) and `server status`.
// The HTTP status stays 200 even when degraded (a node cut off from its parent still serves its
// agents and descendants: it must not be restarted by a liveness probe).
func (n *Node) handleHealth(w http.ResponseWriter, r *http.Request) {
	body := map[string]interface{}{"status": "ok", "timestamp": time.Now().Unix()}
	n.instMu.Lock()
	if n.instRole != "" {
		body["role"], body["instance_id"] = n.instRole, n.instID
	}
	n.instMu.Unlock()
	if n.healthLinks != nil {
		if l := n.healthLinks(); !l.Empty() {
			body["degraded"] = l.Degraded
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		log.Printf("handleHealth write: %v", err)
	}
}

// isListening reports whether something accepts connections on the listener's EFFECTIVE address
// (an unspecified host such as ":7770" or "[::]:7770" is dialed through the loopback).
func isListening(a net.Addr) bool {
	host, port, err := net.SplitHostPort(a.String())
	if err != nil {
		return false
	}
	if ip := net.ParseIP(host); host == "" || (ip != nil && ip.IsUnspecified()) {
		host = "127.0.0.1"
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), 1*time.Second)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// directAgents lists the agents connected directly to this node (1 level).
func directAgents() []repeater.AgentInfo {
	hosts := ws.GetConnectedHostnames()
	out := make([]repeater.AgentInfo, 0, len(hosts))
	for _, h := range hosts {
		out = append(out, repeater.AgentInfo{Hostname: h, Status: "connected"})
	}
	return out
}

// buildSnapshot describes the subtree of this relay for topology_snapshot:
// direct agents plus the descendant relays (and their routed agents).
// relay_chain always starts with this relay's own id (cf. ARCHITECTURE §23.2).
func buildSnapshot(selfID string, st *storage.Store) repeater.Snapshot {
	snap := repeater.Snapshot{}
	for _, h := range ws.GetConnectedHostnames() {
		snap.Agents = append(snap.Agents, repeater.TopoAgent{Hostname: h, RelayID: selfID, RelayChain: []string{selfID}})
	}
	nodes, err := st.ListValidRelayNodes()
	if err != nil {
		log.Printf("[REPEATER] snapshot: list relay nodes: %v", err)
		return snap
	}
	groupVars, gvErr := st.ListRelayGroupVars()
	if gvErr != nil {
		log.Printf("[REPEATER] snapshot: group vars: %v", gvErr)
	}
	// The path to a relay below us is the one learned from the child that declared it
	// (["r2","r3"]); a direct child has none stored. Prefixed with this node, it is origin-last:
	// [self, r2, r3]. Using [self, relay] for every relay would flatten the tree.
	chains, chErr := st.ListRelayChains()
	if chErr != nil {
		log.Printf("[REPEATER] snapshot: relay chains: %v", chErr)
	}
	chainOf := func(relayID string) []string {
		below := chains[relayID]
		if len(below) == 0 || below[len(below)-1] != relayID {
			below = []string{relayID}
		}
		return append([]string{selfID}, below...)
	}
	for _, n := range nodes {
		chain := chainOf(n.RelayID)
		entry := repeater.TopoRelay{RelayID: n.RelayID, RelayChain: chain}
		if raw, ok := groupVars[n.RelayID]; ok {
			var gv map[string]any
			if json.Unmarshal([]byte(raw), &gv) == nil {
				entry.GroupVars = gv
			}
		}
		snap.Relays = append(snap.Relays, entry)
		hosts, herr := st.ListRelayRouting(n.RelayID)
		if herr != nil {
			log.Printf("[REPEATER] snapshot: routing for %q: %v", n.RelayID, herr)
			continue
		}
		for _, h := range hosts {
			snap.Agents = append(snap.Agents, repeater.TopoAgent{Hostname: h, RelayID: n.RelayID, RelayChain: chain})
		}
	}
	return snap
}

// registerPullRelay idempotently records a relay that connected to us (mode=pull).
// An existing declaration (e.g. admin-created) is kept: only its status/last_seen change.
func registerPullRelay(st *storage.Store, relayID string) error {
	existing, err := st.GetRelayNode(relayID)
	if err != nil {
		return fmt.Errorf("get relay node: %w", err)
	}
	now := time.Now().UTC().Unix()
	if existing != nil {
		return st.UpdateRelayStatus(relayID, "connected", now)
	}
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return fmt.Errorf("generate id: %w", err)
	}
	return st.UpsertRelayNode(storage.RelayNode{
		ID: hex.EncodeToString(b), RelayID: relayID, Mode: "pull", Status: "connected", LastSeen: &now,
	})
}

// pushStarter starts the dial-out of one push child.
type pushStarter interface {
	Start(repeater.DialTarget) error
}

// startPushDialers starts a Dialer for every relay_nodes row with mode=push. An invalid or
// undecryptable row is skipped with a warning (the token is never logged).
func startPushDialers(st *storage.Store, mgr pushStarter) {
	nodes, err := st.ListRelayNodes()
	if err != nil {
		log.Printf("[RELAY] cannot list relay nodes for push dial-out: %v", err)
		return
	}
	for _, n := range nodes {
		if n.Mode != "push" {
			continue
		}
		token, terr := handlers.OpenPushToken(n.RelayID, n.TokenSecret)
		if terr != nil {
			log.Printf("[WARN] push relay %q skipped: %v", n.RelayID, terr)
			continue
		}
		if serr := mgr.Start(repeater.DialTarget{RelayID: n.RelayID, URLs: n.URLs, Token: token}); serr != nil {
			if errors.Is(serr, repeater.ErrForbiddenTarget) {
				// the row predates the guard or was written around the API: never dialed
				log.Printf("[SECURITY WARNING] push relay %q not dialed: a stored address is forbidden (%v)", n.RelayID, serr)
				continue
			}
			log.Printf("[WARN] push relay %q skipped: %v", n.RelayID, serr)
			continue
		}
		log.Printf("[RELAY] dial-out started: relay_id=%q mode=push", n.RelayID)
	}
}

// queueUpstream hands an event to the uplink without ever blocking a handler.
func queueUpstream(ch chan<- repeater.Event, ev repeater.Event) {
	select {
	case ch <- ev:
	default:
		log.Printf("[REPEATER] upstream event queue full, event %s dropped", ev.Event)
	}
}

// agentJTICheck builds the /ws/agent handshake check (#169, SECURITY.md §4/§5) on top of the
// store. A token is refused when its JTI is blacklisted (revoked agent), when the agent is
// unknown, or when its JTI is no longer the agent's current one (replaced by a re-enrollment, a
// refresh or a rekey). A token validated with the PREVIOUS JWT secret (rotation grace period)
// legitimately carries an older JTI: it only has to be non-blacklisted. Any store error refuses
// the connection (fail closed).
func agentJTICheck(store *storage.Store) func(hostname, jti string, usedPrevious bool) error {
	return func(hostname, jti string, usedPrevious bool) error {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		revoked, err := store.IsJTIBlacklisted(ctx, jti)
		if err != nil {
			return fmt.Errorf("blacklist_check_failed: %w", err)
		}
		if revoked {
			return fmt.Errorf("token_revoked")
		}
		agent, err := store.GetAgent(ctx, hostname)
		if err != nil {
			return fmt.Errorf("agent_lookup_failed: %w", err)
		}
		if agent == nil {
			return fmt.Errorf("unknown_agent")
		}
		if agent.Revoked { // the persistent revocation does not depend on the blacklist retention (#193)
			return fmt.Errorf("token_revoked")
		}
		if !usedPrevious && agent.TokenJTI != jti {
			return fmt.Errorf("token_replaced")
		}
		return nil
	}
}
