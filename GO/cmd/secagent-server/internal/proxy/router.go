// Package proxy implements the relay router for secagent-server.
//
// ProxyRouter routes exec/upload/fetch operations to downstream relays.
// All routing uses the WebSocket pull path: relays connect to this server
// via /ws/relay and the router dispatches tasks over those connections.
//
// Push-mode relay entries (relay_nodes.mode = "push") are preserved in the
// DB for future use (#140) but are currently inert: a relay registered as
// push that is not connected via /ws/relay is treated as offline.
//
// Routing decision:
//  1. Look up hostname in relay_routing table → find relay_id.
//  2. If relay is connected via /ws/relay (ws.IsRelayConnected) → dispatch WS.
//  3. Otherwise → return relay_offline error.
//
// The WS dispatch functions are injectable for unit-test isolation.
package proxy

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"secagent-server/cmd/secagent-server/internal/storage"
	"secagent-server/cmd/secagent-server/internal/ws"
)

// ErrHostNotFound is returned when no relay owns the requested hostname.
var ErrHostNotFound = errors.New("host_not_found")

// RelayAgentEntry is an agent discovered via relay_routing + relay_nodes status.
type RelayAgentEntry struct {
	Hostname    string
	RelayID     string
	RelayStatus string // relay-level: "connected" | "disconnected"
	LastSeen    int64  // relay last_seen Unix timestamp (0 if never)
}

// ProxyRouter routes exec/upload/fetch operations to the appropriate relay.
type ProxyRouter struct {
	store *storage.Store

	// Injectable WS functions — overridden in unit tests to avoid WS global state.
	isRelayConnected      func(relayID string) bool
	dispatchToRelay       func(relayID string, msg ws.RelayMessage) (chan ws.RelayTaskResult, error)
	unregisterRelayFuture func(taskID string)
}

// NewProxyRouter creates a ProxyRouter backed by the given store.
func NewProxyRouter(store *storage.Store) *ProxyRouter {
	return &ProxyRouter{
		store:                 store,
		isRelayConnected:      ws.IsRelayConnected,
		dispatchToRelay:       ws.DispatchToRelay,
		unregisterRelayFuture: ws.UnregisterRelayTaskFuture,
	}
}

// GetRelayForHostname looks up the NEXT HOP for hostname in relay_routing: the direct child relay
// to dispatch to (relay_chain[0], or the declaring relay for direct routes), not necessarily
// the relay the host is attached to. Returns ("", ErrHostNotFound) if the host is unrouted.
func (r *ProxyRouter) GetRelayForHostname(hostname string) (string, error) {
	relayID, err := r.store.GetNextHopForHostname(hostname)
	if err != nil {
		return "", fmt.Errorf("relay_routing lookup: %w", err)
	}
	if relayID == "" {
		return "", ErrHostNotFound
	}
	return relayID, nil
}

// RouteExec routes an exec request to the relay responsible for hostname.
// Returns ErrHostNotFound if no relay owns the hostname, or relay_offline if
// the relay is not connected via /ws/relay.
func (r *ProxyRouter) RouteExec(ctx context.Context, hostname, taskID string, req ExecRequest) (*ExecResponse, error) {
	relayID, err := r.GetRelayForHostname(hostname)
	if err != nil {
		return nil, err
	}
	if !r.isRelayConnected(relayID) {
		return nil, fmt.Errorf("relay_offline: %s", relayID)
	}
	log.Printf("[PROXY] RouteExec: hostname=%s relay_id=%s task_id=%s", hostname, relayID, taskID)
	return r.pullExec(ctx, relayID, hostname, taskID, req)
}

// RouteUpload routes a file upload to the relay responsible for hostname.
func (r *ProxyRouter) RouteUpload(ctx context.Context, hostname, taskID string, req UploadRequest) error {
	relayID, err := r.GetRelayForHostname(hostname)
	if err != nil {
		return err
	}
	if !r.isRelayConnected(relayID) {
		return fmt.Errorf("relay_offline: %s", relayID)
	}
	log.Printf("[PROXY] RouteUpload: hostname=%s relay_id=%s", hostname, relayID)
	return r.pullUpload(ctx, relayID, hostname, taskID, req)
}

// RouteFetch routes a file fetch to the relay responsible for hostname.
func (r *ProxyRouter) RouteFetch(ctx context.Context, hostname, taskID string, req FetchRequest) (*FetchResponse, error) {
	relayID, err := r.GetRelayForHostname(hostname)
	if err != nil {
		return nil, err
	}
	if !r.isRelayConnected(relayID) {
		return nil, fmt.Errorf("relay_offline: %s", relayID)
	}
	log.Printf("[PROXY] RouteFetch: hostname=%s relay_id=%s", hostname, relayID)
	return r.pullFetch(ctx, relayID, hostname, taskID, req)
}

// AggregateRelayInventory returns all agent entries from relay_routing
// enriched with relay-level status (connected/disconnected).
// Local agents (directly connected) are NOT included — they come from the caller's DB query.
func (r *ProxyRouter) AggregateRelayInventory() ([]RelayAgentEntry, error) {
	nodes, err := r.store.ListValidRelayNodes()
	if err != nil {
		return nil, fmt.Errorf("AggregateRelayInventory: list nodes: %w", err)
	}

	// Build relay_id → DB status / last_seen
	nodeStatus := make(map[string]string, len(nodes))
	nodeLastSeen := make(map[string]int64, len(nodes))
	for _, n := range nodes {
		nodeStatus[n.RelayID] = n.Status
		if n.LastSeen != nil {
			nodeLastSeen[n.RelayID] = *n.LastSeen
		}
		// Live WS connection overrides DB status
		if r.isRelayConnected(n.RelayID) {
			nodeStatus[n.RelayID] = "connected"
		}
	}

	var entries []RelayAgentEntry
	for _, n := range nodes {
		hostnames, hErr := r.store.ListRelayRouting(n.RelayID)
		if hErr != nil {
			log.Printf("[PROXY] AggregateRelayInventory: list routing for %s: %v", n.RelayID, hErr)
			continue
		}
		relayStatus := nodeStatus[n.RelayID]
		if relayStatus == "" {
			relayStatus = "disconnected"
		}
		for _, h := range hostnames {
			entries = append(entries, RelayAgentEntry{
				Hostname:    h,
				RelayID:     n.RelayID,
				RelayStatus: relayStatus,
				LastSeen:    nodeLastSeen[n.RelayID],
			})
		}
	}
	return entries, nil
}

// ── Pull mode (WS dispatch) ───────────────────────────────────────────────────

const (
	pullRouteMarginSec = 5
	pullFileTimeoutSec = 60
)

func (r *ProxyRouter) pullExec(ctx context.Context, relayID, hostname, taskID string, req ExecRequest) (*ExecResponse, error) {
	msg := ws.RelayMessage{
		Type:         "task_dispatch",
		TaskID:       taskID,
		Hostname:     hostname,
		Cmd:          req.Cmd,
		Stdin:        req.Stdin,
		Timeout:      req.Timeout,
		Become:       req.Become,
		BecomeMethod: req.BecomeMethod,
	}

	ch, err := r.dispatchToRelay(relayID, msg)
	if err != nil {
		return nil, fmt.Errorf("dispatch_failed: %w", err)
	}

	timeout := time.Duration(req.Timeout+pullRouteMarginSec) * time.Second
	select {
	case result := <-ch:
		r.unregisterRelayFuture(taskID)
		if result.Error != "" {
			return nil, fmt.Errorf("%s", result.Error)
		}
		return &ExecResponse{
			RC:        result.RC,
			Stdout:    result.Stdout,
			Stderr:    result.Stderr,
			Truncated: result.Truncated,
		}, nil
	case <-time.After(timeout):
		r.unregisterRelayFuture(taskID)
		return nil, fmt.Errorf("timeout")
	case <-ctx.Done():
		r.unregisterRelayFuture(taskID)
		return nil, fmt.Errorf("context_cancelled")
	}
}

func (r *ProxyRouter) pullUpload(ctx context.Context, relayID, hostname, taskID string, req UploadRequest) error {
	msg := ws.RelayMessage{
		Type:     "file_upload",
		TaskID:   taskID,
		Hostname: hostname,
		Dest:     req.Dest,
		Data:     req.Data,
		Mode:     req.Mode,
	}

	ch, err := r.dispatchToRelay(relayID, msg)
	if err != nil {
		return fmt.Errorf("dispatch_failed: %w", err)
	}

	select {
	case result := <-ch:
		r.unregisterRelayFuture(taskID)
		if result.Error != "" {
			return fmt.Errorf("%s", result.Error)
		}
		if result.RC != 0 {
			return fmt.Errorf("upload_failed: rc=%d", result.RC)
		}
		return nil
	case <-time.After(pullFileTimeoutSec * time.Second):
		r.unregisterRelayFuture(taskID)
		return fmt.Errorf("timeout")
	case <-ctx.Done():
		r.unregisterRelayFuture(taskID)
		return fmt.Errorf("context_cancelled")
	}
}

func (r *ProxyRouter) pullFetch(ctx context.Context, relayID, hostname, taskID string, req FetchRequest) (*FetchResponse, error) {
	msg := ws.RelayMessage{
		Type:     "file_fetch",
		TaskID:   taskID,
		Hostname: hostname,
		Src:      req.Src,
	}

	ch, err := r.dispatchToRelay(relayID, msg)
	if err != nil {
		return nil, fmt.Errorf("dispatch_failed: %w", err)
	}

	select {
	case result := <-ch:
		r.unregisterRelayFuture(taskID)
		if result.Error != "" {
			return nil, fmt.Errorf("%s", result.Error)
		}
		return &FetchResponse{RC: result.RC, Data: result.Data}, nil
	case <-time.After(pullFileTimeoutSec * time.Second):
		r.unregisterRelayFuture(taskID)
		return nil, fmt.Errorf("timeout")
	case <-ctx.Done():
		r.unregisterRelayFuture(taskID)
		return nil, fmt.Errorf("context_cancelled")
	}
}
