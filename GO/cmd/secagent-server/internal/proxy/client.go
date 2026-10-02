// Package proxy implements the pull-mode relay router for secagent-server.
//
// This file contains:
//   - Anti-loop hop counting helpers (X-Relay-Hops header)
//   - Request / response types shared between the ProxyRouter and the exec handlers
//
// The push-mode REST client (RelayClient) was removed in v3.0 (#123).
// Push-mode relay entries in the DB are preserved for future use (#140).
package proxy

import "context"

// ── Anti-loop hop counting ────────────────────────────────────────────────────

// RelayHopsHeader is the HTTP header used to prevent routing loops in proxy chains.
// Each hop that receives a forwarded request decrements the value before forwarding.
// A value of 0 on an incoming request triggers HTTP 508 (Loop Detected).
//
// NOTE(#140): With push-mode REST removed in v3.0 (#123), the hop budget is only
// enforced on INCOMING forwarded requests (exec.go rejects X-Relay-Hops ≤ 0 with
// 508).  Outgoing WS dispatch does NOT propagate this header.  The full loop-
// detection design (ancestors set, relay tree depth) will be finalized in #140.
const RelayHopsHeader = "X-Relay-Hops"

// DefaultMaxHops is the initial hop budget injected into a fresh request context.
// Supports up to 8 consecutive relay hops before loop detection fires.
const DefaultMaxHops = 8

// hopCountKey is the unexported context key for the remaining hop budget.
type hopCountKey struct{}

// WithRelayHops stores the remaining hop count in ctx.
// Call this after decrementing the value received in the incoming X-Relay-Hops header.
func WithRelayHops(ctx context.Context, hops int) context.Context {
	return context.WithValue(ctx, hopCountKey{}, hops)
}

// RelayHopsFromContext retrieves the hop count from ctx.
// Returns DefaultMaxHops when no value has been stored (first hop in the chain).
func RelayHopsFromContext(ctx context.Context) int {
	if v, ok := ctx.Value(hopCountKey{}).(int); ok {
		return v
	}
	return DefaultMaxHops
}

// ── Request / Response types ─────────────────────────────────────────────────

// ExecRequest mirrors the relay's POST /api/exec/{hostname} body.
type ExecRequest struct {
	Cmd          string `json:"cmd"`
	Stdin        string `json:"stdin,omitempty"`
	Timeout      int    `json:"timeout,omitempty"`
	Become       bool   `json:"become,omitempty"`
	BecomeMethod string `json:"become_method,omitempty"`
	TaskID       string `json:"task_id,omitempty"`
}

// ExecResponse mirrors the relay's exec response.
type ExecResponse struct {
	TaskID    string `json:"task_id"`
	RC        int    `json:"rc"`
	Stdout    string `json:"stdout"`
	Stderr    string `json:"stderr"`
	Truncated bool   `json:"truncated"`
}

// UploadRequest mirrors the relay's POST /api/upload/{hostname} body.
type UploadRequest struct {
	Dest string `json:"dest"`
	Data string `json:"data"` // base64-encoded content
	Mode string `json:"mode,omitempty"`
}

// FetchRequest mirrors the relay's POST /api/fetch/{hostname} body.
type FetchRequest struct {
	Src string `json:"src"`
}

// FetchResponse mirrors the relay's fetch response.
type FetchResponse struct {
	Data string `json:"data"` // base64-encoded content
	RC   int    `json:"rc"`
}
