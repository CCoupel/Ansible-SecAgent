// Package forward executes the tasks a PARENT relay sends down the tree (#127): it resolves the
// next hop of the target hostname and either runs the task on a directly connected agent or
// relays it to the child that routes the host, then sends the task_result back upstream.
//
// Resolution order (security): a live /ws/agent connection always wins over the routing table,
// so a relay cannot divert a locally connected host (and its become_pass stdin) by declaring it.
package forward

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"time"

	"secagent-server/cmd/secagent-server/internal/ws"
)

// Errors reported to the parent in task_result.error.
const (
	ErrInvalidTask  = "invalid_task"
	ErrHostNotFound = "host_not_found"
	ErrRelayOffline = "relay_offline"
	ErrRouteLookup  = "route_lookup_failed"
	ErrTimeout      = "timeout"
	ErrDispatch     = "dispatch_failed"
	// Suspension of a directly connected agent (#173): the refusal travels up to the plugin.
	ErrAgentSuspended        = "agent_suspended"
	ErrAgentStateUnavailable = "agent_state_unavailable"
)

const (
	defaultExecTimeout = 30
	timeoutMargin      = 5
	fileTimeout        = 60 * time.Second
)

// Forwarder resolves and executes forwarded tasks.
type Forwarder struct {
	// NextHop returns the direct child relay routing hostname ("" when unrouted).
	NextHop func(hostname string) (string, error)
	// Suspended reports whether a directly connected agent is suspended on this node (#173).
	// An error refuses the task (fail closed). A nil function disables the check: test seam only,
	// the server always wires it.
	Suspended func(hostname string) (bool, error)
}

// Handle processes one task message from the parent (raw JSON) and replies with a task_result.
// It matches repeater.TaskHandler. stdin / become_pass are never logged.
func (f *Forwarder) Handle(ctx context.Context, raw json.RawMessage, reply func(v any) error) {
	var m ws.RelayMessage
	if err := json.Unmarshal(raw, &m); err != nil || m.TaskID == "" || m.Hostname == "" {
		if m.TaskID != "" {
			send(reply, ws.RelayMessage{Type: "task_result", TaskID: m.TaskID, Error: ErrInvalidTask})
		}
		log.Printf("[FORWARD] invalid task message dropped")
		return
	}
	res := f.run(ctx, m)
	res.Type = "task_result"
	res.TaskID = m.TaskID
	send(reply, res)
}

func send(reply func(v any) error, m ws.RelayMessage) {
	if err := reply(m); err != nil {
		log.Printf("[FORWARD] reply failed: task_id=%s err=%v", m.TaskID, err)
	}
}

func (f *Forwarder) run(ctx context.Context, m ws.RelayMessage) ws.RelayMessage {
	switch m.Type {
	case "task_forward", "task_dispatch", "file_upload", "file_fetch":
	default:
		return ws.RelayMessage{Error: ErrInvalidTask}
	}

	// 1. directly connected agent
	if _, err := ws.GetConnection(m.Hostname); err == nil {
		if f.Suspended != nil {
			suspended, err := f.Suspended(m.Hostname)
			if err != nil {
				log.Printf("[SECURITY WARNING] forwarded task refused: suspension state of %q unavailable: %v task_id=%s", m.Hostname, err, m.TaskID)
				return ws.RelayMessage{Error: ErrAgentStateUnavailable}
			}
			if suspended {
				log.Printf("[SECURITY WARNING] forwarded task refused: agent %q is suspended task_id=%s", m.Hostname, m.TaskID)
				return ws.RelayMessage{Error: ErrAgentSuspended}
			}
		}
		return runLocal(ctx, m)
	}

	// 2. downstream relay
	hop := ""
	if f.NextHop != nil {
		var err error
		if hop, err = f.NextHop(m.Hostname); err != nil {
			log.Printf("[FORWARD] route lookup failed: host=%s err=%v", m.Hostname, err)
			return ws.RelayMessage{Error: ErrRouteLookup}
		}
	}
	if hop == "" {
		return ws.RelayMessage{Error: ErrHostNotFound}
	}
	if !ws.IsRelayConnected(hop) {
		return ws.RelayMessage{Error: ErrRelayOffline}
	}
	log.Printf("[FORWARD] task_id=%s host=%s next_hop=%s type=%s", m.TaskID, m.Hostname, hop, m.Type)
	ch, err := ws.DispatchToRelay(hop, m)
	if err != nil {
		return ws.RelayMessage{Error: ErrDispatch}
	}
	select {
	case r := <-ch:
		return resultMsg(r)
	case <-time.After(waitFor(m)):
		ws.UnregisterRelayTaskFuture(m.TaskID)
		return ws.RelayMessage{Error: ErrTimeout}
	case <-ctx.Done():
		ws.UnregisterRelayTaskFuture(m.TaskID)
		return ws.RelayMessage{Error: "context_cancelled"}
	}
}

func resultMsg(r ws.RelayTaskResult) ws.RelayMessage {
	return ws.RelayMessage{RC: r.RC, Stdout: r.Stdout, Stderr: r.Stderr, Truncated: r.Truncated, Data: r.Data, Error: r.Error}
}

func waitFor(m ws.RelayMessage) time.Duration {
	if m.Type == "task_forward" || m.Type == "task_dispatch" {
		t := m.Timeout
		if t <= 0 {
			t = defaultExecTimeout
		}
		return time.Duration(t+timeoutMargin) * time.Second
	}
	return fileTimeout
}

// runLocal executes the task on the agent connected to this node.
func runLocal(ctx context.Context, m ws.RelayMessage) ws.RelayMessage {
	msg, err := agentMessage(m)
	if err != nil {
		return ws.RelayMessage{Error: ErrInvalidTask}
	}
	ch := ws.RegisterFuture(m.TaskID, m.Hostname)
	if err := ws.SendToAgent(m.Hostname, msg); err != nil {
		ws.UnregisterFuture(m.TaskID)
		return ws.RelayMessage{Error: "send_failed"}
	}
	done := make(chan struct{})
	var res ws.Message
	var werr error
	go func() {
		res, werr = ws.WaitForResult(ch, waitFor(m))
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
		ws.UnregisterFuture(m.TaskID)
		return ws.RelayMessage{Error: "context_cancelled"}
	}
	if werr != nil {
		ws.UnregisterFuture(m.TaskID)
		return ws.RelayMessage{Error: ErrTimeout}
	}
	return ws.RelayMessage{RC: res.RC, Stdout: res.Stdout, Stderr: res.Stderr, Truncated: res.Truncated, Data: res.Data, Error: res.Error}
}

// agentMessage builds the /ws/agent message for a forwarded task (same format as the REST handlers).
func agentMessage(m ws.RelayMessage) (map[string]interface{}, error) {
	switch m.Type {
	case "task_forward", "task_dispatch":
		timeout := m.Timeout
		if timeout <= 0 {
			timeout = defaultExecTimeout
		}
		out := map[string]interface{}{
			"task_id":       m.TaskID,
			"type":          "exec",
			"cmd":           m.Cmd,
			"timeout":       timeout,
			"become":        m.Become,
			"become_method": m.BecomeMethod,
			"expires_at":    time.Now().Unix() + int64(timeout),
		}
		if m.Stdin != "" {
			out["stdin"] = m.Stdin
		}
		return out, nil
	case "file_upload":
		mode := m.Mode
		if mode == "" {
			mode = "0644"
		}
		return map[string]interface{}{"task_id": m.TaskID, "type": "put_file", "dest": m.Dest, "data": m.Data, "mode": mode}, nil
	case "file_fetch":
		return map[string]interface{}{"task_id": m.TaskID, "type": "fetch_file", "src": m.Src}, nil
	}
	return nil, errors.New("unsupported task type")
}
