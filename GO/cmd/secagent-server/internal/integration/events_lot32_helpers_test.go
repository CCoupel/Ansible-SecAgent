// SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
// SPDX-License-Identifier: AGPL-3.0-or-later

package integration

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// LOT-3.2 (#244 #246 #247) — helpers of the host.rerouted / relay.rerouted / relay.converged / upstream queue tests.
// Contract: _work/reports/planner-lot32-v3.0.6-20261111.md §T15-T17, T21; DOC/server/HOOKS_SPEC.md (variables §5).

// lot32Events are the events the lot32Hooks shell hooks log.
var lot32Events = []string{
	"host.up", "host.down", "host.reconnect", "host.conflict", "host.rerouted",
	"relay.up", "relay.down", "relay.reconnect", "relay.failover", "relay.rerouted", "relay.converged", "relay.discover",
}

// lot32Hooks builds a hooks configuration whose shell actions append ONE line per event to out:
//
//	<event> relay=<id> host=<h> cause=<c> reason=<r> old=<old_relay> new=<new_relay> oldc=<old_chain> newc=<new_chain>
//	        rc=<relays_connected> rm=<relays_missing> hd=<hosts_direct> hr=<hosts_routed> dropped=<upstream_dropped_events_total>
//	        inst=<instance_id> prev=<previous_instance_id>
//
// (chains are comma-joined by the dispatcher, a variable that is not carried reads empty). Use parseLine to read a line.
func lot32Hooks(out string) string {
	line := `"$SECAGENT_EVENT relay=$SECAGENT_RELAY_ID host=$SECAGENT_HOSTNAME cause=$SECAGENT_CAUSE reason=$SECAGENT_REASON ` +
		`old=$SECAGENT_OLD_RELAY new=$SECAGENT_NEW_RELAY oldc=$SECAGENT_OLD_CHAIN newc=$SECAGENT_NEW_CHAIN ` +
		`rc=$SECAGENT_RELAYS_CONNECTED rm=$SECAGENT_RELAYS_MISSING hd=$SECAGENT_HOSTS_DIRECT hr=$SECAGENT_HOSTS_ROUTED ` +
		`dropped=$SECAGENT_UPSTREAM_DROPPED_EVENTS_TOTAL inst=$SECAGENT_INSTANCE_ID prev=$SECAGENT_PREVIOUS_INSTANCE_ID"`
	type action struct {
		Type    string   `json:"type"`
		Cmd     string   `json:"cmd"`
		Args    []string `json:"args"`
		Timeout int      `json:"timeout_seconds"`
	}
	type hook struct {
		Event   string   `json:"event"`
		Actions []action `json:"actions"`
	}
	var hooks []hook
	for _, ev := range lot32Events {
		hooks = append(hooks, hook{Event: ev, Actions: []action{{Type: "shell", Cmd: "/bin/sh", Args: []string{"-c", "echo " + line + " >> " + out}, Timeout: 10}}})
	}
	b, _ := json.Marshal(map[string]any{"hooks": hooks})
	return string(b)
}

// parseLine splits a lot32Hooks line: the event name, then its key=value fields.
func parseLine(l string) (ev string, kv map[string]string) {
	f := strings.Fields(l)
	if len(f) == 0 {
		return "", nil
	}
	kv = map[string]string{}
	for _, p := range f[1:] {
		if i := strings.IndexByte(p, '='); i > 0 {
			kv[p[:i]] = p[i+1:]
		}
	}
	return f[0], kv
}

// eventsOf returns the parsed lines of the node's journal for the event ev whose fields all match want
// (a field not listed in want is not checked), in order of arrival.
func (n *node) eventsOf(ev string, want map[string]string) []map[string]string {
	var out []map[string]string
	for _, l := range n.hookLines() {
		e, kv := parseLine(l)
		if e != ev {
			continue
		}
		ok := true
		for k, v := range want {
			if kv[k] != v {
				ok = false
				break
			}
		}
		if ok {
			out = append(out, kv)
		}
	}
	return out
}

// firstIndex is the index (in hookLines) of the first line of event ev matching want, -1 if none.
func (n *node) firstIndex(ev string, want map[string]string) int {
	for i, l := range n.hookLines() {
		e, kv := parseLine(l)
		if e != ev {
			continue
		}
		ok := true
		for k, v := range want {
			if kv[k] != v {
				ok = false
				break
			}
		}
		if ok {
			return i
		}
	}
	return -1
}

// quiet lets the tree settle: the journal of n must not grow any line of event ev (matching want) in d.
func quiet(t *testing.T, n *node, ev string, want map[string]string, d time.Duration) {
	t.Helper()
	before := len(n.eventsOf(ev, want))
	time.Sleep(d)
	if after := len(n.eventsOf(ev, want)); after != before {
		t.Errorf("%s: %d %s line(s) appeared during the settling time (%d -> %d)", n.id, after-before, ev, before, after)
	}
}

// statusField reads a numeric field of GET /api/admin/status (top level).
func (n *node) statusField(name string) (float64, bool) {
	n.t.Helper()
	code, raw := n.callOn(n.adminURL(), "GET", "/api/admin/status", n.adminTok, nil)
	if code != http.StatusOK {
		n.t.Fatalf("admin status on %s: %d %s", n.id, code, raw)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		n.t.Fatal(err)
	}
	v, ok := m[name].(float64)
	return v, ok
}

// hookJournal returns the raw body of GET /api/admin/hooks/log?event=<ev>&limit=<limit> on the node.
func (n *node) hookJournal(ev string, limit int) string {
	n.t.Helper()
	code, raw := n.callOn(n.adminURL(), "GET", fmt.Sprintf("/api/admin/hooks/log?event=%s&limit=%d", ev, limit), n.adminTok, nil)
	if code != http.StatusOK {
		n.t.Fatalf("hooks log on %s: %d %s", n.id, code, raw)
	}
	return string(raw)
}

// lot32Link is a hand-driven link of a fake child to a parent: hello WITHOUT conn_seq (so every link is a relay.up
// for the parent), then an empty snapshot. The token is reusable, so the same child can flap.
type lot32Link struct {
	conn *websocket.Conn
}

func dialLot32Link(parent *node, id, token string) (*lot32Link, error) {
	h := http.Header{}
	h.Set("Authorization", "Bearer "+token)
	d := websocket.Dialer{TLSClientConfig: tlsClientConfig(), HandshakeTimeout: 10 * time.Second}
	conn, _, err := d.Dial(parent.wssURL()+"/ws/relay", h)
	if err != nil {
		return nil, err
	}
	hello := map[string]any{"type": "relay_hello", "relay_id": id, "node_type": "relay", "mode": "pull", "version": "3.0", "ancestors": []string{}}
	if err := conn.WriteJSON(hello); err != nil {
		_ = conn.Close()
		return nil, err
	}
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	for {
		var m map[string]any
		if err := conn.ReadJSON(&m); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("waiting for relay_ack: %w", err)
		}
		if m["type"] == "relay_ack" {
			break
		}
	}
	_ = conn.SetReadDeadline(time.Time{})
	if err := conn.WriteJSON(map[string]any{"type": "topology_snapshot", "relays": []any{}, "agents": []any{}}); err != nil {
		_ = conn.Close()
		return nil, err
	}
	go func() { // answer pings, drain: the link stays up until closed
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}()
	return &lot32Link{conn: conn}, nil
}

func (l *lot32Link) close() { _ = l.conn.Close() }

// flap opens and closes a fake child link n times (the first open included): it produces on the PARENT side
// 1 relay.up, then (n-1) times a relay.down + relay.up, and a final relay.down, i.e. 2*n events.
func flap(parent *node, id, token string, n int) (produced int, err error) {
	for i := 0; i < n; i++ {
		l, err := dialLot32Link(parent, id, token)
		if err != nil {
			return produced, err
		}
		produced++ // relay.up
		l.close()
		produced++                       // relay.down
		time.Sleep(5 * time.Millisecond) // let the parent notice the close before the next link
	}
	return produced, nil
}
