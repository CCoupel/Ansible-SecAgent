// SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
// SPDX-License-Identifier: AGPL-3.0-or-later

package integration

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// LOT-3.1 (#225 #245 #265) — helpers of the relay / reconnect lifecycle events tests.
// Contract: DOC/server/SERVER_SPEC.md §9.2, DOC/contracts/WEBSOCKET.md (header X-SecAgent-Conn-Seq, §8), commit d6deb6f.

// lifecycleEvents are the events the helper hooks log.
var lifecycleEvents = []string{
	"relay.failover", "relay.up", "relay.reconnect", "relay.down",
	"host.up", "host.reconnect", "host.down",
}

// lifecycleHooks builds a hooks configuration whose shell actions append ONE line per event to out:
//
//	<event> relay=<id> host=<hostname> reason=<r> cause=<c> mode=<m> hosts=<n> seq=<conn_seq> inst=<instance_id> prev=<previous_instance_id>
//
// built from the SECAGENT_* variables of the contract (empty when the event does not carry them). A relay.* line
// must therefore always read "host= " (no hostname, never the name of a host).
func lifecycleHooks(out string) string {
	line := `"$SECAGENT_EVENT relay=$SECAGENT_RELAY_ID host=$SECAGENT_HOSTNAME reason=$SECAGENT_REASON cause=$SECAGENT_CAUSE ` +
		`mode=$SECAGENT_MODE hosts=$SECAGENT_HOSTS_ROUTED seq=$SECAGENT_CONN_SEQ inst=$SECAGENT_INSTANCE_ID prev=$SECAGENT_PREVIOUS_INSTANCE_ID"`
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
	for _, ev := range lifecycleEvents {
		hooks = append(hooks, hook{Event: ev, Actions: []action{{Type: "shell", Cmd: "/bin/sh", Args: []string{"-c", "echo " + line + " >> " + out}, Timeout: 10}}})
	}
	b, _ := json.Marshal(map[string]any{"hooks": hooks})
	return string(b)
}

// lines returns the hook lines of the node starting with prefix.
func (n *node) linesWith(prefix string) []string {
	var out []string
	for _, l := range n.hookLines() {
		if strings.HasPrefix(l, prefix) {
			out = append(out, l)
		}
	}
	return out
}

// dialAgentSeq opens /ws/agent for host with the agent token tok and the raw X-SecAgent-Conn-Seq header
// (seq == nil: header absent, like a v3.0.5 minion). The link stays open until the test ends.
func dialAgentSeq(t *testing.T, n *node, tok string, seq *string) *websocket.Conn {
	t.Helper()
	h := http.Header{}
	h.Set("Authorization", "Bearer "+tok)
	if seq != nil {
		h["X-Secagent-Conn-Seq"] = []string{*seq} // set verbatim, even empty
	}
	d := websocket.Dialer{TLSClientConfig: tlsClientConfig(), HandshakeTimeout: 10 * time.Second}
	conn, resp, err := d.Dial(n.wssURL()+"/ws/agent", h)
	if err != nil {
		t.Fatalf("agent dial on %s (conn-seq %v): %v (resp %v)", n.id, seq, err, resp)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// hostLines returns the lines of event ev (exact event name) about host.
func (n *node) hostLines(ev, host string) []string {
	var out []string
	for _, l := range n.hookLines() {
		if strings.HasPrefix(l, ev+" ") && strings.Contains(l, " host="+host+" ") {
			out = append(out, l)
		}
	}
	return out
}

// relayLines returns the lines of event ev (exact event name) about the relay id.
func (n *node) relayLines(ev, id string) []string {
	var out []string
	for _, l := range n.hookLines() {
		if strings.HasPrefix(l, ev+" relay="+id+" ") {
			out = append(out, l)
		}
	}
	return out
}

func strp(s string) *string { return &s }
