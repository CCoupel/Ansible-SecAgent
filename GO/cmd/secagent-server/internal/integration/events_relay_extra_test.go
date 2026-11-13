// SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
// SPDX-License-Identifier: AGPL-3.0-or-later

package integration

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// LOT-3.1 (#225 #245 #265), second part: push links (conn_seq in relay_ack, written by the CHILD), relay_hello
// conn_seq decoding, tolerance of unknown kinds (what a v3.0.5 parent does), webhook body, hook journal API.

// Push: the parent dials the child; the child's relay_ack carries its conn_seq (counter of ITS process).
func TestRelayEvents_PushLink_UpThenReconnectThenUpAfterChildRestart(t *testing.T) {
	parallel(t)
	root := startNode(t, nodeSpec{ID: "root", Hooks: lifecycleHooks})
	relay1 := startNode(t, nodeSpec{ID: "relay1"})
	linkPush(t, root, relay1)
	waitFor(t, "relay.up (push)", func() bool { return len(root.relayLines("relay.up", "relay1")) == 1 })
	u := root.relayLines("relay.up", "relay1")[0]
	for _, want := range []string{" mode=push ", " seq=1 ", " host= "} {
		if !strings.Contains(u, want) {
			t.Errorf("relay.up of a push link lacks %q: %s", want, u)
		}
	}

	root.closeRelay("relay1", 1011) // cut by the parent: the dialer redials, the child PROCESS is the same
	waitFor(t, "relay.down (push)", func() bool { return len(root.relayLines("relay.down", "relay1")) >= 1 })
	waitFor(t, "relay.reconnect (push)", func() bool { return len(root.relayLines("relay.reconnect", "relay1")) >= 1 })
	r := root.relayLines("relay.reconnect", "relay1")[0]
	if !strings.Contains(r, " mode=push ") || strings.Contains(r, " seq=1 ") || strings.Contains(r, " seq= ") {
		t.Errorf("relay.reconnect of a push link: want mode=push and conn_seq > 1 (from the child's relay_ack): %s", r)
	}
	if got := len(root.relayLines("relay.up", "relay1")); got != 1 {
		t.Errorf("%d relay.up after a same-process reconnection, want 1", got)
	}

	relay1.restart() // a NEW child process: conn_seq restarts at 1
	waitFor(t, "relay.up of the restarted child (push)", func() bool { return len(root.relayLines("relay.up", "relay1")) == 2 })
}

// dialFakeChild opens /ws/relay by hand with extra fields in relay_hello (conn_seq as the test wants it).
func dialFakeChild(t *testing.T, parent *node, id string, extra map[string]any) {
	t.Helper()
	h := http.Header{}
	h.Set("Authorization", "Bearer "+parent.registerChild(id))
	d := websocket.Dialer{TLSClientConfig: tlsClientConfig(), HandshakeTimeout: 5 * time.Second}
	conn, _, err := d.Dial(parent.wssURL()+"/ws/relay", h)
	if err != nil {
		t.Fatalf("fake child %s: %v", id, err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	hello := map[string]any{"type": "relay_hello", "relay_id": id, "node_type": "relay", "mode": "pull", "version": "3.0", "ancestors": []string{}}
	for k, v := range extra {
		hello[k] = v
	}
	if err := conn.WriteJSON(hello); err != nil {
		t.Fatal(err)
	}
	for { // the relay_ack first
		var m map[string]any
		if err := conn.ReadJSON(&m); err != nil {
			t.Fatalf("fake child %s: waiting for relay_ack: %v", id, err)
		}
		if m["type"] == "relay_ack" {
			break
		}
	}
	if err := conn.WriteJSON(map[string]any{"type": "topology_snapshot", "relays": []any{}, "agents": []any{}}); err != nil {
		t.Fatal(err)
	}
	go func() { // keep answering pings / draining so that the link stays up
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}()
}

// relay_hello.conn_seq: > 1 ⇒ relay.reconnect ; absent / invalid / out of range ⇒ relay.up (fail-safe).
func TestRelayEvents_HelloConnSeqDecoding(t *testing.T) {
	parallel(t)
	root := startNode(t, nodeSpec{ID: "root", Hooks: lifecycleHooks})
	cases := []struct {
		id    string
		extra map[string]any
		want  string
	}{
		{"c-absent", nil, "relay.up"},
		{"c-one", map[string]any{"conn_seq": 1}, "relay.up"},
		{"c-three", map[string]any{"conn_seq": 3}, "relay.reconnect"},
		{"c-zero", map[string]any{"conn_seq": 0}, "relay.up"},
		{"c-neg", map[string]any{"conn_seq": -4}, "relay.up"},
		{"c-text", map[string]any{"conn_seq": "abc"}, "relay.up"},
		{"c-float", map[string]any{"conn_seq": 2.5}, "relay.up"},
		{"c-huge", map[string]any{"conn_seq": 4294967296}, "relay.up"},
	}
	for _, c := range cases {
		t.Run(c.id, func(t *testing.T) {
			dialFakeChild(t, root, c.id, c.extra)
			other := "relay.reconnect"
			if c.want == "relay.reconnect" {
				other = "relay.up"
			}
			waitFor(t, c.id+": "+c.want, func() bool { return len(root.relayLines(c.want, c.id)) == 1 })
			time.Sleep(100 * time.Millisecond)
			if got := len(root.relayLines(other, c.id)); got != 0 {
				t.Errorf("%s: %d %s, want 0 (up and reconnect are exclusive)", c.id, got, other)
			}
		})
	}
}

// What a pre-3.0.6 parent does with a kind it does not know (T9): a warning, the link stays open, no hook, and the
// events that follow are still processed. The current server behaves the same for a kind nobody defines.
func TestRelayEvents_UnknownKindIsDroppedWithoutClosingTheLink(t *testing.T) {
	parallel(t)
	root := startNode(t, nodeSpec{ID: "root", Hooks: lifecycleHooks})
	fake := newFakeChild(t, root, "fakeA")
	fake.send(map[string]any{"type": "event_forward", "event": "relay.bogus", "relay_id": "fakeA", "relay_chain": []string{"fakeA"}})
	waitFor(t, "the unknown kind is refused with a warning", func() bool { return root.logs.has("unsupported event kind") })
	fake.send(map[string]any{"type": "event_forward", "event": "relay.down", "relay_id": "fakeA", "relay_chain": []string{"fakeA"}, "reason": "read_error", "hosts_routed": 0})
	waitFor(t, "a valid relay.down that follows is processed", func() bool { return len(root.relayLines("relay.down", "fakeA")) == 1 })
	select {
	case err := <-fake.closed:
		t.Fatalf("the link was closed by an unknown kind: %v", err)
	default:
	}
	if got := len(root.relayLines("relay.bogus", "fakeA")); got != 0 {
		t.Errorf("an unknown kind reached the hooks")
	}
}

// The webhook body of a relay event has a relay object and NO host object; a host event keeps its host object.
func TestRelayEvents_WebhookBodyHasRelayAndNoHost(t *testing.T) {
	parallel(t)
	var mu sync.Mutex
	var bodies []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var m map[string]any
		if json.Unmarshal(b, &m) == nil {
			mu.Lock()
			bodies = append(bodies, m)
			mu.Unlock()
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	root := startNode(t, nodeSpec{ID: "root", Hooks: func(out string) string {
		return `{"hooks":[{"event":"relay.up","actions":[{"type":"webhook","url":"` + srv.URL + `","timeout_seconds":5}]},` +
			`{"event":"host.up","actions":[{"type":"webhook","url":"` + srv.URL + `","timeout_seconds":5}]}]}`
	}})
	tok := root.registerChild("relay1")
	startNode(t, nodeSpec{ID: "relay1", ParentURL: root.wssURL(), ParentToken: tok})
	connectMinion(t, root, "wh-host")
	find := func(ev string) map[string]any {
		mu.Lock()
		defer mu.Unlock()
		for _, b := range bodies {
			if b["event"] == ev {
				return b
			}
		}
		return nil
	}
	waitFor(t, "the relay.up and host.up webhooks", func() bool { return find("relay.up") != nil && find("host.up") != nil })
	up := find("relay.up")
	if _, has := up["host"]; has {
		t.Errorf("a relay.* webhook body must not carry a host object: %v", up)
	}
	if rel, _ := up["relay"].(map[string]any); rel == nil || rel["relay_id"] != "relay1" {
		t.Errorf("a relay.* webhook body must carry the relay object: %v", up)
	}
	if h, _ := find("host.up")["host"].(map[string]any); h == nil || h["hostname"] != "wh-host" {
		t.Errorf("a host.* webhook body keeps its host object: %v", find("host.up"))
	}
}

// `hooks log --event relay.down` reads GET /api/admin/hooks/log?event=relay.down: the entry has no hostname.
func TestRelayEvents_HooksLogFiltersRelayDown(t *testing.T) {
	parallel(t)
	root, _ := pullChild(t)
	waitFor(t, "relay.up", func() bool { return len(root.relayLines("relay.up", "relay1")) == 1 })
	root.closeRelay("relay1", 1011)
	waitFor(t, "relay.down hook ran", func() bool { return len(root.relayLines("relay.down", "relay1")) >= 1 })
	var entries []map[string]any
	waitFor(t, "relay.down is in the hook journal", func() bool {
		code, raw := root.callOn(root.adminURL(), "GET", "/api/admin/hooks/log?event=relay.down&limit=50", root.adminTok, nil)
		entries = nil
		return code == http.StatusOK && json.Unmarshal(raw, &entries) == nil && len(entries) >= 1
	})
	for _, e := range entries {
		if e["event"] != "relay.down" {
			t.Errorf("the journal filter returned another event: %v", e)
		}
		if h, _ := e["hostname"].(string); h != "" {
			t.Errorf("a relay.down journal entry must have no hostname: %v", e)
		}
	}
	code, raw := root.callOn(root.adminURL(), "GET", "/api/admin/hooks/log?event=relay.reconnect&limit=50", root.adminTok, nil)
	if code != http.StatusOK {
		t.Errorf("hooks log --event relay.reconnect = %d %s", code, raw)
	}
}
