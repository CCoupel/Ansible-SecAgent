package repeater

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/websocket"

	"secagent-server/cmd/secagent-server/internal/ws"
)

const interopSecret = "interop-child-secret"

func parentJWT(t *testing.T, sub, role string) string {
	t.Helper()
	raw, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": sub, "role": role, "jti": "interop-jti-" + sub,
		"iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(),
	}).SignedString([]byte(interopSecret))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// childNode starts the CHILD side for real (ws.RelayHandler accepting a parent + Uplink)
// and returns its wss URL and the uplink. ws hooks are process-global: one child per test.
func childNode(t *testing.T, childID string, agents []AgentInfo) (string, *Uplink) {
	t.Helper()
	oldJWT := ws.JWTSecretsFunc
	ws.JWTSecretsFunc = func() (string, string, time.Time) { return interopSecret, "", time.Time{} }
	ws.SetRelayLocalIDFunc(func() string { return childID })
	ws.SetRelayAncestorsFunc(func() []string { return nil })
	ws.SetRelayJTIBlacklistFunc(func(string) (bool, error) { return false, nil })
	up := NewUplink(childID, Options{
		DirectAgents: func() []AgentInfo { return agents },
		Snapshot: func() Snapshot {
			return Snapshot{Agents: []TopoAgent{{Hostname: "host-A", RelayID: childID, RelayChain: []string{childID}}}}
		},
		PingInterval: time.Hour, AgentListInterval: time.Hour,
	})
	ws.SetRelayParentLinkFunc(up.ServeAccepted)
	srv := httptest.NewTLSServer(http.HandlerFunc(ws.RelayHandler))
	t.Cleanup(func() {
		srv.Close()
		ws.JWTSecretsFunc = oldJWT
		ws.SetRelayLocalIDFunc(nil)
		ws.SetRelayAncestorsFunc(nil)
		ws.SetRelayJTIBlacklistFunc(nil)
		ws.SetRelayParentLinkFunc(nil)
	})
	return "wss" + strings.TrimPrefix(srv.URL, "https"), up
}

// recordingServe plays the parent's ServeDialedRelay: it just records what the child sends.
func recordingServe(msgs chan<- map[string]any) func(context.Context, *websocket.Conn, string) error {
	return func(ctx context.Context, conn *websocket.Conn, peer string) error {
		defer func() { _ = conn.Close() }()
		for {
			var m map[string]any
			if err := conn.ReadJSON(&m); err != nil {
				return err
			}
			msgs <- m
		}
	}
}

func TestInterop_ParentDialsChild(t *testing.T) {
	url, up := childNode(t, "dmz1", []AgentInfo{{Hostname: "host-A", Status: "connected"}})
	msgs := make(chan map[string]any, 8)
	opts := DialerOptions{
		Identity:   func() (string, []string) { return "central", []string{"root"} },
		WouldLoop:  func(id string) bool { return id == "central" || id == "root" },
		TLSConfig:  &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // test server cert
		MinBackoff: 10 * time.Millisecond, MaxBackoff: 40 * time.Millisecond,
		Serve: recordingServe(msgs),
	}
	d, err := NewDialer(DialTarget{RelayID: "dmz1", URL: url, Token: parentJWT(t, "central", "relay-parent")}, opts)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := d.Start(ctx); err != nil {
		t.Fatal(err)
	}

	// the child sends topology_snapshot first, then agent_list
	get := func(typ string) map[string]any {
		t.Helper()
		deadline := time.After(5 * time.Second)
		for {
			select {
			case m := <-msgs:
				if m["type"] == typ {
					return m
				}
			case <-deadline:
				t.Fatalf("timeout waiting for %s", typ)
			}
		}
	}
	snap := get("topology_snapshot")
	if a := snap["agents"].([]any); len(a) != 1 || a[0].(map[string]any)["hostname"] != "host-A" {
		t.Errorf("snapshot = %v", snap)
	}
	al := get("agent_list")
	if a := al["agents"].([]any); len(a) != 1 {
		t.Errorf("agent_list = %v", al)
	}
	if got := up.Ancestors(); len(got) != 2 || got[0] != "central" || got[1] != "root" {
		t.Errorf("child ancestors = %v, want [central root]", got)
	}
	if !up.Active() {
		t.Error("uplink must be active while the parent link is up")
	}
}

func TestInterop_ChildRefusesSecondParent(t *testing.T) {
	url, up := childNode(t, "dmz1", nil)
	dial := func(sub string) *websocket.Conn {
		t.Helper()
		h := http.Header{}
		h.Set("Authorization", "Bearer "+parentJWT(t, sub, "relay-parent"))
		c, _, err := (&websocket.Dialer{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}).Dial(url+"/ws/relay", h) //nolint:gosec // test
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close() })
		if err := c.WriteJSON(map[string]any{"type": "relay_hello", "relay_id": sub, "version": "3.0"}); err != nil {
			t.Fatal(err)
		}
		return c
	}
	first := dial("central")
	var ack map[string]any
	if err := first.ReadJSON(&ack); err != nil || ack["type"] != "relay_ack" || ack["relay_id"] != "dmz1" {
		t.Fatalf("first parent: ack=%v err=%v", ack, err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for !up.Active() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}

	second := dial("other-parent")
	_ = second.SetReadDeadline(time.Now().Add(3 * time.Second))
	var m map[string]any
	err := second.ReadJSON(&m)
	var ce *websocket.CloseError
	if err == nil || !asCloseError(err, &ce) || ce.Code != CloseCodeRetry {
		t.Errorf("second parent must be refused with the correctable code 4012 (busy slot), got msg=%v err=%v", m, err)
	}
}

func TestInterop_ChildRejectsChildRoleAsParent(t *testing.T) {
	url, _ := childNode(t, "dmz1", nil)
	// A child-role token ("relay") must never be treated as a parent: no parent handshake,
	// no relay_ack from the uplink path, so it cannot drive task_forward on this node.
	h := http.Header{}
	h.Set("Authorization", "Bearer "+parentJWT(t, "central", "relay"))
	c, _, err := (&websocket.Dialer{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}).Dial(url+"/ws/relay", h) //nolint:gosec // test
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if err := c.WriteJSON(map[string]any{"type": "relay_hello", "relay_id": "central", "version": "3.0"}); err != nil {
		t.Fatal(err)
	}
	var ack map[string]any
	if err := c.ReadJSON(&ack); err != nil {
		t.Fatal(err)
	}
	// regular child-side ack (served by the pull path), not an uplink: the node sends NO snapshot
	_ = c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	var next map[string]any
	if err := c.ReadJSON(&next); err == nil && next["type"] == "topology_snapshot" {
		t.Error("a child-role token must not trigger the uplink (snapshot sent to it)")
	}
}

func asCloseError(err error, target **websocket.CloseError) bool {
	return errors.As(err, target)
}
