package repeater

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"secagent-server/cmd/secagent-server/internal/ws"
)

// ── a close frame received on the SERVED push link decides the dialer's fate (#148/#153) ──

// ackThenClose is a push child that completes the handshake, lets the parent serve the link,
// then ends it with a close frame carrying `code`.
type ackThenClose struct {
	srv      *httptest.Server
	attempts atomic.Int32
	code     atomic.Int32
}

func newAckThenClose(t *testing.T, childID string, code int) *ackThenClose {
	t.Helper()
	c := &ackThenClose{}
	c.code.Store(int32(code))
	up := websocket.Upgrader{}
	c.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		c.attempts.Add(1)
		var hello map[string]any
		if err := conn.ReadJSON(&hello); err != nil {
			return
		}
		if err := conn.WriteJSON(map[string]any{"type": "relay_ack", "relay_id": childID, "status": "ok"}); err != nil {
			return
		}
		time.Sleep(50 * time.Millisecond) // let the parent register the served link
		if code := int(c.code.Load()); code != 0 {
			_ = conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(code, "token revoked"), time.Now().Add(time.Second))
			time.Sleep(50 * time.Millisecond)
			return
		}
		for { // healthy link
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}))
	t.Cleanup(c.srv.Close)
	return c
}

func (c *ackThenClose) url() string { return "wss" + strings.TrimPrefix(c.srv.URL, "https") }

// realDialer wires the REAL ws.ServeDialedRelay (parent side) to a Dialer.
func realDialer(t *testing.T, c *ackThenClose, childID string) *Dialer {
	t.Helper()
	ws.SetRelayLocalIDFunc(func() string { return "central" })
	t.Cleanup(func() { ws.SetRelayLocalIDFunc(nil) })
	d, err := NewDialer(DialTarget{RelayID: childID, URL: c.url(), Token: "dialer-secret-token"}, DialerOptions{
		Identity:   func() (string, []string) { return "central", nil },
		TLSConfig:  &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // test server cert
		MinBackoff: 20 * time.Millisecond, MaxBackoff: 80 * time.Millisecond,
		Serve: ws.ServeDialedRelay,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := d.Start(ctx); err != nil {
		t.Fatal(err)
	}
	return d
}

func TestDialedLink_Close4010IsPermanentErrorLoggedAndNoRedial(t *testing.T) {
	sink := captureRawLogs(t)
	c := newAckThenClose(t, "dmz-perm", CloseCodePermanent)
	d := realDialer(t, c, "dmz-perm")
	st := waitStatus(t, d.Status, LinkRefusedPermanent)
	if !strings.Contains(st.Reason, "4010") {
		t.Errorf("reason = %q", st.Reason)
	}
	if !errors.Is(d.Terminal(), ErrPermanentRefusal) {
		t.Errorf("Terminal() = %v", d.Terminal())
	}
	n := c.attempts.Load()
	time.Sleep(300 * time.Millisecond) // ~4 backoff periods: no redial allowed
	if c.attempts.Load() != n || n != 1 {
		t.Errorf("attempts = %d then %d, want exactly 1", n, c.attempts.Load())
	}
	logs := sink.String()
	if !strings.Contains(logs, "ERROR") || !strings.Contains(logs, "operator action required") {
		t.Errorf("the operator must get an ERROR log:\n%s", logs)
	}
	if strings.Contains(logs, "dialer-secret-token") || strings.Contains(logs, "Bearer") {
		t.Errorf("token leaked in logs:\n%s", logs)
	}
}

func TestDialedLink_Close4012IsRetriedAndOthersAreLinkLost(t *testing.T) {
	for name, code := range map[string]int{"correctable 4012": CloseCodeRetry, "normal 1000": websocket.CloseNormalClosure} {
		t.Run(name, func(t *testing.T) {
			id := "dmz-retry-" + strings.Fields(name)[1]
			c := newAckThenClose(t, id, code)
			d := realDialer(t, c, id)
			deadline := time.Now().Add(5 * time.Second)
			for c.attempts.Load() < 3 && time.Now().Before(deadline) {
				time.Sleep(10 * time.Millisecond)
			}
			if c.attempts.Load() < 3 {
				t.Fatalf("only %d attempts: the link must be retried", c.attempts.Load())
			}
			if d.Terminal() != nil || d.Status().State == LinkRefusedPermanent {
				t.Errorf("not terminal expected: %v / %+v", d.Terminal(), d.Status())
			}
		})
	}
}

func TestDialedLink_ContextCancelIsNotARefusal(t *testing.T) {
	c := newAckThenClose(t, "dmz-cancel", 0) // healthy link
	d := realDialer(t, c, "dmz-cancel")
	waitStatus(t, d.Status, LinkConnected)
	// stopping the manager/dialer context must not look like a refusal
	if d.Terminal() != nil {
		t.Errorf("Terminal() = %v while healthy", d.Terminal())
	}
}
