// SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
// SPDX-License-Identifier: AGPL-3.0-or-later

package repeater

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// An orderly stop of the uplink (context cancelled) sends the close frame 1001 "going away" before the
// socket closes: the parent reads peer_closed:1001, not an abnormal 1006 (#244/#246 follow-up of the
// QUALIF r2 remark b).
func TestUplink_OrderlyStopSendsGoingAway(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	up := NewUplink("child", Options{})
	served := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer close(served)
		_ = up.Serve(ctx, c)
	}))
	defer srv.Close()
	c, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	// the first frame is the topology_snapshot: the link is up
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, _, err := c.ReadMessage(); err != nil {
		t.Fatalf("first frame: %v", err)
	}
	cancel()
	for {
		_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
		_, _, err := c.ReadMessage()
		if err == nil {
			continue
		}
		var ce *websocket.CloseError
		if !errors.As(err, &ce) {
			t.Fatalf("read: %v, want a close frame", err)
		}
		if ce.Code != websocket.CloseGoingAway {
			t.Fatalf("close code = %d, want 1001", ce.Code)
		}
		break
	}
	select {
	case <-served:
	case <-time.After(3 * time.Second):
		t.Fatal("Serve did not return after the stop")
	}
}

// A link that ends for another reason than the stop (the parent hangs up) sends no 1001.
func TestUplink_ParentHangupIsNotGoingAway(t *testing.T) {
	up := NewUplink("child", Options{})
	errc := make(chan error, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			return
		}
		errc <- up.Serve(context.Background(), c)
	}))
	defer srv.Close()
	c, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, _, err := c.ReadMessage(); err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	select {
	case <-errc:
	case <-time.After(3 * time.Second):
		t.Fatal("Serve did not return after the parent hung up")
	}
}

// A parent that closes with 4010 while the child is writing: the child reads the refusal (permanent),
// whichever of its write failure or the close frame is seen first (a revoked child must not come back).
func TestUplink_Close4010WinsOverAConcurrentWriteFailure(t *testing.T) {
	for i := 0; i < 20; i++ {
		events := make(chan Event, 500)
		for j := 0; j < 500; j++ {
			events <- Event{Event: "host.up", Hostname: "h", RelayChain: []string{}}
		}
		up := NewUplink("child", Options{Events: events})
		errc := make(chan error, 1)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
			if err != nil {
				return
			}
			errc <- up.Serve(context.Background(), c)
		}))
		c, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
		if err != nil {
			t.Fatal(err)
		}
		_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
		if _, _, err := c.ReadMessage(); err != nil { // the snapshot: the link is up
			t.Fatal(err)
		}
		_ = c.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(CloseCodePermanent, "revoked"), time.Now().Add(time.Second))
		_ = c.UnderlyingConn().Close() // the socket goes away right after the close frame
		select {
		case serr := <-errc:
			var ref *refusedError
			if !errors.As(serr, &ref) || !ref.permanent {
				t.Fatalf("iteration %d: Serve returned %v, want a permanent refusal", i, serr)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("Serve did not return")
		}
		srv.Close()
	}
}
