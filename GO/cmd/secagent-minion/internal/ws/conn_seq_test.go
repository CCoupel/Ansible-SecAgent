// SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
// SPDX-License-Identifier: AGPL-3.0-or-later

package ws

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/gorilla/websocket"
)

// seqServer note l'en-tête X-SecAgent-Conn-Seq de chaque requête ; refuse en 401 tant que
// *refuse > 0 (décrémenté à chaque refus), sinon fait l'upgrade.
func seqServer(t *testing.T, refuse *atomic.Int32) (*url.URL, *[]string, *sync.Mutex) {
	t.Helper()
	var seen []string
	var mu sync.Mutex
	up := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Header.Get("X-SecAgent-Conn-Seq"))
		mu.Unlock()
		if refuse != nil && refuse.Add(-1) >= 0 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		_ = c.Close()
	}))
	t.Cleanup(srv.Close)
	u, err := url.Parse("ws" + strings.TrimPrefix(srv.URL, "http"))
	if err != nil {
		t.Fatal(err)
	}
	return u, &seen, &mu
}

func dialSeq(t *testing.T, d *Dispatcher, u *url.URL) error {
	t.Helper()
	c, err := d.dialOne(context.Background(), u, nil, "jwt")
	if c != nil {
		_ = c.Close()
	}
	return err
}

func TestConnSeqHeaderIncrementsOnSuccess(t *testing.T) {
	t.Parallel()
	u, seen, mu := seqServer(t, nil)
	d := NewDispatcher(ConnConfig{}, nil)
	for i := 0; i < 3; i++ {
		if err := dialSeq(t, d, u); err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if got := strings.Join(*seen, ","); got != "1,2,3" {
		t.Fatalf("en-têtes = %q, attendu 1,2,3", got)
	}
}

func TestConnSeqFailedAttemptsDoNotCount(t *testing.T) {
	t.Parallel()
	var refuse atomic.Int32
	refuse.Store(2)
	u, seen, mu := seqServer(t, &refuse)
	d := NewDispatcher(ConnConfig{}, nil)
	for i := 0; i < 2; i++ {
		if err := dialSeq(t, d, u); err == nil {
			t.Fatalf("dial %d: 401 attendu", i)
		}
	}
	if err := dialSeq(t, d, u); err != nil {
		t.Fatal(err)
	}
	if err := dialSeq(t, d, u); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	// 2 échecs et 1re réussite portent 1 ; la reconnexion porte 2.
	if got := strings.Join(*seen, ","); got != "1,1,1,2" {
		t.Fatalf("en-têtes = %q, attendu 1,1,1,2", got)
	}
}

func TestConnSeqRestartsAtOne(t *testing.T) {
	t.Parallel()
	u, seen, mu := seqServer(t, nil)
	d1 := NewDispatcher(ConnConfig{}, nil)
	for i := 0; i < 2; i++ {
		if err := dialSeq(t, d1, u); err != nil {
			t.Fatal(err)
		}
	}
	d2 := NewDispatcher(ConnConfig{}, nil) // nouveau process
	if err := dialSeq(t, d2, u); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if got := strings.Join(*seen, ","); got != "1,2,1" {
		t.Fatalf("en-têtes = %q, attendu 1,2,1", got)
	}
}
