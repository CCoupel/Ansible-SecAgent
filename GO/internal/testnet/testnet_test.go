package testnet

import (
	"net"
	"strconv"
	"testing"
	"time"
)

func TestClosedAddrRefusesConnectionsAndIsNotReused(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		a := ClosedAddr(t)
		if seen[a] {
			t.Fatalf("%s handed out twice", a)
		}
		seen[a] = true
		_, ps, _ := net.SplitHostPort(a)
		port, _ := strconv.Atoi(ps)
		mu.Lock()
		reserved := used[port]
		mu.Unlock()
		if !reserved {
			t.Fatalf("%s is not reserved: ListenOutsideEphemeralRange could hand it out again while the test relies on it being closed", a)
		}
		if c, err := net.DialTimeout("tcp", a, time.Second); err == nil {
			_ = c.Close()
			t.Fatalf("%s accepted a connection: it must be closed", a)
		}
	}
}

func TestListenOutsideEphemeralRange(t *testing.T) {
	top := ephemeralStart()
	if top-bottom < 1000 {
		t.Skip("no non-ephemeral range on this host")
	}
	seen := map[int]bool{}
	for i := 0; i < 20; i++ {
		ln, err := ListenOutsideEphemeralRange()
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = ln.Close() }()
		p := ln.Addr().(*net.TCPAddr).Port
		if p < bottom || p >= top {
			t.Errorf("port %d is not in [%d,%d), i.e. may be an ephemeral port", p, bottom, top)
		}
		if seen[p] {
			t.Errorf("port %d handed out twice", p)
		}
		seen[p] = true
	}
}
