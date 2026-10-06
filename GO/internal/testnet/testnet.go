// Package testnet gives tests loopback ports that cannot be stolen between "release" and "use".
//
// A port obtained with net.Listen("…:0") then Close() sits in the kernel's EPHEMERAL range: until
// the test uses it again, any outgoing connection of the machine (source port) or any other ":0"
// listener can be handed that very port — "bind: address already in use" when the test re-listens,
// or a "closed" address that suddenly answers. Ports of this package come from BELOW that range,
// which the kernel never hands out on its own, and are never returned twice by the process.
package testnet

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"net"
	"os"
	"sync"
	"testing"
)

const bottom = 12000

var (
	mu   sync.Mutex
	used = map[int]bool{} // ports already handed out by this process
)

func ephemeralStart() int {
	top := 32768
	if b, err := os.ReadFile("/proc/sys/net/ipv4/ip_local_port_range"); err == nil {
		var lo, hi int
		if _, err := fmt.Sscanf(string(b), "%d %d", &lo, &hi); err == nil && lo >= 2048 {
			top = lo
		}
	}
	return top
}

// ListenOutsideEphemeralRange binds a loopback port that the kernel never hands out as an ephemeral
// port. It falls back to an ephemeral ":0" port only when the non-ephemeral range is too small or
// exhausted (non-Linux hosts, tiny ranges).
func ListenOutsideEphemeralRange() (net.Listener, error) {
	top := ephemeralStart()
	if top-bottom < 1000 {
		return net.Listen("tcp", "127.0.0.1:0")
	}
	mu.Lock()
	defer mu.Unlock()
	for i := 0; i < 500; i++ {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(top-bottom)))
		if err != nil {
			return nil, err
		}
		port := bottom + int(n.Int64())
		if used[port] {
			continue
		}
		if ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port)); err == nil {
			used[port] = true
			return ln, nil
		}
	}
	return net.Listen("tcp", "127.0.0.1:0")
}

// ClosedAddr returns a loopback "host:port" on which nothing listens (connection refused) and which
// this process will not hand out again.
func ClosedAddr(t testing.TB) string {
	t.Helper()
	ln, err := ListenOutsideEphemeralRange()
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}
