package server

import (
	"net"
	"testing"
)

func TestIsListening_EffectiveAddress(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	if !isListening(ln.Addr()) {
		t.Error("an open listener must be reported as listening")
	}
	_ = ln.Close()
	if isListening(ln.Addr()) {
		t.Error("a closed port must not be reported as listening")
	}
}

func TestIsListening_UnspecifiedHostIsDialedThroughLoopback(t *testing.T) {
	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	if !isListening(ln.Addr()) {
		t.Error("[::]:port / :port must be reachable through the loopback")
	}
}
