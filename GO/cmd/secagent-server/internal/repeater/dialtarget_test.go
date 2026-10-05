package repeater

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
)

func withGuard(t *testing.T) {
	t.Helper()
	UnsafeAllowInternalDialTargets(false)
	t.Cleanup(func() { UnsafeAllowInternalDialTargets(true) })
}

func TestParseTargetURLs_RefusesInternalAddresses(t *testing.T) {
	withGuard(t)
	for _, h := range []string{
		"127.0.0.1", "[::1]", "localhost", "0.0.0.0", "[::]", "169.254.169.254", "[fd00:ec2::254]",
		"169.254.10.10", "224.0.0.1", "[fe80::1]", "0.1.2.3",
	} {
		_, err := ParseTargetURLs([]string{"wss://" + h + ":7772"})
		if !errors.Is(err, ErrForbiddenTarget) {
			t.Errorf("%s: want ErrForbiddenTarget, got %v", h, err)
		}
		if err != nil && h != "localhost" && strings.Contains(err.Error(), h) { // "localhost" is the reason itself
			t.Errorf("%s: the error echoes the address: %v", h, err)
		}
	}
}

func TestParseTargetURLs_AcceptsPrivateRangesAndNames(t *testing.T) {
	withGuard(t)
	setLookup(t, nil, errors.New("no such host"))
	for _, h := range []string{"10.1.2.3", "172.16.0.9", "192.168.1.218", "dmz1.example.net"} {
		if _, err := ParseTargetURLs([]string{"wss://" + h + ":7772"}); err != nil {
			t.Errorf("%s must be accepted: %v", h, err)
		}
	}
}

func TestParseTargetURLs_OneForbiddenAddressRefusesTheWholeList(t *testing.T) {
	withGuard(t)
	_, err := ParseTargetURLs([]string{"wss://10.0.0.1:7772", "wss://169.254.169.254:7772", "wss://10.0.0.2:7772"})
	if !errors.Is(err, ErrForbiddenTarget) || !strings.Contains(err.Error(), "url #2") {
		t.Fatalf("want ErrForbiddenTarget on url #2, got %v", err)
	}
	if _, err := ParseTargetURLs([]string{"wss://10.0.0.1:7772", "wss://10.0.0.2:7772"}); err != nil {
		t.Fatalf("a clean list is accepted: %v", err)
	}
}

func TestParseTargetURLs_ResolvedInternalIPIsRefused(t *testing.T) {
	withGuard(t)
	setLookup(t, []net.IP{net.ParseIP("10.0.0.5"), net.ParseIP("127.0.0.1")}, nil)
	if _, err := ParseTargetURLs([]string{"wss://sneaky.example.net:7772"}); !errors.Is(err, ErrForbiddenTarget) {
		t.Fatalf("a name resolving to loopback must be refused, got %v", err)
	}
}

func TestParseTargetURLs_SchemeAndUserinfo(t *testing.T) {
	withGuard(t)
	setLookup(t, nil, errors.New("no such host"))
	cases := map[string]string{
		"https://dmz1:7772":           "wss://",
		"ws://dmz1:7772":              "wss://",
		"wss://user:secret@dmz1:7772": "userinfo",
	}
	for u, want := range cases {
		_, err := ParseTargetURLs([]string{u})
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: want error containing %q, got %v", u, want, err)
		}
		if err != nil && strings.Contains(err.Error(), "secret") {
			t.Errorf("the error leaks the userinfo: %v", err)
		}
	}
	if _, err := ParseTargetURLs(nil); err == nil {
		t.Error("an empty list must be refused")
	}
}

func setLookup(t *testing.T, ips []net.IP, err error) {
	t.Helper()
	old := lookupIP
	lookupIP = func(context.Context, string) ([]net.IP, error) { return ips, err }
	t.Cleanup(func() { lookupIP = old })
}
