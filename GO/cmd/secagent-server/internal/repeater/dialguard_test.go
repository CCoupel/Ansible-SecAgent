package repeater

// #151a — the SSRF guard applies to the IP ADDRESSES ACTUALLY CONTACTED (DNS rebinding), at every
// dial and every reconnection, on the pull (Client) and push (Dialer) paths.

import (
	"context"
	"errors"
	"net"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"secagent-server/cmd/secagent-server/internal/config"
	"secagent-server/internal/endpoints"
)

func TestInternalReason_MetadataAndTransitionAddresses(t *testing.T) {
	for _, ip := range []string{
		"169.254.169.254", "100.100.100.200", "168.63.129.16", "192.0.0.192", "fd00:ec2::254",
		"127.0.0.1", "::1", "0.0.0.0", "::", "169.254.0.1", "fe80::1", "224.0.0.9", "ff02::1",
		"::ffff:169.254.169.254", "::ffff:127.0.0.1", // IPv4-mapped
		"64:ff9b::a9fe:a9fe", "64:ff9b::7f00:1", // NAT64 around 169.254.169.254 and 127.0.0.1
		"2002:a9fe:a9fe::1", "2002:7f00:1::1", // 6to4 around the same
	} {
		if internalReason(net.ParseIP(ip)) == "" {
			t.Errorf("%s must be refused", ip)
		}
	}
	for _, ip := range []string{
		"100.64.0.1", "100.100.100.201", "100.127.255.254", // CGNAT / Tailscale stay allowed (only .200 is metadata)
		"10.0.0.1", "172.16.5.5", "192.168.1.218", "fc00::1", "fd12:3456::1", // RFC 1918 / unique-local
		"8.8.8.8", "203.0.113.10", "2001:4860:4860::8888", "64:ff9b::808:808", "2002:808:808::1", // public, also embedded
		"168.63.129.17", "192.0.0.193",
	} {
		if why := internalReason(net.ParseIP(ip)); why != "" {
			t.Errorf("%s must be allowed, refused as %q", ip, why)
		}
	}
}

func TestParseTargetURLs_NonCanonicalNumericHostsAreRefused(t *testing.T) {
	withGuard(t)
	setLookup(t, []net.IP{net.ParseIP("203.0.113.10")}, nil)
	for _, h := range []string{"2130706433", "0x7f000001", "0177.0.0.1", "127.1", "0x7f.1", "0x7f.0x0.0x0.0x1", "4294967295", "017700000001"} {
		_, err := ParseTargetURLs([]string{"wss://" + h + ":7772"})
		if !errors.Is(err, ErrForbiddenTarget) || !strings.Contains(err.Error(), "canonical") {
			t.Errorf("%s: %v", h, err)
		}
		if err != nil && strings.Contains(err.Error(), h) {
			t.Errorf("%s: the error echoes the host", h)
		}
	}
	for _, h := range []string{"10.0.0.1", "123.example.com", "dead.beef", "relay1", "0xg.example", "1.example.net", "8.8.8.8"} {
		if _, err := ParseTargetURLs([]string{"wss://" + h + ":7772"}); err != nil {
			t.Errorf("%s must be accepted: %v", h, err)
		}
	}
}

func TestValidateNewDialTarget_RefusesAnUnresolvableNameButBootStaysLenient(t *testing.T) {
	withGuard(t)
	setLookup(t, nil, errors.New("no such host"))
	tgt := DialTarget{RelayID: "dmz1", URL: "wss://ghost.example.net:7772", Token: "tok"}
	if err := ValidateNewDialTarget(tgt); !errors.Is(err, ErrForbiddenTarget) || !strings.Contains(err.Error(), "cannot resolve the target host") {
		t.Fatalf("registration: %v", err)
	}
	if err := ValidateDialTarget(tgt); err != nil {
		t.Fatalf("a stored target must still boot while the DNS is down: %v", err)
	}
	setLookup(t, []net.IP{net.ParseIP("203.0.113.10")}, nil)
	if err := ValidateNewDialTarget(tgt); err != nil {
		t.Fatalf("a resolvable public name is accepted: %v", err)
	}
}

// rebinder answers a public address for the first `public` lookups (the registration) then `then`.
type rebinder struct {
	lookups atomic.Int32
	public  int32
	then    []net.IP
}

func (r *rebinder) lookup(context.Context, string) ([]net.IP, error) {
	if r.lookups.Add(1) <= r.public {
		return []net.IP{net.ParseIP("203.0.113.10")}, nil
	}
	return r.then, nil
}

func installResolver(t *testing.T, r *rebinder) {
	t.Helper()
	old := lookupIP
	lookupIP = r.lookup
	t.Cleanup(func() { lookupIP = old })
}

func TestGuardedDial_DNSRebindingIsRefusedOnTheIPActuallyContacted(t *testing.T) {
	withGuard(t)
	srv := newMockParent(t, "central") // listens on 127.0.0.1
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(srv.url(), "wss://"))
	for name, then := range map[string][]net.IP{
		"loopback":       {net.ParseIP("127.0.0.1")},
		"metadata":       {net.ParseIP("169.254.169.254")},
		"alibaba":        {net.ParseIP("100.100.100.200")},
		"azure":          {net.ParseIP("168.63.129.16")},
		"all internal":   {net.ParseIP("127.0.0.1"), net.ParseIP("169.254.169.254")},
		"v6 loopback":    {net.ParseIP("::1")},
		"nat64 metadata": {net.ParseIP("64:ff9b::a9fe:a9fe")},
		"empty answer":   {},
	} {
		t.Run(name, func(t *testing.T) {
			installResolver(t, &rebinder{then: then})
			_, err := guardedDial(context.Background(), "tcp", "relay.example.net:"+port)
			if err == nil {
				t.Fatal("the connection must be refused")
			}
			if name != "empty answer" && !errors.Is(err, ErrForbiddenTarget) {
				t.Errorf("want ErrForbiddenTarget, got %v", err)
			}
			// a refusal is a failure BEFORE send: DialFirst tries the next address
			if !endpoints.IsBeforeSend(err) {
				t.Errorf("the refusal must be classified before-send: %v", err)
			}
			if n := srv.accepted.Load(); n != 0 {
				t.Errorf("the internal server received %d connection(s)", n)
			}
		})
	}
}

// a name that mixes an internal and a public address never reaches the internal one: the allowed
// addresses are dialed, the others are skipped (no connect, no accept on the listener).
func TestGuardedDial_MixedAnswerNeverTouchesTheInternalAddress(t *testing.T) {
	withGuard(t)
	srv := newMockParent(t, "central")
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(srv.url(), "wss://"))
	// the only dialable address of the answer is internal (127.0.0.1): the public one is a TEST-NET
	// address (unreachable here); the call fails, and the loopback listener saw nothing
	installResolver(t, &rebinder{then: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("203.0.113.77")}})
	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()
	if _, err := guardedDial(ctx, "tcp", "relay.example.net:"+port); err == nil {
		t.Fatal("203.0.113.77 is unreachable here: the dial must fail")
	}
	if srv.accepted.Load() != 0 {
		t.Error("the internal address was contacted")
	}
}

func TestGuardedDial_LiteralAndLocalhostAndNumericFormsAreRefused(t *testing.T) {
	withGuard(t)
	installResolver(t, &rebinder{public: 1 << 30})
	for _, addr := range []string{"127.0.0.1:1", "[::1]:1", "169.254.169.254:80", "localhost:1", "x.localhost:1", "2130706433:1", "0x7f000001:1", "0177.0.0.1:1", "100.100.100.200:80"} {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second) // a missing check would try to connect
		_, err := guardedDial(ctx, "tcp", addr)
		cancel()
		if !errors.Is(err, ErrForbiddenTarget) {
			t.Errorf("%s: %v", addr, err)
		}
	}
}

// The connect(2) barrier (net.Dialer.Control) is independent of the resolution check.
func TestRejectInternalSocket(t *testing.T) {
	for _, a := range []string{"127.0.0.1:443", "[::1]:443", "169.254.169.254:80", "100.100.100.200:80", "0.0.0.0:1", "[64:ff9b::a9fe:a9fe]:80", "not-an-address", "example.net:443", "[fe80::1]:1"} {
		if err := rejectInternalSocket(a); !errors.Is(err, ErrForbiddenTarget) {
			t.Errorf("%s: %v", a, err)
		}
	}
	for _, a := range []string{"203.0.113.10:443", "10.1.2.3:7772", "100.64.0.9:443", "[2001:4860:4860::8888]:443"} {
		if err := rejectInternalSocket(a); err != nil {
			t.Errorf("%s: %v", a, err)
		}
	}
}

func TestGuardedDial_AllowInternalStillDialsThroughTheResolver(t *testing.T) {
	srv := newMockParent(t, "central")
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(srv.url(), "wss://"))
	old := lookupIP
	lookupIP = func(context.Context, string) ([]net.IP, error) { return []net.IP{net.ParseIP("127.0.0.1")}, nil }
	defer func() { lookupIP = old }()
	UnsafeAllowInternalDialTargets(true) // the test harness mode (main_test sets it for the package)
	c, err := guardedDial(context.Background(), "tcp", "relay.example.net:"+port)
	if err != nil {
		t.Fatalf("harness mode must connect: %v", err)
	}
	_ = c.Close()
}

// ── the real links: pull (Client) and push (Dialer), registration then rebinding ──

func TestRebinding_PushDialerNeverContactsAnInternalAddress_EvenOnReconnection(t *testing.T) {
	withGuard(t)
	child := newMockChild(t, "dmz1")
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(child.url(), "wss://"))
	for name, internal := range map[string]string{"loopback": "127.0.0.1", "metadata": "169.254.169.254", "alibaba": "100.100.100.200"} {
		t.Run(name, func(t *testing.T) {
			rb := &rebinder{public: 2, then: []net.IP{net.ParseIP(internal)}} // lookups 1-2: NewDialer and Start validate
			installResolver(t, rb)
			serve := make(chan serveCall, 4)
			opts := dialerOpts(serve)
			opts.TLSConfig = testTLS()
			opts.MinBackoff, opts.MaxBackoff = 5*time.Millisecond, 10*time.Millisecond
			d, err := NewDialer(DialTarget{RelayID: "dmz1", URL: "wss://relay.example.net:" + port, Token: "tok"}, opts)
			if err != nil {
				t.Fatalf("the name looked public at registration: %v", err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if err := d.Start(ctx); err != nil {
				t.Fatal(err)
			}
			deadline := time.Now().Add(5 * time.Second)
			for rb.lookups.Load() < 6 && time.Now().Before(deadline) {
				time.Sleep(10 * time.Millisecond)
			}
			if got := rb.lookups.Load(); got < 6 {
				t.Fatalf("only %d resolutions: the dialer does not reconnect", got)
			}
			cancel()
			if n := child.accepts.Load(); n != 0 {
				t.Fatalf("the internal child was contacted %d time(s)", n)
			}
			select {
			case <-serve:
				t.Fatal("a session was established with an internal address")
			default:
			}
		})
	}
}

func TestRebinding_PullClientNeverContactsAnInternalAddress_EvenOnReconnection(t *testing.T) {
	withGuard(t)
	parent := newMockParent(t, "central")
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(parent.url(), "wss://"))
	rb := &rebinder{public: 0, then: []net.IP{net.ParseIP("169.254.169.254")}}
	installResolver(t, rb)
	opts := Options{TLSConfig: testTLS(), MinBackoff: 5 * time.Millisecond, MaxBackoff: 10 * time.Millisecond}
	u := "wss://relay.example.net:" + port
	if _, err := url.Parse(u); err != nil {
		t.Fatal(err)
	}
	c := New(config.RepeaterConfig{ID: "dmz1", UpstreamURLs: []string{u}, UpstreamToken: "tok"}, opts)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := c.Start(ctx); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for rb.lookups.Load() < 6 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if rb.lookups.Load() < 6 {
		t.Fatalf("only %d resolutions: the client does not reconnect", rb.lookups.Load())
	}
	cancel()
	if n := parent.accepted.Load(); n != 0 {
		t.Fatalf("the internal parent was contacted %d time(s)", n)
	}
}
