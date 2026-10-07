package repeater

// #151 (L7) — the REAL dial policy against the specification (matrix, configuration, enforcement at
// registration and at every dial, rebinding with ALLOW) and the lock on HTTP redirections (3xx),
// which needs no new code and runs today.

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"secagent-server/cmd/secagent-server/internal/config"
)

func requirePolicy(t *testing.T) *specDialPolicy {
	t.Helper()
	p := specDialPolicyUnderTest
	if p == nil || p.Configure == nil || p.Category == nil {
		t.Skip("PENDING #151: the dial policy is not wired yet (create dialpolicy_spec_wire_test.go that sets specDialPolicyUnderTest)")
	}
	return p
}

// useGuardWith switches the SSRF guard on (the package tests run with it off), applies the policy
// and restores everything at the end.
func useGuardWith(t *testing.T, p *specDialPolicy, allowLoopback bool, deny, allow string) {
	t.Helper()
	withGuard(t)
	restore, err := p.Configure(allowLoopback, deny, allow)
	if err != nil {
		t.Fatalf("Configure(%v,%q,%q): %v", allowLoopback, deny, allow, err)
	}
	t.Cleanup(restore)
}

func TestSpecDialPolicy_RealPolicyConformsToTheMatrix(t *testing.T) {
	p := requirePolicy(t)
	withGuard(t)
	for _, c := range specPolicyCases {
		t.Run(c.Name, func(t *testing.T) {
			restore, err := p.Configure(c.Loop, c.Deny, c.Allow)
			if err != nil {
				if !c.AcceptConfig {
					t.Fatalf("valid configuration refused: %v", err)
				}
				return
			}
			defer restore()
			if got := p.Category(net.ParseIP(c.IP)); got != c.Want {
				t.Errorf("%s under loop=%v deny=%q allow=%q: category %q, want %q", c.IP, c.Loop, c.Deny, c.Allow, got, c.Want)
			}
		})
	}
}

func TestSpecDialPolicy_RealConfigurationIsValidatedFailClosed(t *testing.T) {
	p := requirePolicy(t)
	withGuard(t)
	for _, c := range specConfigCases {
		t.Run(c.Name, func(t *testing.T) {
			restore, err := p.Configure(false, c.Deny, c.Allow)
			if err == nil {
				defer restore()
			}
			if c.Valid && err != nil {
				t.Errorf("must be accepted: %v", err)
			}
			if !c.Valid && err == nil {
				t.Error("must be refused: the process must refuse to start")
			}
			if err != nil && c.Deny != "" && strings.Contains(err.Error(), "secret") {
				t.Errorf("the error must not carry a secret: %v", err)
			}
		})
	}
}

func TestSpecDialPolicy_TheLoopbackSettingIsAStrictBoolean(t *testing.T) {
	p := requirePolicy(t)
	if p.FromEnv == nil {
		t.Skip("PENDING #151: FromEnv not wired")
	}
	for _, v := range []string{"true", "false"} {
		if err := p.FromEnv(map[string]string{"REPEATER_DIAL_ALLOW_LOOPBACK": v}); err != nil {
			t.Errorf("%q must be accepted: %v", v, err)
		}
	}
	for _, v := range []string{"yes", "1", "TRUE", "True", " true", "true ", "on", "enabled", "0", "no"} {
		if err := p.FromEnv(map[string]string{"REPEATER_DIAL_ALLOW_LOOPBACK": v}); err == nil {
			t.Errorf("%q must be refused (strict boolean, like envStrictBool): refuse to start", v)
		}
	}
	if err := p.FromEnv(map[string]string{}); err != nil {
		t.Errorf("unset = default false, must start: %v", err)
	}
	if err := p.FromEnv(map[string]string{"REPEATER_DIAL_DENY_CIDRS": "0.0.0.0/0"}); err == nil {
		t.Error("an invalid list read from the environment must refuse the start")
	}
}

// tcpCounter listens on a loopback port chosen by the system (no hard-coded port) and counts the
// connections it receives.
func tcpCounter(t *testing.T) (port string, accepts *atomic.Int32) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	accepts = &atomic.Int32{}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			accepts.Add(1)
			_ = c.Close()
		}
	}()
	t.Cleanup(func() { _ = l.Close() })
	_, port, _ = net.SplitHostPort(l.Addr().String())
	return port, accepts
}

// settle waits until the listener has accepted `want` connections, then proves that nothing else is
// on its way: a raw connection (outside the guard) is accepted AFTER every earlier one, so once it is
// counted, any connection the guarded dialer had made before is counted too. No fixed sleep.
func settle(t *testing.T, port string, accepts *atomic.Int32, want int32) {
	t.Helper()
	waitHits(t, "the listener accepted the expected connections", accepts, want)
	c, err := net.Dial("tcp", "127.0.0.1:"+port)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	waitHits(t, "the barrier connection", accepts, want+1)
	if got := accepts.Load(); got != want+1 {
		t.Errorf("accepts = %d, want %d: a refused dial reached the network", got-1, want)
	}
}

func dialCtx(t *testing.T, addr string) (net.Conn, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return guardedDial(ctx, "tcp", addr)
}

func resolveTo(t *testing.T, ips ...string) {
	t.Helper()
	var l []net.IP
	for _, s := range ips {
		l = append(l, net.ParseIP(s))
	}
	setLookup(t, l, nil)
}

// DNS rebinding WITH an allow list: the name was fine when validated; at dial time it points elsewhere.
func TestSpecDialPolicy_RebindingOutsideAllowIsRefusedAtDialTime(t *testing.T) {
	p := requirePolicy(t)
	useGuardWith(t, p, true, "", "127.0.0.0/8")
	port, accepts := tcpCounter(t)

	resolveTo(t, "127.0.0.1") // validation / first connection: inside ALLOW
	conn, err := dialCtx(t, "relay.example.test:"+port)
	if err != nil {
		t.Fatalf("a name resolving inside ALLOW must connect: %v", err)
	}
	_ = conn.Close()

	resolveTo(t, "10.9.9.9") // the same name later resolves outside ALLOW (rebinding)
	if _, err := dialCtx(t, "relay.example.test:"+port); !errors.Is(err, ErrForbiddenTarget) {
		t.Fatalf("a name that now resolves outside ALLOW must be refused at dial time, got %v", err)
	}
	settle(t, port, accepts, 1) // exactly the first connection: the refused dial never reached the network
}

// A name that resolves to a mix of allowed and refused addresses only ever reaches the allowed one.
func TestSpecDialPolicy_MixedResolutionOnlyReachesTheAllowedAddress(t *testing.T) {
	p := requirePolicy(t)
	useGuardWith(t, p, true, "", "127.0.0.0/8")
	port, accepts := tcpCounter(t)
	resolveTo(t, "10.9.9.9", "169.254.169.254", "127.0.0.1")
	conn, err := dialCtx(t, "mixed.example.test:"+port)
	if err != nil {
		t.Fatalf("the allowed address must be reached: %v", err)
	}
	_ = conn.Close()
	settle(t, port, accepts, 1) // only the allowed address was reached, once
}

func TestSpecDialPolicy_DenyAndLoopbackRefusalsNeverReachTheNetwork(t *testing.T) {
	p := requirePolicy(t)
	port, accepts := tcpCounter(t)
	for _, tc := range []struct {
		name         string
		loop         bool
		deny, allow  string
		addr, lookup string
	}{
		{"loopback without opt-in, literal", false, "", "", "127.0.0.1:" + port, ""},
		{"loopback without opt-in, by name", false, "", "", "lo.example.test:" + port, "127.0.0.1"},
		{"loopback opted in but denied, literal", true, "127.0.0.0/8", "", "127.0.0.1:" + port, ""},
		{"loopback opted in but denied, by name", true, "127.0.0.0/8", "", "lo.example.test:" + port, "127.0.0.1"},
		{"loopback opted in but ALLOW names only another range", true, "", "192.168.0.0/16", "127.0.0.1:" + port, ""},
		{"ALLOW naming loopback does not lift it", false, "", "127.0.0.0/8", "127.0.0.1:" + port, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			useGuardWith(t, p, tc.loop, tc.deny, tc.allow)
			if tc.lookup != "" {
				resolveTo(t, tc.lookup)
			}
			before := accepts.Load()
			if _, err := dialCtx(t, tc.addr); !errors.Is(err, ErrForbiddenTarget) {
				t.Fatalf("want ErrForbiddenTarget, got %v", err)
			}
			settle(t, port, accepts, before) // nothing reached the listener: the refusal came before the network
		})
	}
}

func TestSpecDialPolicy_AllowCanNeverLiftABuiltInProhibition(t *testing.T) {
	p := requirePolicy(t)
	for _, tc := range []struct{ allow, addr string }{
		{"169.254.0.0/16", "169.254.169.254:80"},
		{"100.64.0.0/10", "100.100.100.200:80"},
		{"fc00::/7", "[fd00:ec2::254]:80"},
		{"168.63.129.0/24", "168.63.129.16:80"},
		{"255.255.255.255/32", "255.255.255.255:80"},
		{"224.0.0.0/4", "224.0.0.1:80"},
		{"0.0.0.0/8", "0.0.0.0:80"},
	} {
		withGuard(t)
		restore, err := p.Configure(true, "", tc.allow)
		if err != nil {
			continue // refusing such a configuration is also fail closed
		}
		if _, derr := dialCtx(t, tc.addr); !errors.Is(derr, ErrForbiddenTarget) {
			t.Errorf("ALLOW %s must not lift %s: %v", tc.allow, tc.addr, derr)
		}
		restore()
	}
}

// Registration (POST /api/admin/relays push) uses the same policy as the dial.
func TestSpecDialPolicy_RegistrationAppliesTheSamePolicy(t *testing.T) {
	p := requirePolicy(t)

	useGuardWith(t, p, false, "10.0.0.0/8", "")
	setLookup(t, []net.IP{net.ParseIP("203.0.113.10")}, nil)
	_, err := ParseTargetURLs([]string{"wss://10.1.2.3:7772"})
	if !errors.Is(err, ErrForbiddenTarget) {
		t.Errorf("an address inside DENY must be refused at registration: %v", err)
	}
	if err != nil && strings.Contains(err.Error(), "10.1.2.3") {
		t.Errorf("the error must not echo the address: %v", err)
	}
	if _, err := ParseTargetURLs([]string{"wss://relay.example.test:7772"}); err != nil {
		t.Errorf("a name outside DENY must be accepted: %v", err)
	}
	if _, err := ParseTargetURLs([]string{"wss://192.168.1.5:7772", "wss://10.1.2.3:7772"}); !errors.Is(err, ErrForbiddenTarget) {
		t.Errorf("one refused address refuses the whole list: %v", err)
	}
	setLookup(t, []net.IP{net.ParseIP("10.5.5.5")}, nil)
	if _, err := ParseTargetURLs([]string{"wss://relay.example.test:7772"}); !errors.Is(err, ErrForbiddenTarget) {
		t.Errorf("a name resolving inside DENY must be refused at registration: %v", err)
	}

	useGuardWith(t, p, false, "", "192.168.0.0/16")
	setLookup(t, []net.IP{net.ParseIP("192.168.1.5")}, nil)
	if _, err := ParseTargetURLs([]string{"wss://192.168.1.5:7772", "wss://relay.example.test:7772"}); err != nil {
		t.Errorf("addresses inside ALLOW must be accepted: %v", err)
	}
	if _, err := ParseTargetURLs([]string{"wss://203.0.113.5:7772"}); !errors.Is(err, ErrForbiddenTarget) {
		t.Errorf("an address outside ALLOW must be refused: %v", err)
	}
	setLookup(t, []net.IP{net.ParseIP("203.0.113.10")}, nil)
	if _, err := ParseTargetURLs([]string{"wss://relay.example.test:7772"}); !errors.Is(err, ErrForbiddenTarget) {
		t.Errorf("a name resolving outside ALLOW must be refused: %v", err)
	}
}

// ── HTTP redirections are never followed (runs today: locks the current behaviour) ──────────────────

// redirector answers every request with a 3xx to target and counts what it received.
type redirector struct {
	srv  *httptest.Server
	hits atomic.Int32
	auth atomic.Value // last Authorization header seen
}

func newRedirector(t *testing.T, code int, target string) *redirector {
	t.Helper()
	r := &redirector{}
	r.auth.Store("")
	r.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.hits.Add(1)
		r.auth.Store(req.Header.Get("Authorization"))
		http.Redirect(w, req, target, code)
	}))
	t.Cleanup(r.srv.Close)
	return r
}

// sink is the redirection target: it must never be contacted.
type sink struct {
	srv  *httptest.Server
	hits atomic.Int32
	auth atomic.Value
}

func newSink(t *testing.T) *sink {
	t.Helper()
	s := &sink{}
	s.auth.Store("")
	s.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		s.hits.Add(1)
		s.auth.Store(req.Header.Get("Authorization"))
		http.Error(w, "sink", http.StatusTeapot)
	}))
	t.Cleanup(s.srv.Close)
	return s
}

func waitHits(t *testing.T, what string, n *atomic.Int32, atLeast int32) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if n.Load() >= atLeast {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("%s: %d hits after 5s, want >= %d", what, n.Load(), atLeast)
}

var redirectCodes = []int{http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect, http.StatusPermanentRedirect}

func TestPushDialer_NeverFollowsARedirection(t *testing.T) {
	for _, code := range redirectCodes {
		t.Run(http.StatusText(code), func(t *testing.T) {
			target := newSink(t)
			rd := newRedirector(t, code, target.srv.URL+"/ws/relay")
			serve := make(chan serveCall, 4)
			d, err := NewDialer(DialTarget{RelayID: "dmz1", URL: "wss" + strings.TrimPrefix(rd.srv.URL, "https"), Token: "tok-secret"}, dialerOpts(serve))
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if err := d.Start(ctx); err != nil {
				t.Fatal(err)
			}
			waitHits(t, "the redirecting server", &rd.hits, 2) // several attempts: the loop keeps trying, never follows
			if n := target.hits.Load(); n != 0 {
				t.Errorf("the redirection target was contacted %d time(s): a 3xx must never be followed", n)
			}
			if a, _ := target.auth.Load().(string); a != "" {
				t.Errorf("the link token reached the redirection target: %q", a)
			}
			select {
			case <-serve:
				t.Error("a link must never be established through a redirection")
			case <-time.After(200 * time.Millisecond):
			}
		})
	}
}

func TestPullClient_NeverFollowsARedirection(t *testing.T) {
	for _, code := range redirectCodes {
		t.Run(http.StatusText(code), func(t *testing.T) {
			target := newSink(t)
			rd := newRedirector(t, code, target.srv.URL+"/ws/relay")
			opts := Options{TLSConfig: &tls.Config{InsecureSkipVerify: true}, MinBackoff: 10 * time.Millisecond, MaxBackoff: 40 * time.Millisecond} //nolint:gosec // test server cert
			c := New(config.RepeaterConfig{ID: "dmz1", UpstreamURL: "wss" + strings.TrimPrefix(rd.srv.URL, "https"), UpstreamToken: "tok-secret"}, opts)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if err := c.Start(ctx); err != nil {
				t.Fatal(err)
			}
			waitHits(t, "the redirecting parent", &rd.hits, 2)
			if n := target.hits.Load(); n != 0 {
				t.Errorf("the redirection target was contacted %d time(s): a 3xx must never be followed", n)
			}
			if a, _ := target.auth.Load().(string); a != "" {
				t.Errorf("the upstream token reached the redirection target: %q", a)
			}
			if c.ParentID() != "" {
				t.Errorf("no parent identity may be learned through a redirection, got %q", c.ParentID())
			}
		})
	}
}
