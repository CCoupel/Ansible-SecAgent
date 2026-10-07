package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// trustProxies installs the trusted proxy CIDRs for one test and clears them afterwards.
func trustProxies(t *testing.T, list string) {
	t.Helper()
	nets, err := ParseTrustedProxyCIDRs(list)
	if err != nil {
		t.Fatal(err)
	}
	SetTrustedProxies(nets)
	t.Cleanup(func() { SetTrustedProxies(nil) })
}

func xffReq(remote string, xff ...string) *http.Request {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = remote
	for _, v := range xff {
		r.Header.Add("X-Forwarded-For", v)
	}
	return r
}

func TestClientAddr_Table(t *testing.T) {
	cases := []struct {
		name       string
		trusted    string
		remote     string
		xff        []string
		wantClient string
		wantPeer   string
	}{
		{"default: no trusted proxy, forged XFF ignored", "", "203.0.113.9:4000", []string{"10.0.0.1"}, "203.0.113.9", "203.0.113.9"},
		{"default: XFF with several forged hops ignored", "", "203.0.113.9:4000", []string{"10.0.0.1, 192.168.0.1"}, "203.0.113.9", "203.0.113.9"},
		{"trusted proxy relays one hop", "10.0.0.0/8", "10.0.0.5:80", []string{"198.51.100.7"}, "198.51.100.7", "10.0.0.5"},
		{"right-to-left: client-forged leftmost entry is not believed", "10.0.0.0/8", "10.0.0.5:80", []string{"10.9.9.9, 198.51.100.7"}, "198.51.100.7", "10.0.0.5"},
		{"intermediate trusted proxy skipped", "10.0.0.0/8", "10.0.0.5:80", []string{"198.51.100.7, 10.1.1.1"}, "198.51.100.7", "10.0.0.5"},
		{"forged left, real client right: the rightmost untrusted wins", "10.0.0.0/8", "10.0.0.5:80", []string{"1.2.3.4, 198.51.100.7"}, "198.51.100.7", "10.0.0.5"},
		{"several header lines are concatenated", "10.0.0.0/8", "10.0.0.5:80", []string{"1.2.3.4", "198.51.100.7"}, "198.51.100.7", "10.0.0.5"},
		{"untrusted peer with XFF while proxies are configured: XFF ignored", "10.0.0.0/8", "203.0.113.9:4000", []string{"10.0.0.1"}, "203.0.113.9", "203.0.113.9"},
		{"trusted proxy without XFF: the proxy itself", "10.0.0.0/8", "10.0.0.5:80", nil, "10.0.0.5", "10.0.0.5"},
		{"all hops trusted: the peer", "10.0.0.0/8", "10.0.0.5:80", []string{"10.1.1.1, 10.2.2.2"}, "10.0.0.5", "10.0.0.5"},
		{"unparsable entry: fail safe to the peer", "10.0.0.0/8", "10.0.0.5:80", []string{"not-an-ip"}, "10.0.0.5", "10.0.0.5"},
		{"entry with a port", "10.0.0.0/8", "10.0.0.5:80", []string{"198.51.100.7:5555"}, "198.51.100.7", "10.0.0.5"},
		{"IPv6 client", "fd00::/8", "[fd00::1]:80", []string{"2001:db8::7"}, "2001:db8::7", "fd00::1"},
		{"peer without port", "", "127.0.0.1", nil, "127.0.0.1", "127.0.0.1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.trusted != "" {
				trustProxies(t, tc.trusted)
			}
			c, p := clientAddr(xffReq(tc.remote, tc.xff...))
			if c != tc.wantClient || p != tc.wantPeer {
				t.Errorf("clientAddr = (%q, %q), want (%q, %q)", c, p, tc.wantClient, tc.wantPeer)
			}
		})
	}
}

func TestParseTrustedProxyCIDRs(t *testing.T) {
	if nets, err := ParseTrustedProxyCIDRs(""); err != nil || len(nets) != 0 {
		t.Errorf("empty = (%v, %v), want no networks and no error", nets, err)
	}
	if nets, err := ParseTrustedProxyCIDRs(" 10.0.0.0/8 , 192.168.1.0/24,"); err != nil || len(nets) != 2 {
		t.Errorf("valid list = (%v, %v)", nets, err)
	}
	for _, bad := range []string{"10.0.0.0/33", "banana", "10.0.0.0/8,300.1.1.1/8", "10.0.0.1"} {
		if _, err := ParseTrustedProxyCIDRs(bad); err == nil {
			t.Errorf("%q must be refused", bad)
		}
	}
}

// #177b: a /0 range would make every peer a trusted proxy and neutralise allowed_ips.
func TestParseTrustedProxyCIDRs_RefusesPrefixZero(t *testing.T) {
	for _, bad := range []string{"0.0.0.0/0", "::/0", "1.2.3.4/0", "10.0.0.0/8,0.0.0.0/0", " ::/0 ,10.0.0.0/8", "::ffff:0:0/96"} {
		nets, err := ParseTrustedProxyCIDRs(bad)
		if err == nil || nets != nil {
			t.Errorf("%q must be refused, got (%v, %v)", bad, nets, err)
		}
		if err != nil && !strings.Contains(err.Error(), EnvTrustedProxyCIDRs) {
			t.Errorf("%q: error should name the variable: %v", bad, err)
		}
	}
	// the message is exact for each case and never echoes the value
	for in, want := range map[string]string{"0.0.0.0/0": "prefix length 0", "::/0": "prefix length 0", "::ffff:0:0/96": "every IPv4 address"} {
		_, err := ParseTrustedProxyCIDRs(in)
		if err == nil || !strings.Contains(err.Error(), want) || strings.Contains(err.Error(), in) {
			t.Errorf("%q: error %v, want it to say %q without echoing the value", in, err, want)
		}
	}
	// the widest legitimate ranges stay accepted
	for _, ok := range []string{"0.0.0.0/1", "::/1", "10.0.0.0/8", "::ffff:10.0.0.0/104", "2001:db8::/32"} {
		if _, err := ParseTrustedProxyCIDRs(ok); err != nil {
			t.Errorf("%q must be accepted: %v", ok, err)
		}
	}
}

// #177 end to end through the plugin token check: with no trusted proxy a forged XFF cannot
// satisfy allowed_ips.
func TestPluginAuth_ForgedXFFDoesNotBypassAllowedIPs(t *testing.T) {
	s := newTestStore(t)
	SetAdminStore(s)
	plain := "secagent_plg_forged_xff_01"
	insertPluginTokenFull(t, "tok-forged-xff-01", plain, "forged", "10.0.0.0/8", "", nil, false)

	req := pluginReqWithDetails("POST", "/api/exec/host", plain, "203.0.113.9:4000", "10.0.0.1", "")
	w := httptest.NewRecorder()
	if _, ok := requirePluginAuth(w, req); ok {
		t.Fatal("a forged X-Forwarded-For must not pass the allowed_ips filter")
	}
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}

	// behind a trusted proxy the same header is honored
	trustProxies(t, "203.0.113.0/24")
	w = httptest.NewRecorder()
	if _, ok := requirePluginAuth(w, req); !ok {
		t.Errorf("XFF behind a trusted proxy must be honored: %d %s", w.Code, w.Body.String())
	}
}
