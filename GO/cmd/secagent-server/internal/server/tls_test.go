package server

// #175 — native TLS: real nodes (Build + Run) on ephemeral ports, certificates generated per test.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"secagent-server/cmd/secagent-server/internal/ws"
)

// tlsPair is a self-signed certificate (valid for 127.0.0.1 / localhost) and its files.
type tlsPair struct {
	certPath, keyPath string
	leaf              *x509.Certificate
	keyPEM            []byte
}

func (p *tlsPair) pool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(p.leaf)
	return pool
}

func (p *tlsPair) fingerprint() [32]byte { return sha256.Sum256(p.leaf.Raw) }

func genPEM(t *testing.T, name string, notBefore, notAfter time.Time) (certPEM, keyPEM []byte, leaf *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: name},
		NotBefore: notBefore, NotAfter: notAfter,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, DNSNames: []string{"localhost"},
		IsCA: true, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ = x509.ParseCertificate(der)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), leaf
}

// writePair writes a pair into dir (key 0600) and returns it.
func writePair(t *testing.T, dir, name string, notBefore, notAfter time.Time) *tlsPair {
	t.Helper()
	certPEM, keyPEM, leaf := genPEM(t, name, notBefore, notAfter)
	p := &tlsPair{certPath: filepath.Join(dir, "tls.crt"), keyPath: filepath.Join(dir, "tls.key"), leaf: leaf, keyPEM: keyPEM}
	replaceFiles(t, p, certPEM, keyPEM)
	return p
}

func replaceFiles(t *testing.T, p *tlsPair, certPEM, keyPEM []byte) {
	t.Helper()
	// write-then-rename like a real rotation, so a poll never sees a half-written file
	for path, data := range map[string][]byte{p.certPath: certPEM, p.keyPath: keyPEM} {
		tmp := path + ".new"
		if err := os.WriteFile(tmp, data, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(tmp, path); err != nil {
			t.Fatal(err)
		}
	}
}

func validPair(t *testing.T) *tlsPair {
	t.Helper()
	return writePair(t, t.TempDir(), "node", time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour))
}

// tlsNode starts a real node serving TLS with the pair.
func tlsNode(t *testing.T, p *tlsPair, mutate func(*Config)) (n *Node, api, admin, wsAddr string) {
	t.Helper()
	return startNode(t, func(c *Config) {
		c.TLSDisable = false
		c.TLSCert, c.TLSKey = p.certPath, p.keyPath
		c.TLSReloadInterval = 100 * time.Millisecond
		if mutate != nil {
			mutate(c)
		}
	})
}

func httpsClient(pool *x509.CertPool, maxVersion uint16) *http.Client {
	return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool, MaxVersion: maxVersion}, DisableKeepAlives: true,
	}}
}

func peerFingerprint(t *testing.T, addr string, pool *x509.CertPool) [32]byte {
	t.Helper()
	c, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", addr, &tls.Config{RootCAs: pool, ServerName: "127.0.0.1"})
	if err != nil {
		t.Fatalf("TLS dial %s: %v", addr, err)
	}
	defer func() { _ = c.Close() }()
	return sha256.Sum256(c.ConnectionState().PeerCertificates[0].Raw)
}

// logCapture captures the std logger (the server logs through it).
type logCapture struct {
	mu sync.Mutex
	b  strings.Builder
}

func (l *logCapture) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}
func (l *logCapture) String() string { l.mu.Lock(); defer l.mu.Unlock(); return l.b.String() }

func captureStdLog(t *testing.T) *logCapture {
	t.Helper()
	c := &logCapture{}
	prev := log.Writer()
	log.SetOutput(io.MultiWriter(c, prev))
	t.Cleanup(func() { log.SetOutput(prev) })
	return c
}

func TestTLS_PublicPortsServeTLSAndRefuseOldVersions(t *testing.T) {
	p := validPair(t)
	_, api, _, wsAddr := tlsNode(t, p, nil)
	client := httpsClient(p.pool(), 0)
	for name, addr := range map[string]string{"7770 (api)": api, "7772 (ws)": wsAddr} {
		resp, err := client.Get("https://" + addr + "/health")
		if err != nil {
			t.Fatalf("%s: https: %v", name, err)
		}
		_ = resp.Body.Close()
		if resp.TLS == nil || resp.TLS.Version < tls.VersionTLS12 {
			t.Errorf("%s: negotiated version %v", name, resp.TLS)
		}
		// plain HTTP on a TLS port is not served
		if r, err := http.Get("http://" + addr + "/health"); err == nil {
			if r.StatusCode == http.StatusOK {
				t.Errorf("%s: served a plain HTTP request on a TLS port", name)
			}
			_ = r.Body.Close()
		}
		// TLS 1.0 / 1.1 refused (the client explicitly allows them)
		for _, v := range []uint16{tls.VersionTLS10, tls.VersionTLS11} {
			c, err := tls.Dial("tcp", addr, &tls.Config{RootCAs: p.pool(), ServerName: "127.0.0.1", MinVersion: v, MaxVersion: v})
			if err == nil {
				_ = c.Close()
				t.Errorf("%s: a TLS %#x handshake succeeded", name, v)
			}
		}
		// TLS 1.2 is accepted
		c, err := tls.Dial("tcp", addr, &tls.Config{RootCAs: p.pool(), ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12})
		if err != nil {
			t.Errorf("%s: TLS 1.2 refused: %v", name, err)
		} else {
			if c.ConnectionState().NegotiatedProtocol == "h2" {
				t.Errorf("%s: h2 negotiated (breaks the WebSocket upgrade)", name)
			}
			_ = c.Close()
		}
	}
	// an unknown CA is rejected by the client
	other := validPair(t)
	if _, err := httpsClient(other.pool(), 0).Get("https://" + api + "/health"); err == nil {
		t.Error("a client trusting another CA must refuse the certificate")
	}
}

func TestTLS_WebSocketsWorkOverWSS(t *testing.T) {
	p := validPair(t)
	n, api, admin, wsAddr := tlsNode(t, p, nil)
	if _, err := n.store.RegisterAgent(context.Background(), "host-tls", "pem", "jti-tls"); err != nil {
		t.Fatal(err)
	}
	tok := signAgentToken(t, "node-test-secret", "host-tls", "jti-tls")
	d := websocket.Dialer{TLSClientConfig: &tls.Config{RootCAs: p.pool()}, HandshakeTimeout: 5 * time.Second}
	for name, addr := range map[string]string{"7772": wsAddr, "7770": api} {
		c, resp, err := d.Dial("wss://"+addr+"/ws/agent", http.Header{"Authorization": {"Bearer " + tok}})
		if err != nil {
			t.Fatalf("wss on %s: %v (%v)", name, err, resp)
		}
		_ = c.Close()
	}
	// /ws/relay too: a refusal (401, no relay token) proves the route answers over TLS
	if _, resp, err := d.Dial("wss://"+wsAddr+"/ws/relay", nil); err == nil || resp == nil || resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("/ws/relay over wss: %v %v", err, resp)
	}
	// the admin port stays plain HTTP unless ADMIN_TLS=true
	if code, _ := adminCall(t, admin, "GET", "/api/admin/minions", nil); code != http.StatusOK {
		t.Errorf("plain admin: %d", code)
	}
}

func TestTLS_AdminPortTLSOnlyWithAdminTLS(t *testing.T) {
	p := validPair(t)
	_, _, admin, _ := tlsNode(t, p, func(c *Config) { c.AdminTLS = true })
	req, _ := http.NewRequest("GET", "https://"+admin+"/api/admin/minions", nil)
	req.Header.Set("Authorization", "Bearer "+testAdminToken)
	resp, err := httpsClient(p.pool(), 0).Do(req)
	if err != nil {
		t.Fatalf("admin over TLS: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("admin over TLS: %d", resp.StatusCode)
	}
	if r, err := http.Get("http://" + admin + "/api/admin/minions"); err == nil {
		if r.StatusCode == http.StatusOK {
			t.Error("the admin port served plain HTTP although ADMIN_TLS=true")
		}
		_ = r.Body.Close()
	}
}

func TestTLS_FailClosedOnEveryBadConfiguration(t *testing.T) {
	good := validPair(t)
	dir := t.TempDir()
	write := func(name, content string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	other := validPair(t) // another key: mismatched with good.cert
	expired := writePair(t, t.TempDir(), "old", time.Now().Add(-48*time.Hour), time.Now().Add(-time.Hour))
	future := writePair(t, t.TempDir(), "soon", time.Now().Add(time.Hour), time.Now().Add(2*time.Hour))
	secretMarker := "SUPER-SECRET-KEY-MATERIAL"
	garbageKey := write("garbage.key", "-----BEGIN EC PRIVATE KEY-----\n"+secretMarker+"\n-----END EC PRIVATE KEY-----\n")

	cases := []struct {
		name       string
		cert, key  string
		disable    bool
		wantSubstr string
	}{
		{"nothing configured", "", "", false, "TLS is required"},
		{"only the certificate", good.certPath, "", false, "together"},
		{"only the key", "", good.keyPath, false, "together"},
		{"certificate file missing", filepath.Join(dir, "absent.crt"), good.keyPath, false, "cannot read the certificate"},
		{"key file missing", good.certPath, filepath.Join(dir, "absent.key"), false, "cannot read the key"},
		{"certificate is not PEM", write("bad.crt", "not a certificate"), good.keyPath, false, "invalid certificate/key pair"},
		{"key is not PEM", good.certPath, write("bad.key", "nope"), false, "invalid certificate/key pair"},
		{"key content garbage", good.certPath, garbageKey, false, "invalid certificate/key pair"},
		{"key does not match the certificate", good.certPath, other.keyPath, false, "does not match"},
		{"certificate expired", expired.certPath, expired.keyPath, false, "expired"},
		{"certificate not yet valid", future.certPath, future.keyPath, false, "not valid before"},
		{"pair AND TLS_DISABLE with a bad pair still refused", good.certPath, other.keyPath, true, "does not match"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Config{JWTSecret: "s", AdminToken: "a", DatabaseURL: ":memory:", TLSCert: tc.cert, TLSKey: tc.key, TLSDisable: tc.disable}
			n, err := Build(cfg)
			if err == nil {
				n.Close()
				t.Fatal("Build must refuse to start")
			}
			if !strings.Contains(err.Error(), tc.wantSubstr) {
				t.Errorf("error %q lacks %q", err, tc.wantSubstr)
			}
			for _, leak := range []string{"PRIVATE KEY", secretMarker, string(good.keyPEM[:40]), string(other.keyPEM[:40])} {
				if strings.Contains(err.Error(), leak) {
					t.Errorf("the error leaks key material: %q", leak)
				}
			}
		})
	}
}

func TestTLS_DisableIsExplicitAndLoud(t *testing.T) {
	logs := captureStdLog(t)
	n, err := Build(Config{TLSDisable: true, JWTSecret: "s", AdminToken: "a", DatabaseURL: ":memory:"})
	if err != nil {
		t.Fatal(err)
	}
	n.Close()
	if !strings.Contains(logs.String(), "[SECURITY WARNING] TLS_DISABLE=true") {
		t.Errorf("a [SECURITY WARNING] is expected at every start with TLS_DISABLE:\n%s", logs.String())
	}
	// ConfigFromEnv: never a default, only the exact value "true"
	setServerEnv(t)
	t.Setenv("TLS_DISABLE", "")
	if _, err := ConfigFromEnv(); err == nil || !strings.Contains(err.Error(), "TLS is required") {
		t.Fatalf("no TLS config and no TLS_DISABLE must refuse: %v", err)
	}
	for _, v := range []string{"1", "yes", "TRUE", "on"} {
		t.Setenv("TLS_DISABLE", v)
		if _, err := ConfigFromEnv(); err == nil || !strings.Contains(err.Error(), "TLS_DISABLE") {
			t.Errorf("TLS_DISABLE=%q must be rejected, got %v", v, err)
		}
	}
	t.Setenv("TLS_DISABLE", "true")
	if cfg, err := ConfigFromEnv(); err != nil || !cfg.TLSDisable {
		t.Fatalf("TLS_DISABLE=true: %+v %v", cfg, err)
	}
	// a configured pair wins over TLS_DISABLE: TLS stays on
	p := validPair(t)
	t.Setenv("TLS_DISABLE", "true")
	t.Setenv("TLS_CERT", p.certPath)
	t.Setenv("TLS_KEY", p.keyPath)
	cfg, err := ConfigFromEnv()
	if err != nil || cfg.TLSCert != p.certPath {
		t.Fatalf("%+v %v", cfg, err)
	}
}

func TestTLS_KeyPermissionsAreChecked(t *testing.T) {
	logs := captureStdLog(t)
	p := validPair(t)
	if err := os.Chmod(p.keyPath, 0o644); err != nil {
		t.Fatal(err)
	}
	n, err := Build(Config{TLSCert: p.certPath, TLSKey: p.keyPath, JWTSecret: "s", AdminToken: "a", DatabaseURL: ":memory:"})
	if err != nil {
		t.Fatal(err)
	}
	n.Close()
	if !strings.Contains(logs.String(), "[SECURITY WARNING] TLS_KEY") || !strings.Contains(logs.String(), "accessible to other users") {
		t.Errorf("a world-readable key must be reported:\n%s", logs.String())
	}
	if strings.Contains(logs.String(), "PRIVATE KEY") {
		t.Error("key material in the logs")
	}
}

func TestTLS_AdminPlainOnANonLoopbackAddressIsReported(t *testing.T) {
	logs := captureStdLog(t)
	p := validPair(t)
	n, err := Build(Config{TLSCert: p.certPath, TLSKey: p.keyPath, AdminAddr: "0.0.0.0:7771", JWTSecret: "s", AdminToken: "a", DatabaseURL: ":memory:"})
	if err != nil {
		t.Fatal(err)
	}
	n.Close()
	if !strings.Contains(logs.String(), "admin API") || !strings.Contains(logs.String(), "non-loopback") {
		t.Errorf("expected the non-loopback admin warning:\n%s", logs.String())
	}
	for addr, want := range map[string]bool{"127.0.0.1:7771": true, "[::1]:7771": true, "localhost:7771": true, ":7771": false, "0.0.0.0:7771": false, "10.0.0.5:7771": false} {
		if got := isLoopbackAddr(addr, nil); got != want {
			t.Errorf("isLoopbackAddr(%q) = %v", addr, got)
		}
	}
}

func TestTLS_HotReloadWithoutCuttingExistingConnections(t *testing.T) {
	logs := captureStdLog(t)
	p := validPair(t)
	n, api, _, wsAddr := tlsNode(t, p, nil)
	if _, err := n.store.RegisterAgent(context.Background(), "host-hot", "pem", "jti-hot"); err != nil {
		t.Fatal(err)
	}
	tok := signAgentToken(t, "node-test-secret", "host-hot", "jti-hot")
	d := websocket.Dialer{TLSClientConfig: &tls.Config{RootCAs: p.pool()}, HandshakeTimeout: 5 * time.Second}
	live, _, err := d.Dial("wss://"+wsAddr+"/ws/agent", http.Header{"Authorization": {"Bearer " + tok}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = live.Close() }()
	if got := peerFingerprint(t, api, p.pool()); got != p.fingerprint() {
		t.Fatal("the first certificate is not served")
	}

	// no change on disk = no reload, however many polls go by (no log spam, no useless work)
	time.Sleep(500 * time.Millisecond)
	if strings.Contains(logs.String(), "TLS certificate reloaded") {
		t.Fatalf("the unchanged files were reloaded:\n%s", logs.String())
	}

	// 1. a new valid pair replaces the files: new connections get it, nothing restarts
	certPEM, keyPEM, leaf2 := genPEM(t, "rotated", time.Now().Add(-time.Hour), time.Now().Add(60*24*time.Hour))
	p2 := &tlsPair{certPath: p.certPath, keyPath: p.keyPath, leaf: leaf2}
	replaceFiles(t, p, certPEM, keyPEM)
	both := x509.NewCertPool() // the old and the new certificate are both trusted by the probe
	both.AddCert(p.leaf)
	both.AddCert(leaf2)
	deadline := time.Now().Add(10 * time.Second)
	for peerFingerprint(t, api, both) != p2.fingerprint() {
		if time.Now().After(deadline) {
			t.Fatal("the new certificate is not served after the rotation")
		}
		time.Sleep(100 * time.Millisecond)
	}
	for _, addr := range []string{api, wsAddr} {
		if peerFingerprint(t, addr, p2.pool()) != p2.fingerprint() {
			t.Errorf("%s still serves the old certificate", addr)
		}
	}
	// the WebSocket opened with the OLD certificate is still alive and registered
	if err := live.WriteControl(websocket.PingMessage, []byte("x"), time.Now().Add(2*time.Second)); err != nil {
		t.Fatalf("the existing WebSocket was cut by the rotation: %v", err)
	}
	if hosts := ws.GetConnectedHostnames(); !hostIn(hosts, "host-hot") {
		t.Errorf("the agent is no longer connected: %v", hosts)
	}

	// 2. invalid new pairs keep the previous one, with a [SECURITY WARNING], no cut
	_, otherKey, _ := genPEM(t, "other", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	for name, files := range map[string][2][]byte{
		"garbage":       {[]byte("garbage"), []byte("garbage")},
		"mismatched":    {certPEM, otherKey},
		"expired":       expiredFiles(t),
		"empty files":   {{}, {}},
		"truncated key": {certPEM, keyPEM[:len(keyPEM)/2]},
	} {
		before := strings.Count(logs.String(), "TLS certificate reload refused")
		replaceFiles(t, p, files[0], files[1])
		time.Sleep(450 * time.Millisecond) // several polls
		if got := strings.Count(logs.String(), "TLS certificate reload refused") - before; got != 1 {
			t.Errorf("%s: %d refusal warnings, want exactly 1 (the same bad content must not be re-reported at every poll)", name, got)
		}
		if peerFingerprint(t, api, p2.pool()) != p2.fingerprint() {
			t.Fatalf("%s: the previous certificate must stay in service", name)
		}
	}
	if !strings.Contains(logs.String(), "[SECURITY WARNING] TLS certificate reload refused, keeping the previous pair") {
		t.Errorf("the refusals must be reported:\n%s", logs.String())
	}
	if strings.Contains(logs.String(), "PRIVATE KEY") {
		t.Error("key material in the logs")
	}
	if err := live.WriteControl(websocket.PingMessage, []byte("y"), time.Now().Add(2*time.Second)); err != nil {
		t.Fatalf("the existing WebSocket was cut by an invalid pair: %v", err)
	}

	// 3. ReloadTLS (SIGHUP) forces a read: a valid pair is taken immediately
	certPEM3, keyPEM3, leaf3 := genPEM(t, "third", time.Now().Add(-time.Hour), time.Now().Add(30*24*time.Hour))
	replaceFiles(t, p, certPEM3, keyPEM3)
	if !n.ReloadTLS() {
		t.Fatal("ReloadTLS must take the new valid pair")
	}
	pool3 := x509.NewCertPool()
	pool3.AddCert(leaf3)
	if peerFingerprint(t, api, pool3) != sha256.Sum256(leaf3.Raw) {
		t.Error("the certificate loaded by ReloadTLS is not served")
	}
}

func expiredFiles(t *testing.T) [2][]byte {
	t.Helper()
	c, k, _ := genPEM(t, "expired", time.Now().Add(-48*time.Hour), time.Now().Add(-time.Hour))
	return [2][]byte{c, k}
}

func hostIn(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
