package integration

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// unrelatedCAFile writes a valid CA certificate that signed nothing.
func unrelatedCAFile(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "unrelated-ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "other-ca.pem")
	if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// REPEATER_CA_FILE REPLACES the system roots on the pull link: with SSL_CERT_FILE pointing at an
// unrelated CA (the system roots would refuse the parent), the link comes up on the CA file alone.
func TestCustomCA_PullLinkTrustsTheCAFileAndNotTheSystemRoots(t *testing.T) {
	parallel(t)
	root := startNode(t, nodeSpec{ID: "root", Hooks: standardHooks})
	child := startNode(t, nodeSpec{ID: "relay1", ParentURL: root.wssURL(), ParentToken: root.registerChild("relay1"), Hooks: standardHooks,
		Env: []string{"SSL_CERT_FILE=" + unrelatedCAFile(t), "REPEATER_CA_FILE=" + certPath}})
	waitFor(t, "the link is up through the CA file alone", func() bool { return child.upstreamState() == "connected" })
}

// The other way round: the system roots trust the parent, the CA file does not: the link must NOT
// come up (the CA file wins, no fallback to the system roots).
func TestCustomCA_WrongCAFileRefusesThePullLink(t *testing.T) {
	parallel(t)
	root := startNode(t, nodeSpec{ID: "root", Hooks: standardHooks})
	child := startNode(t, nodeSpec{ID: "relay1", ParentURL: root.wssURL(), ParentToken: root.registerChild("relay1"), Hooks: standardHooks,
		Env: []string{"SSL_CERT_FILE=" + certPath, "REPEATER_CA_FILE=" + unrelatedCAFile(t)}})
	waitFor(t, "the node tried and failed to reach the parent", func() bool { return child.logs.has("certificate") })
	time.Sleep(time.Second)
	if st := child.upstreamState(); st == "connected" {
		t.Fatal("the link came up although the CA file does not trust the parent")
	}
	if root.logs.has("Relay connected: relay_id=relay1") {
		t.Fatal("the parent saw a connection from the child")
	}
}

// A CA file that cannot be used refuses the start (fail closed).
func TestCustomCA_UnusableCAFileRefusesTheStart(t *testing.T) {
	parallel(t)
	n := prepareNode(t, nodeSpec{ID: "node"})
	bad := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(bad, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	n.setEnv("REPEATER_CA_FILE", bad)
	code, out := n.runExpectingExit()
	if code == 0 || code == -1 {
		t.Fatalf("the node must refuse to start (exit %d): %s", code, out)
	}
}
