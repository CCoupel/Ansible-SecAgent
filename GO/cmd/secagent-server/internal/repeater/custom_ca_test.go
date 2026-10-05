package repeater

import (
	"context"
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

	"secagent-server/cmd/secagent-server/internal/tlsca"
)

func writeCA(t *testing.T, der []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func unrelatedCA(t *testing.T) []byte {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(9), Subject: pkix.Name{CommonName: "unrelated"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// The push dial-out verifies the child against the custom CA only (#147): trusted CA = link up,
// another CA = the child never sees an upgrade request.
func TestDialer_CustomCAIsTheOnlyTrustAnchor(t *testing.T) {
	child := newMockChild(t, "dmz1")
	run := func(caFile string) *mockChild {
		cfg, err := tlsca.Load(caFile)
		if err != nil {
			t.Fatal(err)
		}
		serve := make(chan serveCall, 2)
		o := dialerOpts(serve)
		o.TLSConfig = cfg
		d, err := NewDialer(DialTarget{RelayID: "dmz1", URLs: []string{child.url()}, Token: "tok"}, o)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		if err := d.Start(ctx); err != nil {
			t.Fatal(err)
		}
		return child
	}
	run(writeCA(t, child.srv.Certificate().Raw))
	deadline := time.Now().Add(waitTimeout)
	for child.accepts.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if child.accepts.Load() == 0 {
		t.Fatal("the child signed by the configured CA must be reachable")
	}

	other := newMockChild(t, "dmz2")
	cfg, err := tlsca.Load(writeCA(t, unrelatedCA(t)))
	if err != nil {
		t.Fatal(err)
	}
	o := dialerOpts(make(chan serveCall, 2))
	o.TLSConfig = cfg
	d, err := NewDialer(DialTarget{RelayID: "dmz2", URLs: []string{other.url()}, Token: "tok"}, o)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := d.Start(ctx); err != nil {
		t.Fatal(err)
	}
	time.Sleep(500 * time.Millisecond)
	if n := other.accepts.Load(); n != 0 {
		t.Fatalf("a child not signed by the configured CA received %d connection(s)", n)
	}
}
