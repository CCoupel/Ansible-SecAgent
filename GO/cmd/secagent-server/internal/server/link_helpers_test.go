package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"

	"secagent-server/cmd/secagent-server/internal/auth"
	"secagent-server/cmd/secagent-server/internal/state"
)

// testRoot plays the ROOT relay "central" for nodes that have a parent (v3.0.4, #141/#146): it holds
// the Ed25519 key, pins its public half as the trust anchor (link_trust) of the node under test and
// signs the link tokens that node must accept (parent link tokens, tokens of its children).
type testRoot struct {
	id   string
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
}

func newTestRoot(t *testing.T) *testRoot {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &testRoot{id: "central", pub: pub, priv: priv}
}

// anchored returns a config mutation that pins this root's key in the state of the node (as the
// deployment does), then applies inner (may be nil).
func (r *testRoot) anchored(inner func(*Config)) func(*Config) {
	return func(c *Config) {
		st, err := openSeedStore(c.StateDir)
		if err != nil {
			panic(err)
		}
		err = st.SetLinkTrust(nil, state.LinkTrust{RootID: r.id, CurrentPub: base64.RawURLEncoding.EncodeToString(r.pub), CurrentKID: auth.LinkKID(r.pub)})
		_ = st.Close()
		if err != nil {
			panic(err)
		}
		if inner != nil {
			inner(c)
		}
	}
}

// token signs a link token as the root: role relay-child (sub = child, aud = this node) or
// relay-parent (sub = the parent, aud = this node).
func (r *testRoot) token(t *testing.T, role, sub, aud string) string {
	t.Helper()
	tok, _, err := auth.SignLinkToken(r.priv, r.id, sub, aud, role, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}
