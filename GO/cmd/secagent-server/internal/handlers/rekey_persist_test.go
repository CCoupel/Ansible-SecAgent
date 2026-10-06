package handlers

import (
	"context"
	"testing"
	"time"

	"secagent-server/cmd/secagent-server/internal/storage"
)

// A rekey whose new JTI cannot be persisted must not be sent (#192 audit): the agent would hold a token
// the next handshake refuses while the old one stays valid.
func TestSendRekeyToAgent_NothingIsSentWhenTheJTICannotBePersisted(t *testing.T) {
	if server == nil || server.PrivateKey == nil {
		t.Skip("server state not initialized")
	}
	_, pub := genRSAPubPEM(t, 4096)
	host := "rekey-persist-host"
	preAuthorize(t, host, pub)
	if _, err := registerStore.RegisterAgent(context.Background(), host, pub, "jti-before"); err != nil {
		t.Fatal(err)
	}
	prev := adminStore
	adminStore = registerStore
	defer func() { adminStore = prev }()
	secret, _, _ := GetServerJWTSecrets()

	var sent int
	prevSend := sendToAgentFn
	sendToAgentFn = func(string, map[string]interface{}) error { sent++; return nil }
	defer func() { sendToAgentFn = prevSend }()

	registerStore.SetWriteGuard(func() error { return storage.ErrReadOnly })
	ok := sendRekeyToAgent(context.Background(), host, secret, time.Hour)
	registerStore.SetWriteGuard(func() error { return nil })
	if ok || sent != 0 {
		t.Fatalf("a rekey must not be sent when its JTI was not persisted (ok=%v, messages sent=%d)", ok, sent)
	}
	a, _ := registerStore.GetAgent(context.Background(), host)
	if a == nil || a.TokenJTI != "jti-before" {
		t.Fatalf("the stored JTI must be untouched, got %+v", a)
	}
}
