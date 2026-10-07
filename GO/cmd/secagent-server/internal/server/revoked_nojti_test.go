package server

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"secagent-server/cmd/secagent-server/internal/storage"
)

// #189: an agent without TokenJTI (nothing to blacklist) is still revoked for real: the flag is
// persisted (read back after a reopening of the store), the live WS is closed with 4001, the
// reconnection and the enrollment are refused. The API does not answer 409 for it.
func TestRevoke_AgentWithoutTokenJTI_IsRevokedForReal(t *testing.T) {
	var dir string
	n, _, admin, wsAddr, cancel, done := startNodeCtl(t, func(c *Config) { dir = c.StateDir })
	ctx := context.Background()
	if _, err := n.store.RegisterAgent(ctx, "host-nojti", "pem", "jti-live"); err != nil {
		t.Fatal(err)
	}
	conn, status, err := dialAgentWS(wsAddr, signAgentToken(t, serverJWTSecret(), "host-nojti", "jti-live"))
	if err != nil {
		t.Fatalf("connect: %v (status %d)", err, status)
	}
	defer func() { _ = conn.Close() }()
	// the agent loses its JTI (legacy record): nothing to blacklist at revocation
	if ok, err := n.store.UpdateTokenJTI(ctx, "host-nojti", ""); err != nil || !ok {
		t.Fatalf("clear jti: %v %v", ok, err)
	}

	code, body := adminCall(t, admin, "POST", "/api/admin/revoke/host-nojti", nil)
	if code != http.StatusOK {
		t.Fatalf("revoke: %d %s (must not be 409)", code, body)
	}
	if got := readUntilClose(t, conn); got != 4001 {
		t.Errorf("close code = %d, want 4001", got)
	}
	// reconnection refused
	if _, status, err := dialAgentWS(wsAddr, signAgentToken(t, serverJWTSecret(), "host-nojti", "jti-live")); err == nil || status != http.StatusUnauthorized {
		t.Errorf("revoked agent reconnected: status %d err %v, want 401", status, err)
	}
	// enrollment refused
	if _, err := n.store.RegisterAgent(ctx, "host-nojti", "pem2", "jti-new"); !errors.Is(err, storage.ErrAgentRevoked) {
		t.Errorf("enrollment of a revoked host: %v, want ErrAgentRevoked", err)
	}

	// stop the node, reopen the store: the flag is persisted
	cancel()
	select {
	case <-done:
	case <-time.After(35 * time.Second):
		t.Fatal("node did not stop")
	}
	st, err := openSeedStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	if r, _ := st.IsAgentRevoked(ctx, "host-nojti"); !r {
		t.Fatal("Revoked=true must survive the reopening of the store")
	}
	if _, err := st.RegisterAgent(ctx, "host-nojti", "pem3", "jti-n3"); !errors.Is(err, storage.ErrAgentRevoked) {
		t.Errorf("after reopening, enrollment: %v, want ErrAgentRevoked", err)
	}
	if err := agentJTICheck(st)("host-nojti", "jti-live", false); err == nil {
		t.Error("after reopening, the handshake check must refuse")
	}
}
