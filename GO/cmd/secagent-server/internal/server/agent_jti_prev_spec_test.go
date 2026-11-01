package server

// #217 cycle 2 — M1 / M2 of the security review of the delivered code (PrevTokenJTI):
//
//	M1  a replaced JWT is refused during the rotation grace period too, whichever secret signed it; only the
//	    JTI that the current one replaced (PrevTokenJTI) stays valid, until the current JTI served a handshake
//	M2  a rekey whose send failed (JTI written, nothing delivered) does not lose the agent: it comes back with
//	    the JWT it holds
//	compat  a state written by v3.0.4 (no prev_token_jti) is read again and written back unchanged in shape

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"secagent-server/cmd/secagent-server/internal/handlers"
	"secagent-server/cmd/secagent-server/internal/state"
	"secagent-server/cmd/secagent-server/internal/storage"
)

func jtiErr(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// M1, matrix on the check itself: the previous secret (usedPrevious=true) is no exemption.
func TestSecM1_AReplacedJTIIsRefusedEvenWhenSignedWithThePreviousSecret(t *testing.T) {
	st := newMemStore(t)
	ctx := context.Background()
	if _, err := st.RegisterAgent(ctx, "h", "pem", "j0"); err != nil {
		t.Fatal(err)
	}
	check := agentJTICheck(st)

	// current = j0
	for _, prev := range []bool{false, true} {
		if err := check("h", "j0", prev); err != nil {
			t.Fatalf("the current JTI must be accepted (usedPrevious=%v): %v", prev, err)
		}
	}
	// renewal: current = j1, prev = j0 (the agent may not have received j1)
	if _, err := st.UpdateTokenJTI(ctx, "h", "j1"); err != nil {
		t.Fatal(err)
	}
	for _, prev := range []bool{false, true} {
		if err := check("h", "j0", prev); err != nil {
			t.Fatalf("the JTI the current one replaced stays valid while the current one was never used (usedPrevious=%v): %v", prev, err)
		}
	}
	// renewal again: current = j2, prev = j1, j0 is now TWO renewals old
	if _, err := st.UpdateTokenJTI(ctx, "h", "j2"); err != nil {
		t.Fatal(err)
	}
	for _, prev := range []bool{false, true} {
		err := check("h", "j0", prev)
		if err == nil || !strings.Contains(err.Error(), "token_replaced") {
			t.Errorf("M1: an older replaced JTI must be refused with token_replaced (usedPrevious=%v), got %v", prev, err)
		}
	}
	if err := check("h", "j1", true); err != nil {
		t.Errorf("the immediate predecessor stays valid until the current JTI is used: %v", err)
	}
	// the first handshake with the current JTI forgets its predecessor
	if err := check("h", "j2", false); err != nil {
		t.Fatalf("current JTI: %v", err)
	}
	for _, prev := range []bool{false, true} {
		if err := check("h", "j1", prev); err == nil || !strings.Contains(err.Error(), "token_replaced") {
			t.Errorf("after the first handshake with the current JTI, the previous one must be refused (usedPrevious=%v), got %v", prev, err)
		}
	}
	// unknown / blacklisted / revoked keep their reasons
	if err := check("nobody", "j2", true); err == nil || !strings.Contains(err.Error(), "unknown_agent") {
		t.Errorf("unknown agent: %v", err)
	}
	reason := "t"
	if err := st.AddToBlacklist(ctx, "j2", "h", time.Now().Add(time.Hour).UTC().Format(time.RFC3339), &reason); err != nil {
		t.Fatal(err)
	}
	if err := check("h", "j2", true); err == nil || !strings.Contains(err.Error(), "token_revoked") {
		t.Errorf("a blacklisted current JTI stays revoked: %v", err)
	}
}

// The predecessor of a REVOKED agent is refused as well (the flag primes over the grace of prev).
func TestSecM1_ARevokedAgentsPredecessorIsRefused(t *testing.T) {
	st := newMemStore(t)
	ctx := context.Background()
	_, _ = st.RegisterAgent(ctx, "h", "pem", "j0")
	_, _ = st.UpdateTokenJTI(ctx, "h", "j1") // prev = j0
	if _, err := st.RevokeAgent(ctx, "h", "j1", "test", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	check := agentJTICheck(st)
	for _, j := range []string{"j0", "j1"} {
		if err := check("h", j, true); err == nil || !strings.Contains(err.Error(), "token_revoked") {
			t.Errorf("%s of a revoked agent: %v, want token_revoked", j, err)
		}
	}
}

// A re-enrollment resets the chain: the JTIs of the previous enrollment are not predecessors.
func TestSecM1_AReEnrollmentDoesNotKeepOldJTIsValid(t *testing.T) {
	st := newMemStore(t)
	ctx := context.Background()
	_, _ = st.RegisterAgent(ctx, "h", "pem", "j0")
	_, _ = st.UpdateTokenJTI(ctx, "h", "j1")
	_, _ = st.RegisterAgent(ctx, "h", "pem", "e0")
	check := agentJTICheck(st)
	for _, j := range []string{"j0", "j1"} {
		if err := check("h", j, true); err == nil {
			t.Errorf("%s predates the re-enrollment: it must be refused", j)
		}
	}
	if err := check("h", "e0", false); err != nil {
		t.Errorf("the new enrollment JTI: %v", err)
	}
}

func rsaPubPEM(t *testing.T) string {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

// M2: the rekey cannot be delivered (no live connection for the host) AFTER the JTI was written. The
// agent still holds its JWT: it must be accepted on its next handshake, without re-enrollment, and the
// JWT of the failed rekey (never delivered) must be usable too once it is the current one.
func TestSecM2_AfterAFailedRekeySendTheAgentReconnectsWithItsPreviousJWT(t *testing.T) {
	n, _, _, wsAddr := startNode(t, nil)
	ctx := context.Background()
	host := "m2-host"
	if _, err := n.store.RegisterAgent(ctx, host, rsaPubPEM(t), "jti-held"); err != nil {
		t.Fatal(err)
	}
	// no WebSocket is open for host: the send fails after UpdateTokenJTI
	if exp, err := handlers.RenewAgentJWT(host); err == nil || !exp.IsZero() {
		t.Fatalf("the renewal of a host without connection must fail (got %v, %v)", exp, err)
	}
	a, _ := n.store.GetAgent(ctx, host)
	if a == nil || a.TokenJTI == "" || a.TokenJTI == "jti-held" {
		t.Skipf("the implementation rolled the JTI back or did not write it (%+v): the JWT held is still the current one, nothing to heal", a)
	}
	held := signAgentToken(t, serverJWTSecret(), host, "jti-held")
	c, status, err := dialAgentWS(wsAddr, held)
	if err != nil {
		t.Fatalf("M2: the agent must reconnect with the JWT it holds after a failed rekey (status %d): %v", status, err)
	}
	_ = c.Close()
	// a token older than the predecessor never comes back
	if _, status, err := dialAgentWS(wsAddr, signAgentToken(t, serverJWTSecret(), host, "jti-ancient")); err == nil || status != http.StatusUnauthorized {
		t.Errorf("an unrelated old JTI must be refused: status %d err %v", status, err)
	}
}

// compat: the state written by v3.0.4 `state init` + one enrolled agent (testdata/v304_with_agent, master key
// "v304-master-key-of-at-least-32-bytes!!") is read again by this code: the agent keeps its JTI, has no
// predecessor, the check accepts it and refuses any other; the first renewal writes prev_token_jti and
// the file still verifies at schema_version 2.
func TestSecCompat_AV304StateWithAnEnrolledAgentIsReadAgainAndStaysVerifiable(t *testing.T) {
	const key = "v304-master-key-of-at-least-32-bytes!!"
	src, err := os.ReadFile(filepath.Join("..", "state", "testdata", "v304_with_agent", state.StateFile))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, state.StateFile), src, 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := storage.Open(state.Options{Dir: dir, MasterKey: key, BeforeWrite: func() error { return nil }, Instance: "compat"})
	if err != nil {
		t.Fatalf("a v3.0.4 state must open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	ctx := context.Background()
	a, _ := st.GetAgent(ctx, "legacy-host")
	if a == nil || a.TokenJTI != "legacy-jti" || a.PrevTokenJTI != "" {
		t.Fatalf("the enrolled agent of a v3.0.4 state: %+v", a)
	}
	check := agentJTICheck(st)
	if err := check("legacy-host", "legacy-jti", false); err != nil {
		t.Errorf("the legacy JTI is current: %v", err)
	}
	if jtiErr(check("legacy-host", "other", true)) == "" {
		t.Error("any other JTI must be refused, grace or not")
	}
	// first renewal after the upgrade
	if _, err := st.UpdateTokenJTI(ctx, "legacy-host", "renewed-1"); err != nil {
		t.Fatal(err)
	}
	if err := check("legacy-host", "legacy-jti", true); err != nil {
		t.Errorf("the legacy JTI is the predecessor of the first renewal: %v", err)
	}
	_ = st.Close()
	rep, err := state.VerifyFile(filepath.Join(dir, state.StateFile), state.VerifyOptions{MasterKey: key})
	if err != nil {
		t.Fatalf("the state written by this code must verify: %v", err)
	}
	if rep.NeedsMigration {
		t.Error("no schema migration may be required")
	}
	raw, _ := os.ReadFile(filepath.Join(dir, state.StateFile))
	if !strings.Contains(string(raw), `"schema_version":2`) {
		t.Error("schema_version must stay 2")
	}
}
