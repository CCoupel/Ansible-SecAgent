package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func revokeViaAPI(t *testing.T, hostname string) {
	t.Helper()
	w := httptest.NewRecorder()
	req := adminReq("POST", "/api/admin/revoke/"+hostname, nil)
	req.SetPathValue("hostname", hostname)
	AdminRevokeMinion(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("revoke %s: %d %s", hostname, w.Code, w.Body.String())
	}
}

func deleteViaAPI(t *testing.T, hostname string) {
	t.Helper()
	w := httptest.NewRecorder()
	req := adminReq("DELETE", "/api/admin/minions/"+hostname, nil)
	req.SetPathValue("hostname", hostname)
	AdminDeleteMinion(w, req)
	if w.Code != http.StatusOK && w.Code != http.StatusNoContent {
		t.Fatalf("delete %s: %d %s", hostname, w.Code, w.Body.String())
	}
}

// A revoked host cannot re-enroll — with a REUSABLE token, or a token whose hostname pattern is wide —
// and the refusal does not consume the token; an explicit admin action (DELETE) lifts it (#193).
func TestEnrollment_RevokedHostIsRefusedWhateverTheToken(t *testing.T) {
	useFreshStores(t)
	priv, pub := genRSAPubPEM(t, 4096)
	host := "revoked-host-01"
	insertEnrollmentToken(t, "tok-first", "secagent_enr_first_01", host, false, nil)
	if code, _ := fullEnrollment(t, host, "secagent_enr_first_01", priv, pub); code != http.StatusOK {
		t.Fatalf("setup enrollment: %d", code)
	}
	// standing authorizations an admin issued BEFORE the revocation
	insertEnrollmentToken(t, "tok-reusable", "secagent_enr_reusable_01", host, true, nil)
	insertEnrollmentToken(t, "tok-wide", "secagent_enr_wide_01", ".*", true, nil)

	revokeViaAPI(t, host)
	if r, _ := registerStore.IsAgentRevoked(context.Background(), host); !r {
		t.Fatal("the revocation must set the persistent flag")
	}
	before, _ := registerStore.GetAgent(context.Background(), host)

	for name, token := range map[string]string{"reusable token": "secagent_enr_reusable_01", "wide pattern token": "secagent_enr_wide_01"} {
		code, _ := doPhase1(t, host, pub, token)
		if code != http.StatusForbidden {
			t.Fatalf("%s, phase 1: %d, want 403", name, code)
		}
		w := httptest.NewRecorder()
		RegisterAgent(w, httptest.NewRequest("POST", "/api/register", strings.NewReader(`{"hostname":"`+host+`","public_key_pem":"x","enrollment_token":"`+token+`"}`)))
		if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "agent_revoked") {
			t.Fatalf("%s: %d %s, want 403 agent_revoked", name, w.Code, w.Body.String())
		}
	}
	after, _ := registerStore.GetAgent(context.Background(), host)
	if after.TokenJTI != before.TokenJTI || !after.Revoked {
		t.Fatalf("the revoked agent changed: %+v", after)
	}
	for _, id := range []string{"tok-reusable", "tok-wide"} {
		if tok, _ := registerStore.GetEnrollmentTokenByID(context.Background(), id); tok.UseCount != 0 {
			t.Errorf("token %s was consumed by a refused enrollment", id)
		}
	}
	// an OTHER host with the wide token is fine: the refusal is per revoked host
	if code, _ := fullEnrollment(t, "someone-else-01", "secagent_enr_wide_01", priv, pub); code != http.StatusOK {
		t.Errorf("another host with the wide token must enroll: %d", code)
	}

	// the explicit lifting: DELETE the agent, then the same standing token works again
	deleteViaAPI(t, host)
	if code, _ := fullEnrollment(t, host, "secagent_enr_reusable_01", priv, pub); code != http.StatusOK {
		t.Fatalf("after the explicit lifting the host can enroll: %d", code)
	}
	if r, _ := registerStore.IsAgentRevoked(context.Background(), host); r {
		t.Error("the new enrollment is not revoked")
	}
}

// The refusal comes from the flag, not from the 25 h blacklist: it holds after the entry expired.
func TestEnrollment_RevocationHoldsAfterTheBlacklistEntryExpired(t *testing.T) {
	s := useFreshStores(t)
	priv, pub := genRSAPubPEM(t, 4096)
	host := "revoked-host-02"
	insertEnrollmentToken(t, "tok-a", "secagent_enr_a_02", host, false, nil)
	if code, _ := fullEnrollment(t, host, "secagent_enr_a_02", priv, pub); code != http.StatusOK {
		t.Fatal("setup")
	}
	insertEnrollmentToken(t, "tok-b", "secagent_enr_b_02", host, true, nil)
	a, _ := s.GetAgent(context.Background(), host)
	if _, err := s.RevokeAgent(context.Background(), host, a.TokenJTI, "admin_revoke", time.Now().Add(-time.Minute)); err != nil { // expired already
		t.Fatal(err)
	}
	if _, err := s.PurgeExpiredBlacklist(context.Background()); err != nil {
		t.Fatal(err)
	}
	if bl, _ := s.IsJTIBlacklisted(context.Background(), a.TokenJTI); bl {
		t.Fatal("setup: blacklist entry must be gone")
	}
	if code, _ := doPhase1(t, host, pub, "secagent_enr_b_02"); code != http.StatusForbidden {
		t.Fatalf("a revoked host whose blacklist entry expired: %d, want 403", code)
	}
}

// A revoked host never gets a rekey token either.
func TestRekey_RevokedHostGetsNoToken(t *testing.T) {
	s := useFreshStores(t)
	_, pub := genRSAPubPEM(t, 4096)
	host := "revoked-host-03"
	if err := s.UpsertAgent(context.Background(), host, pub, "jti-03"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RevokeAgent(context.Background(), host, "jti-03", "admin_revoke", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	var sent int
	prev := sendToAgentFn
	sendToAgentFn = func(string, map[string]interface{}) error { sent++; return nil }
	defer func() { sendToAgentFn = prev }()
	secret, _, _ := GetServerJWTSecrets()
	if sendRekeyToAgent(context.Background(), host, secret, time.Hour) || sent != 0 {
		t.Fatalf("a revoked host must get no rekey (sent=%d)", sent)
	}
	if a, _ := s.GetAgent(context.Background(), host); a.TokenJTI != "jti-03" {
		t.Error("the revoked agent's JTI changed")
	}
}
