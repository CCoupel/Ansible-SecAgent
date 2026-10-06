package integration

// #193 on a REAL node: the revocation is a persistent flag, set with the blacklist in one write. A revoked
// host is refused by the enrollment — with a REUSABLE token issued before, or any token — even after the
// 25 h blacklist retention (the flag does not depend on it), across a crash, until an admin lifts it
// explicitly (DELETE of the agent).

import (
	"net/http"
	"testing"
)

func enrollPhase1(n *node, host, token string) (int, string) {
	_, pubPEM, err := harnessAgentKeyErr()
	if err != nil {
		return 0, err.Error()
	}
	code, raw := n.call("POST", "/api/register", "", map[string]any{"hostname": host, "public_key_pem": pubPEM, "enrollment_token": token})
	return code, string(raw)
}

func TestRevocation_PersistentFlagRefusesReEnrollmentAcrossACrash(t *testing.T) {
	parallel(t)
	n := startNode(t, nodeSpec{ID: "root"})
	tok := n.enrollAgent("flag-host")

	// a standing, reusable, wide enrollment token issued before the revocation
	code, m := n.admin("POST", "/api/admin/tokens", map[string]any{"role": "enrollment", "hostname_pattern": ".*", "reusable": 1})
	if code >= 300 || m["token"] == nil {
		t.Fatalf("reusable token: %d %v", code, m)
	}
	standing := m["token"].(string)
	if code, body := enrollPhase1(n, "other-host", standing); code != http.StatusOK {
		t.Fatalf("setup: the standing token must work for another host: %d %s", code, body)
	}

	if code, _ := n.admin("POST", "/api/admin/revoke/flag-host", nil); code != http.StatusOK {
		t.Fatalf("revoke: %d", code)
	}
	if code, body := enrollPhase1(n, "flag-host", standing); code != http.StatusForbidden {
		t.Fatalf("a revoked host with a standing token: %d %s, want 403 agent_revoked", code, body)
	}
	if a := n.stateSection("agents")["flag-host"]; a == nil || a["revoked"] != true {
		t.Fatalf("the persistent flag must be in relay.state: %v", a)
	}

	// crash right after the acknowledged revocation: the next master still refuses
	n.kill9()
	if code, body := enrollPhase1(n, "flag-host", standing); code != http.StatusForbidden {
		t.Fatalf("after a crash and restart: %d %s, want 403", code, body)
	}
	if c, conn := openAgentWS(n, tok); c != http.StatusUnauthorized {
		if conn != nil {
			_ = conn.Close()
		}
		t.Fatalf("the revoked token must stay refused after the restart: %d", c)
	}
	// the other host is not affected
	if code, _ := enrollPhase1(n, "other-host-2", standing); code != http.StatusOK {
		t.Errorf("the refusal is per revoked host: %d", code)
	}

	// explicit lifting by the admin: delete the agent, then the host can enroll again
	if code, _ := n.admin("DELETE", "/api/admin/minions/flag-host", nil); code >= 300 {
		t.Fatalf("delete: %d", code)
	}
	if code, body := enrollPhase1(n, "flag-host", standing); code != http.StatusOK {
		t.Fatalf("after the explicit lifting: %d %s, want 200", code, body)
	}
}
