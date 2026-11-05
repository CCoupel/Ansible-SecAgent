// SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
// SPDX-License-Identifier: AGPL-3.0-or-later

package cli

// LOT-3 (#234, #215) — what the operator READS: `keys link-status` tells the three states apart (never_seen is
// no longer shown as confirmed), flags the relays not directly connected since the rotation, and
// `keys retire-link-previous` refused with 409 rotation_unconfirmed names the relays and the remedy
// (`relays remove <id>`). The server contract is in integration/link_status_spec_test.go.

import (
	"net/http"
	"strings"
	"testing"
)

const linkStatusJSON = `{
  "root_id": "root", "seq": 2, "rotation_seq": 1, "current_kid": "KIDCUR", "previous_kid": "KIDPREV",
  "relays": [
    {"relay_id": "relay1", "link_seq": 1, "link_kid": "KIDCUR",  "confirmed": true,  "state": "confirmed",   "direct": true},
    {"relay_id": "stale",  "link_seq": 0, "link_kid": "KIDPREV", "confirmed": false, "state": "unconfirmed", "direct": true},
    {"relay_id": "ghost",  "link_seq": 0,                          "confirmed": false, "state": "never_seen",  "direct": false},
    {"relay_id": "below",  "link_seq": 1, "link_kid": "KIDCUR",  "confirmed": true,  "state": "confirmed",   "direct": false}
  ],
  "not_direct": ["ghost", "below"]
}`

func linkAPI(t *testing.T) {
	t.Helper()
	mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == "GET" && r.URL.Path == "/api/admin/link/status":
			_, _ = w.Write([]byte(linkStatusJSON))
		case r.Method == "POST" && r.URL.Path == "/api/admin/link/keys/retire-previous":
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{"error":"rotation_unconfirmed","unconfirmed":["stale","ghost"],"never_seen":["ghost"],"not_direct":["ghost","below"],` +
				`"message":"relays never seen cannot confirm the rotation: connect them, or remove one that will not connect with 'secagent-server relays remove <id>'; --force retires anyway"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
}

// row returns the line of the table that starts with the relay id.
func row(out, id string) string {
	for _, l := range strings.Split(out, "\n") {
		if f := strings.Fields(l); len(f) > 0 && f[0] == id {
			return l
		}
	}
	return ""
}

func TestKeysLinkStatus_ShowsTheThreeStatesAndTheDirectColumn(t *testing.T) {
	linkAPI(t)
	out, errOut, code := runCLI(t, "keys", "link-status")
	if code != 0 {
		t.Fatalf("exit %d, stderr: %s", code, errOut)
	}
	for _, c := range []struct{ id, state, direct string }{
		{"relay1", "confirmed", "true"}, {"stale", "unconfirmed", "true"}, {"ghost", "never_seen", "false"}, {"below", "confirmed", "false"},
	} {
		l := row(out, c.id)
		if l == "" {
			t.Fatalf("no row for %s:\n%s", c.id, out)
		}
		f := strings.Fields(l)
		if !strings.Contains(l, c.state) {
			t.Errorf("%s: the row must show its state %q:\n%s", c.id, c.state, l)
		}
		if f[len(f)-1] != c.direct {
			t.Errorf("%s: the last column (DIRECT) must be %s:\n%s", c.id, c.direct, l)
		}
	}
	// never_seen is told apart from a confirmed relay: its row carries neither the current kid nor "true" under CONFIRMED
	if l := row(out, "ghost"); strings.Contains(l, "true") || strings.Contains(l, "KIDCUR") {
		t.Errorf("a never_seen relay must not look confirmed:\n%s", l)
	}
	for _, header := range []string{"STATE", "DIRECT", "CONFIRMED"} {
		if !strings.Contains(out, header) {
			t.Errorf("the header must have a %s column:\n%s", header, out)
		}
	}
}

func TestKeysLinkStatus_ExplainsNeverSeenAndNotDirect(t *testing.T) {
	linkAPI(t)
	out, _, code := runCLI(t, "keys", "link-status")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(out, "never_seen") || !strings.Contains(out, "relays remove") {
		t.Errorf("a never_seen relay must be followed by its remedy (relays remove <id>):\n%s", out)
	}
	if !strings.Contains(strings.ToLower(out), "not directly connected") {
		t.Errorf("not_direct relays must be flagged (their confirmation was relayed, unsigned, by an intermediary):\n%s", out)
	}
}

func TestKeysLinkStatus_JSONFormatKeepsEveryField(t *testing.T) {
	linkAPI(t)
	out, _, code := runCLI(t, "--format", "json", "keys", "link-status")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	for _, f := range []string{`"state"`, `"never_seen"`, `"direct"`, `"not_direct"`, `"confirmed"`} {
		if !strings.Contains(out, f) {
			t.Errorf("the JSON output must keep %s:\n%s", f, out)
		}
	}
}

// The refusal of the retire reaches the operator with the relays and the remedy — the message of the API
// is what makes #234 usable: "relays remove <id>" instead of --force.
func TestKeysRetireLinkPrevious_TheRefusalNamesTheRelaysAndTheRemedy(t *testing.T) {
	linkAPI(t)
	out, errOut, code := runCLI(t, "keys", "retire-link-previous")
	if code != 1 {
		t.Fatalf("exit %d, want 1 (409): stdout=%q stderr=%q", code, out, errOut)
	}
	all := out + errOut
	for _, want := range []string{"rotation_unconfirmed", "ghost", "stale", "relays remove"} {
		if !strings.Contains(all, want) {
			t.Errorf("the refusal must show %q (relays that block it, and the remedy):\nstdout=%q\nstderr=%q", want, out, errOut)
		}
	}
}
