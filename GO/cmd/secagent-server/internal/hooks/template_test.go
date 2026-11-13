// SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
// SPDX-License-Identifier: AGPL-3.0-or-later

package hooks

// Tests de Render — moteur de template basé sur des placeholders {{var}}
//
// Référence : DOC/server/HOOKS_SPEC.md §4
//
// Signature implémentée :
//   Render(tmpl string, vars map[string]string) string
//
// Comportement : les variables inconnues ({{foo}}) sont laissées telles quelles.

import "testing"

// ========================================================================
// TestRender_all_vars
// Tous les placeholders connus sont remplacés simultanément
// ========================================================================

func TestRender_all_vars(t *testing.T) {
	vars := map[string]string{
		"hostname":    "my-server-01",
		"event":       "host.new",
		"timestamp":   "2026-05-22T14:30:00Z",
		"status":      "disconnected",
		"enrolled_at": "2026-05-22T14:30:00Z",
	}
	tmpl := "{{hostname}} {{event}} {{timestamp}} {{status}} {{enrolled_at}}"
	got := Render(tmpl, vars)
	want := "my-server-01 host.new 2026-05-22T14:30:00Z disconnected 2026-05-22T14:30:00Z"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// ========================================================================
// TestRender_unknown_var
// Variable inconnue laissée telle quelle : {{foo}} → {{foo}}
// ========================================================================

func TestRender_unknown_var(t *testing.T) {
	vars := map[string]string{"hostname": "h1"}
	got := Render("{{hostname}} {{unknown}}", vars)
	want := "h1 {{unknown}}"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// ========================================================================
// TestRender_no_vars
// Chaîne sans placeholders retournée telle quelle (vars ignorées)
// ========================================================================

func TestRender_no_vars(t *testing.T) {
	vars := map[string]string{"hostname": "h1", "event": "host.up"}
	got := Render("no variables here", vars)
	if got != "no variables here" {
		t.Errorf("got %q, want %q", got, "no variables here")
	}
}

// ========================================================================
// TestRender_partial
// Seuls les placeholders présents dans le template sont remplacés ;
// variables absentes de vars → {{var}} inchangé
// ========================================================================

func TestRender_partial(t *testing.T) {
	vars := map[string]string{
		"hostname":  "my-server-01",
		"timestamp": "2026-05-22T14:30:00Z",
		// "event", "status" not set
	}
	got := Render("{{timestamp}} NEW {{hostname}}\n", vars)
	want := "2026-05-22T14:30:00Z NEW my-server-01\n"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// ========================================================================
// TestRender_empty_string
// Chaîne vide en entrée → chaîne vide en sortie
// ========================================================================

func TestRender_empty_string(t *testing.T) {
	vars := map[string]string{"hostname": "h1"}
	got := Render("", vars)
	if got != "" {
		t.Errorf("expected empty string, got %q", got)
	}
}

// ========================================================================
// LOT-3.2 (#246 remark, T21) — a variable that is KNOWN but not carried by the event renders EMPTY;
// an UNKNOWN token stays as written. Variables known: eventEnvKeys + the base keys (hostname, event,
// timestamp, status, enrolled_at, relay_chain, relay_origin, group_vars…).
// RED before T21: the token of a known-but-absent variable is left in place.
// ========================================================================

func TestRender_known_but_absent_variable_is_empty(t *testing.T) {
	vars := map[string]string{"hostname": "h1", "event": "relay.failover"}
	got := Render("host={{hostname}} previous={{previous_instance_id}} cause={{cause}}", vars)
	want := "host=h1 previous= cause="
	if got != want {
		t.Errorf("got %q, want %q (previous_instance_id and cause are known variables, absent from vars)", got, want)
	}
}

func TestRender_known_variable_with_empty_value_is_empty(t *testing.T) {
	got := Render("previous={{previous_instance_id}}.", map[string]string{"previous_instance_id": ""})
	if got != "previous=." {
		t.Errorf("got %q, want %q", got, "previous=.")
	}
}

func TestRender_mix_known_absent_unknown_and_present(t *testing.T) {
	vars := map[string]string{"instance_id": "i-42"}
	got := Render("{{instance_id}}|{{previous_instance_id}}|{{not_a_variable}}|{{old_chain}}|{{upstream_dropped_events_total}}", vars)
	want := "i-42||{{not_a_variable}}||"
	if got != want {
		t.Errorf("got %q, want %q (unknown tokens stay, known-absent ones become empty)", got, want)
	}
}

func TestRender_known_absent_with_no_vars_at_all(t *testing.T) {
	if got := Render("a={{previous_instance_id}}", nil); got != "a=" {
		t.Errorf("Render(nil vars) = %q, want %q (a known variable is still blanked)", got, "a=")
	}
	if got := Render("a={{not_a_variable}}", nil); got != "a={{not_a_variable}}" {
		t.Errorf("Render(nil vars) = %q, want the unknown token untouched", got)
	}
}

func TestRender_every_event_variable_is_known(t *testing.T) {
	for _, k := range append([]string{"hostname", "event", "timestamp", "status", "enrolled_at", "relay_chain", "old_relay", "new_relay"}, eventEnvKeys...) {
		tok := "{{" + k + "}}"
		if got := Render("["+tok+"]", map[string]string{"hostname": "x"}); got == "["+tok+"]" && k != "hostname" {
			t.Errorf("variable %q is known (event variable) but its token was left in place by Render", k)
		}
	}
}
