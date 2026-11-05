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
