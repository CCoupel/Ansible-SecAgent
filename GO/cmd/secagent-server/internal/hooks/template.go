// SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
// SPDX-License-Identifier: AGPL-3.0-or-later

package hooks

import "strings"

// baseVars are the variables every event defines (buildVars), besides the detail ones (eventEnvKeys).
var baseVars = []string{"event", "hostname", "status", "timestamp", "enrolled_at", "relay_chain", "relay_origin"}

// KnownVars lists every variable a template may use: the base ones and the per-event detail ones
// (eventEnvKeys). A known variable that an event does not carry renders as an empty string.
func KnownVars() []string {
	out := make([]string, 0, len(baseVars)+len(eventEnvKeys))
	out = append(out, baseVars...)
	return append(out, eventEnvKeys...)
}

var knownVarSet = func() map[string]struct{} {
	m := make(map[string]struct{}, len(baseVars)+len(eventEnvKeys))
	for _, k := range KnownVars() {
		m[k] = struct{}{}
	}
	return m
}()

// Render replaces {{key}} tokens in tmpl with values from vars. A KNOWN variable (KnownVars) that
// vars does not carry for this event is replaced by the empty string (e.g. {{previous_instance_id}}
// on a relay.failover with cause start); a token that is not a known variable (e.g. {{foo}}) is
// left unchanged.
func Render(tmpl string, vars map[string]string) string {
	if !strings.Contains(tmpl, "{{") {
		return tmpl
	}
	pairs := make([]string, 0, (len(vars)+len(knownVarSet))*2)
	for k, v := range vars {
		pairs = append(pairs, "{{"+k+"}}", v)
	}
	for k := range knownVarSet {
		if _, ok := vars[k]; !ok {
			pairs = append(pairs, "{{"+k+"}}", "")
		}
	}
	return strings.NewReplacer(pairs...).Replace(tmpl)
}
