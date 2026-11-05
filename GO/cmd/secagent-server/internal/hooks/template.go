// SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
// SPDX-License-Identifier: AGPL-3.0-or-later

package hooks

import "strings"

// Render replaces {{key}} tokens in tmpl with values from vars.
// Known keys come from the vars map; unknown tokens (e.g. {{foo}})
// are left unchanged.
func Render(tmpl string, vars map[string]string) string {
	if len(vars) == 0 {
		return tmpl
	}
	pairs := make([]string, 0, len(vars)*2)
	for k, v := range vars {
		pairs = append(pairs, "{{"+k+"}}", v)
	}
	return strings.NewReplacer(pairs...).Replace(tmpl)
}
