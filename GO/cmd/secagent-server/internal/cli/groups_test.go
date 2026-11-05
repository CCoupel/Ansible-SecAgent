// SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
// SPDX-License-Identifier: AGPL-3.0-or-later

package cli

import (
	"strings"
	"testing"
)

// #219: an unknown word after a group is an error (exit 1, help on stderr); the group alone and --help keep exit 0.
func TestGroups_UnknownSubcommandExits1AndTheGroupAloneExits0(t *testing.T) {
	groups := [][]string{{"minions"}, {"security"}, {"inventory"}, {"server"}, {"tokens"}, {"hooks"}, {"relays"}, {"state"}, {"keys"},
		{"minions", "vars"}, {"state", "link-trust"}}
	for _, g := range groups {
		name := strings.Join(g, " ")
		out, errOut, code := runCLI(t, append(append([]string{}, g...), "frob")...)
		if code != 1 {
			t.Errorf("%s frob: exit %d, want 1 (stdout %q)", name, code, out)
		}
		if !strings.Contains(errOut, "unknown command") || !strings.Contains(errOut, "Usage:") {
			t.Errorf("%s frob: stderr must carry the error and the group's help:\n%s", name, errOut)
		}
		if _, _, code := runCLI(t, g...); code != 0 {
			t.Errorf("%s alone: exit %d, want 0", name, code)
		}
		if out, _, code := runCLI(t, append(append([]string{}, g...), "--help")...); code != 0 || !strings.Contains(out, "Usage:") {
			t.Errorf("%s --help: exit %d", name, code)
		}
	}
}
