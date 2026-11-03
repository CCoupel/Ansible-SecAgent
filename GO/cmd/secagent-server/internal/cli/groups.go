// SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
// SPDX-License-Identifier: AGPL-3.0-or-later

package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

// hardenGroups makes every command that only groups subcommands (minions, security, inventory, server,
// tokens, hooks, relays, state, keys and their nested groups) refuse an unknown word: error, exit 1, the
// group's help on stderr (#219; cobra's default printed the help and exited 0, so a typo in a script
// looked like a success). The group alone, or with --help, still prints its help and exits 0.
// Idempotent; Execute calls it once the whole tree is registered.
func hardenGroups(c *cobra.Command) {
	for _, sub := range c.Commands() {
		hardenGroups(sub)
	}
	if !c.HasSubCommands() || c.Runnable() || c == rootCmd {
		return
	}
	c.Args = func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return nil
		}
		_ = cmd.Usage() // stderr
		return fmt.Errorf("unknown command %q for %q", args[0], cmd.CommandPath())
	}
	c.RunE = func(cmd *cobra.Command, args []string) error { return cmd.Help() }
}
