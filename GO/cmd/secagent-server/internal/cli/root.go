package cli

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// globalFormat is the --format flag value shared across all commands.
var globalFormat string

// rootCmd is the cobra root command for secagent-server CLI mode.
// Version is printed by --version; override at build time with -ldflags "-X .../internal/cli.Version=vX.Y.Z".
var Version = "dev"

var rootCmd = &cobra.Command{
	Use:   "secagent-server",
	Short: "Ansible-SecAgent secagent-server CLI",
	Long: `secagent-server — CLI for the Ansible-SecAgent relay server.

Environment variables:
  RELAY_API_URL  Admin API base URL (default: http://localhost:7771)
  ADMIN_TOKEN    Admin bearer token (required)`,
	SilenceUsage:  true,
	SilenceErrors: true,
	// --version is handled here, not by cobra's built-in flag (which answered before looking at the
	// arguments: `--version extra` exited 0). D5 (#220): same as the minion, an extra argument is an error.
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if rootShowVersion {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s version %s\nLicense: AGPL-3.0-or-later\nSource: https://github.com/CCoupel/Ansible-SecAgent\n", cmd.Name(), Version)
			return nil
		}
		return cmd.Help()
	},
}

var rootShowVersion bool

func init() {
	rootCmd.PersistentFlags().StringVar(&globalFormat, "format", "table", "Output format: table, json, yaml")
	rootCmd.Flags().BoolVarP(&rootShowVersion, "version", "v", false, "print the version and exit")

	rootCmd.AddCommand(
		minionsCmd,
		securityCmd,
		inventoryCmd,
		serverCmd,
		tokensCmd,
		hooksCmd,
		relaysCmd,
	)
}

// Execute runs the CLI and exits with the appropriate code.
func Execute() {
	hardenGroups(rootCmd)
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		var ee *ExitError
		if errors.As(err, &ee) && ee.Code != 0 {
			os.Exit(ee.Code)
		}
		os.Exit(1)
	}
}

// CommandNames lists the registered top-level commands (tests).
func CommandNames() []string {
	var names []string
	for _, c := range rootCmd.Commands() {
		names = append(names, c.Name())
	}
	return names
}
