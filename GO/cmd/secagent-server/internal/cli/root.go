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
	Version:       Version,
}

func init() {
	rootCmd.PersistentFlags().StringVar(&globalFormat, "format", "table", "Output format: table, json, yaml")

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
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		var ee *ExitError
		if errors.As(err, &ee) && ee.Code != 0 {
			os.Exit(ee.Code)
		}
		os.Exit(1)
	}
}

// IsCommand reports whether name is a top-level command of the CLI (registered on the cobra root,
// plus the built-in help and completion). main uses it to choose between the CLI and the server, so
// a newly registered command can never fall through to starting a server.
func IsCommand(name string) bool {
	if name == "help" || name == "completion" {
		return true
	}
	for _, c := range rootCmd.Commands() {
		if c.Name() == name || c.HasAlias(name) {
			return true
		}
	}
	return false
}

// CommandNames lists the registered top-level commands (tests).
func CommandNames() []string {
	var names []string
	for _, c := range rootCmd.Commands() {
		names = append(names, c.Name())
	}
	return names
}
