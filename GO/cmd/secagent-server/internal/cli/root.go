package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// globalFormat is the --format flag value shared across all commands.
var globalFormat string

// rootCmd is the cobra root command for secagent-server CLI mode.
var rootCmd = &cobra.Command{
	Use:   "secagent-server",
	Short: "Ansible-SecAgent secagent-server CLI",
	Long: `secagent-server — CLI for the Ansible-SecAgent relay server.

Environment variables:
  RELAY_API_URL  Admin API base URL (default: http://localhost:7771)
  ADMIN_TOKEN    Admin bearer token (required)`,
	SilenceUsage:  true,
	SilenceErrors: true,
}

func init() {
	rootCmd.PersistentFlags().StringVar(&globalFormat, "format", "table", "Output format: table, json, yaml")

	rootCmd.AddCommand(
		minionsCmd,
		securityCmd,
		inventoryCmd,
		serverCmd,
		tokensCmd,
	)
}

// Execute runs the CLI and exits with the appropriate code.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
