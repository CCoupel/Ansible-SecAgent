package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// globalFormat is the --format flag value shared across all commands.
var globalFormat string

// rootCmd is the cobra root command for relay-server CLI mode.
var rootCmd = &cobra.Command{
	Use:   "relay-server",
	Short: "AnsibleRelay relay-server CLI",
	Long: `relay-server — CLI for the AnsibleRelay relay server.

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
