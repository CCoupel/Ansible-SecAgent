package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"secagent-server/cmd/secagent-server/internal/state"
)

// state init is a LOCAL command: it writes the initial relay.state in STATE_DIR, talks to no API
// and starts no port.

var (
	stateInitDir       string
	stateInitTestMode  bool
	stateInitRSABitsFn = func() int { return 0 } // 0 = default (4096); tests lower it
)

var stateCmd = &cobra.Command{
	Use:   "state",
	Short: "Manage the relay state file (local, no API)",
}

var stateInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Create the initial relay.state (RSA key and JWT secret) in STATE_DIR",
	Long: `Creates the initial state of a relay: a fresh RSA-4096 keypair and JWT secret, encrypted with
RSA_MASTER_KEY (required, except with --insecure-test-mode).

Refuses to act when relay.state, relay.state.prev or relay.lock already exists in STATE_DIR.
The server never creates its state implicitly: without relay.state it refuses to start.`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		dir := stateInitDir
		if dir == "" {
			dir = state.DirFromEnv()
		}
		err := state.Init(state.InitOptions{
			Dir:            dir,
			MasterKey:      os.Getenv("RSA_MASTER_KEY"),
			AllowPlaintext: stateInitTestMode,
			RSABits:        stateInitRSABitsFn(),
		})
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(cmd.OutOrStdout(), "state initialized in %s\n", dir)
		return err
	},
}

func init() {
	stateInitCmd.Flags().StringVar(&stateInitDir, "state-dir", "", "state directory (default $STATE_DIR, else /data)")
	stateInitCmd.Flags().BoolVar(&stateInitTestMode, "insecure-test-mode", false, "allow init without RSA_MASTER_KEY (secrets in clear): tests only")
	stateCmd.AddCommand(stateInitCmd)
	rootCmd.AddCommand(stateCmd)
}
