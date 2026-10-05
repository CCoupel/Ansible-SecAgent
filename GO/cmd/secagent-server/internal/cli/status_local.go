package cli

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"secagent-server/cmd/secagent-server/internal/localstatus"
)

// statusNow is the clock of the verdict (tests).
var statusNow = time.Now

var statusLocal bool

// status --local is a LOCAL command: it reads the process' status file (no port, no API call) and
// exits 0 only when the process is healthy (docker/compose healthcheck).
var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Health of THIS process from its local status file (--local)",
	Long: `With --local: reads the status file of the running process (RELAY_STATUS_FILE, default
/run/secagent/status.json), opens no port and calls no API. Exit 0: healthy master or healthy secondary.
Non-zero: file absent or unreadable, lock activity too old (frozen process), start failed or lock lost.
For the API view of a running master use "server status".`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if !statusLocal {
			return errors.New("use --local (health of this process) or 'server status' (API view of the master)")
		}
		path := localstatus.PathFromEnv()
		f, err := localstatus.Read(path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return &ExitError{Code: 1, Msg: fmt.Sprintf("unhealthy: no status file at %s (process not started?)", path)}
			}
			return &ExitError{Code: 1, Msg: fmt.Sprintf("unhealthy: %v", err)}
		}
		ok, reason := localstatus.Verdict(f, statusNow())
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "role\t%s\ninstance_id\t%s\nstate\t%s\n", f.Role, f.InstanceID, f.State)
		if !ok {
			return &ExitError{Code: 1, Msg: "unhealthy: " + reason}
		}
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "healthy")
		return nil
	},
}

func init() {
	statusCmd.Flags().BoolVar(&statusLocal, "local", false, "judge this process from its local status file (no port, no API)")
	rootCmd.AddCommand(statusCmd)
}
