package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// serverCmd is the top-level "server" subcommand.
var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Show relay server status and statistics",
}

func init() {
	serverCmd.AddCommand(serverStatusCmd, serverStatsCmd)
}

// ── server status ─────────────────────────────────────────────────────────────

var serverStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show server health (NATS, DB, WS connections, uptime)",
	RunE: func(cmd *cobra.Command, args []string) error {
		data, status, err := apiRequest("GET", "/api/admin/status", nil)
		if err != nil {
			return err
		}
		if code := checkError(data, status); code != 0 {
			os.Exit(code)
		}

		var result map[string]interface{}
		if err := json.Unmarshal(data, &result); err != nil {
			return fmt.Errorf("parse response: %w", err)
		}

		return printOutput(globalFormat, result, func(v interface{}) {
			m := v.(map[string]interface{})
			tw := newTabWriter()
			fmt.Fprintln(tw, "COMPONENT\tSTATUS")
			fmt.Fprintf(tw, "nats\t%v\n", m["nats"])
			fmt.Fprintf(tw, "db\t%v\n", m["db"])
			fmt.Fprintf(tw, "ws_connections\t%v\n", m["ws_connections"])
			fmt.Fprintf(tw, "uptime\t%v\n", m["uptime"])
			tw.Flush()
		})
	},
}

// ── server stats ──────────────────────────────────────────────────────────────

var serverStatsCmd = &cobra.Command{
	Use:   "stats",
	Short: "Show operational statistics (agents connected/total, tasks active)",
	RunE: func(cmd *cobra.Command, args []string) error {
		data, status, err := apiRequest("GET", "/api/admin/stats", nil)
		if err != nil {
			return err
		}
		if code := checkError(data, status); code != 0 {
			os.Exit(code)
		}

		var result map[string]interface{}
		if err := json.Unmarshal(data, &result); err != nil {
			return fmt.Errorf("parse response: %w", err)
		}

		return printOutput(globalFormat, result, func(v interface{}) {
			m := v.(map[string]interface{})
			tw := newTabWriter()
			fmt.Fprintln(tw, "METRIC\tVALUE")
			fmt.Fprintf(tw, "agents_connected\t%v\n", m["agents_connected"])
			fmt.Fprintf(tw, "agents_total\t%v\n", m["agents_total"])
			fmt.Fprintf(tw, "tasks_active\t%v\n", m["tasks_active"])
			tw.Flush()
		})
	},
}
