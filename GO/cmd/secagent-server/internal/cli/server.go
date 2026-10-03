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

		return printOutput(globalFormat, result, func(v interface{}) error {
			m := v.(map[string]interface{})
			tp := newTabPrinter()
			tp.println("COMPONENT\tSTATUS")
			tp.printf("nats\t%v\n", m["nats"])
			tp.printf("db\t%v\n", m["db"])
			tp.printf("ws_connections\t%v\n", m["ws_connections"])
			tp.printf("uptime\t%v\n", m["uptime"])
			return tp.flush()
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

		return printOutput(globalFormat, result, func(v interface{}) error {
			m := v.(map[string]interface{})
			tp := newTabPrinter()
			tp.println("METRIC\tVALUE")
			tp.printf("agents_connected\t%v\n", m["agents_connected"])
			tp.printf("agents_total\t%v\n", m["agents_total"])
			tp.printf("tasks_active\t%v\n", m["tasks_active"])
			return tp.flush()
		})
	},
}
