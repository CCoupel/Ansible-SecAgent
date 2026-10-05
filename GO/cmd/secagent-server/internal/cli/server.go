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
	Short: "Show server health (DB, WS connections, uptime)",
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
			tp.printf("db\t%v\n", m["db"])
			tp.printf("ws_connections\t%v\n", m["ws_connections"])
			tp.printf("uptime\t%v\n", m["uptime"])
			if err := tp.flush(); err != nil {
				return err
			}
			return printLinks(m["links"])
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

// printLinks shows the parent / push-child link states (#154); nothing when the node has none.
func printLinks(raw interface{}) error {
	links, ok := raw.(map[string]interface{})
	if !ok {
		return nil
	}
	up, _ := links["upstream"].(map[string]interface{})
	push, _ := links["push_children"].([]interface{})
	if up == nil && len(push) == 0 {
		return nil
	}
	_, _ = fmt.Println()
	tp := newTabPrinter()
	tp.println("LINK\tPEER\tSTATE\tSINCE\tREASON")
	if up != nil {
		tp.printf("upstream (%v)\t%v\t%v\t%v\t%v\n", up["mode"], dash(up["peer"]), up["state"], dash(up["since"]), dash(up["reason"]))
	}
	for _, c := range push {
		m, _ := c.(map[string]interface{})
		tp.printf("push child\t%v\t%v\t%v\t%v\n", m["relay_id"], m["state"], dash(m["since"]), dash(m["reason"]))
	}
	if err := tp.flush(); err != nil {
		return err
	}
	if d, _ := links["degraded"].(bool); d {
		_, _ = fmt.Println("\nWARNING: a link was refused permanently (refused_permanent): operator action required.")
	}
	return nil
}

func dash(v interface{}) interface{} {
	if s, ok := v.(string); !ok || s == "" {
		return "-"
	}
	return v
}
