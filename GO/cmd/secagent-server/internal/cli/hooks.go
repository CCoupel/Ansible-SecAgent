package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"secagent-server/cmd/secagent-server/internal/hooks"
)

// hooksCmd is the top-level cobra command for hook-related operations.
var hooksCmd = &cobra.Command{
	Use:   "hooks",
	Short: "Manage event hooks configuration and execution log",
}

// ── hooks status ─────────────────────────────────────────────────────────────

var hooksStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show active hooks configuration",
	Long:  `Reads and displays the hooks configuration file (RELAY_HOOKS_CONFIG env or default path).`,
	RunE:  runHooksStatus,
}

func runHooksStatus(cmd *cobra.Command, args []string) error {
	path := hooks.ConfigPath()
	cfg, err := hooks.LoadConfig(path)
	if err != nil {
		return fmt.Errorf("hooks config %s: %w", path, err)
	}

	_, _ = fmt.Printf("Hooks config : %s\n", path)

	if cfg == nil {
		_, _ = fmt.Println("Status       : not found — 0 hooks active")
		return nil
	}

	_, _ = fmt.Printf("Hooks        : %d defined\n\n", len(cfg.Hooks))

	tp := newTabPrinter()
	tp.println("EVENT\tACTIONS")
	tp.println("─────\t───────")
	for _, h := range cfg.Hooks {
		actions := ""
		for i, a := range h.Actions {
			if i > 0 {
				actions += ", "
			}
			switch a.Type {
			case "webhook", "api":
				m := a.Method
				if m == "" {
					m = "POST"
				}
				if a.Type == "webhook" {
					m = "POST"
				}
				actions += fmt.Sprintf("%s(%s %s)", a.Type, m, a.URL)
			case "shell":
				actions += fmt.Sprintf("shell(%s)", a.Cmd)
			case "file":
				actions += fmt.Sprintf("file(%s)", a.Path)
			default:
				actions += a.Type
			}
		}
		tp.printf("%s\t%s\n", h.Event, actions)
	}
	return tp.flush()
}

// ── hooks log ─────────────────────────────────────────────────────────────────

var (
	hooksLogLimit    int
	hooksLogEvent    string
	hooksLogHostname string
	hooksLogFormat   string
)

var hooksLogCmd = &cobra.Command{
	Use:   "log",
	Short: "Show hook execution log",
	Long:  `Displays recent hook action executions from the server action journal (actions.log).`,
	RunE:  runHooksLog,
}

func runHooksLog(cmd *cobra.Command, args []string) error {
	path := fmt.Sprintf("/api/admin/hooks/log?limit=%d", hooksLogLimit)
	if hooksLogEvent != "" {
		path += "&event=" + hooksLogEvent
	}
	if hooksLogHostname != "" {
		path += "&hostname=" + hooksLogHostname
	}

	data, status, err := apiRequest("GET", path, nil)
	if err != nil {
		return err
	}
	if c := checkError(data, status); c != 0 {
		os.Exit(c)
	}

	var entries []map[string]interface{}
	if err := json.Unmarshal(data, &entries); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}

	if hooksLogFormat == "json" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(entries)
	}

	// Table format
	tp := newTabPrinter()
	tp.println("EXECUTED_AT\tEVENT\tHOSTNAME\tTYPE\tSUCCESS\tDURATION\tERROR")
	for _, e := range entries {
		success := "✗"
		if s, ok := e["success"].(bool); ok && s {
			success = "✓"
		}
		dur := "-"
		if d, ok := e["duration_ms"].(float64); ok {
			dur = fmt.Sprintf("%dms", int64(d))
		}
		errMsg, _ := e["error"].(string)
		tp.printf("%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			e["executed_at"], e["event"], e["hostname"],
			e["action_type"], success, dur, errMsg,
		)
	}
	return tp.flush()
}

func init() {
	hooksLogCmd.Flags().IntVar(&hooksLogLimit, "limit", 50, "Max entries to show (1–200)")
	hooksLogCmd.Flags().StringVar(&hooksLogEvent, "event", "", "Filter by event type (e.g. host.new)")
	hooksLogCmd.Flags().StringVar(&hooksLogHostname, "hostname", "", "Filter by agent hostname")
	hooksLogCmd.Flags().StringVar(&hooksLogFormat, "format", "table", "Output format: table|json")

	hooksCmd.AddCommand(hooksStatusCmd, hooksLogCmd)
}
