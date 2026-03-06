package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

// minionsCmd is the top-level "minions" subcommand.
var minionsCmd = &cobra.Command{
	Use:   "minions",
	Short: "Manage enrolled agents (minions)",
}

func init() {
	minionsCmd.AddCommand(
		minionsListCmd,
		minionsGetCmd,
		minionsSetStateCmd,
		minionsSuspendCmd,
		minionsResumeCmd,
		minionsRevokeCmd,
		minionsAuthorizeCmd,
		minionsVarsCmd,
	)
}

// ── minions list ──────────────────────────────────────────────────────────────

var minionsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all enrolled agents",
	RunE: func(cmd *cobra.Command, args []string) error {
		data, status, err := apiRequest("GET", "/api/admin/minions", nil)
		if err != nil {
			return err
		}
		if code := checkError(data, status); code != 0 {
			os.Exit(code)
		}

		var agents []map[string]interface{}
		if err := json.Unmarshal(data, &agents); err != nil {
			return fmt.Errorf("parse response: %w", err)
		}

		return printOutput(globalFormat, agents, func(v interface{}) {
			list := v.([]map[string]interface{})
			tw := newTabWriter()
			fmt.Fprintln(tw, "HOSTNAME\tSTATUS\tSUSPENDED\tLAST_SEEN\tENROLLED_AT")
			for _, a := range list {
				fmt.Fprintf(tw, "%s\t%s\t%v\t%s\t%s\n",
					a["hostname"], a["status"], a["suspended"],
					a["last_seen"], a["enrolled_at"])
			}
			tw.Flush()
		})
	},
}

// ── minions get ───────────────────────────────────────────────────────────────

var minionsGetCmd = &cobra.Command{
	Use:   "get <hostname>",
	Short: "Get details for one agent",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		data, status, err := apiRequest("GET", "/api/admin/minions/"+args[0], nil)
		if err != nil {
			return err
		}
		if code := checkError(data, status); code != 0 {
			os.Exit(code)
		}

		var agent map[string]interface{}
		if err := json.Unmarshal(data, &agent); err != nil {
			return fmt.Errorf("parse response: %w", err)
		}

		return printOutput(globalFormat, agent, func(v interface{}) {
			a := v.(map[string]interface{})
			tw := newTabWriter()
			for _, k := range []string{"hostname", "status", "suspended", "last_seen", "enrolled_at", "key_fingerprint"} {
				fmt.Fprintf(tw, "%s\t%v\n", k, a[k])
			}
			tw.Flush()
		})
	},
}

// ── minions set-state ─────────────────────────────────────────────────────────

var minionsSetStateCmd = &cobra.Command{
	Use:   "set-state <hostname> connected|disconnected",
	Short: "Force agent connection state in DB",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		state := args[1]
		if state != "connected" && state != "disconnected" {
			return fmt.Errorf("state must be 'connected' or 'disconnected'")
		}
		data, status, err := apiRequest("POST", "/api/admin/minions/"+args[0]+"/set-state",
			map[string]string{"status": state})
		if err != nil {
			return err
		}
		if code := checkError(data, status); code != 0 {
			os.Exit(code)
		}
		fmt.Printf("Agent %s state set to %s\n", args[0], state)
		return nil
	},
}

// ── minions suspend ───────────────────────────────────────────────────────────

var minionsSuspendCmd = &cobra.Command{
	Use:   "suspend <hostname>",
	Short: "Suspend an agent (exec returns 503)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		data, status, err := apiRequest("POST", "/api/admin/minions/"+args[0]+"/suspend", nil)
		if err != nil {
			return err
		}
		if code := checkError(data, status); code != 0 {
			os.Exit(code)
		}
		fmt.Printf("Agent %s suspended\n", args[0])
		return nil
	},
}

// ── minions resume ────────────────────────────────────────────────────────────

var minionsResumeCmd = &cobra.Command{
	Use:   "resume <hostname>",
	Short: "Resume a suspended agent",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		data, status, err := apiRequest("POST", "/api/admin/minions/"+args[0]+"/resume", nil)
		if err != nil {
			return err
		}
		if code := checkError(data, status); code != 0 {
			os.Exit(code)
		}
		fmt.Printf("Agent %s resumed\n", args[0])
		return nil
	},
}

// ── minions revoke ────────────────────────────────────────────────────────────

var minionsRevokeCmd = &cobra.Command{
	Use:   "revoke <hostname>",
	Short: "Revoke agent token (blacklist JTI + close WS 4001)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		data, status, err := apiRequest("POST", "/api/admin/revoke/"+args[0], nil)
		if err != nil {
			return err
		}
		if code := checkError(data, status); code != 0 {
			os.Exit(code)
		}
		fmt.Printf("Agent %s revoked\n", args[0])
		return nil
	},
}

// ── minions authorize ─────────────────────────────────────────────────────────

var minionsAuthorizeKeyFile string

var minionsAuthorizeCmd = &cobra.Command{
	Use:   "authorize <hostname>",
	Short: "Pre-authorize a public key for enrollment",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if minionsAuthorizeKeyFile == "" {
			return fmt.Errorf("--key-file is required")
		}

		keyBytes, err := os.ReadFile(minionsAuthorizeKeyFile)
		if err != nil {
			return fmt.Errorf("read key file: %w", err)
		}

		body := map[string]string{
			"hostname":       args[0],
			"public_key_pem": string(keyBytes),
			"approved_by":    "cli",
		}
		data, status, err := apiRequest("POST", "/api/admin/authorize", body)
		if err != nil {
			return err
		}
		if code := checkError(data, status); code != 0 {
			os.Exit(code)
		}
		fmt.Printf("Key authorized for %s\n", args[0])
		return nil
	},
}

func init() {
	minionsAuthorizeCmd.Flags().StringVar(&minionsAuthorizeKeyFile, "key-file", "", "Path to PEM public key file")
}

// ── minions vars ──────────────────────────────────────────────────────────────

var minionsVarsCmd = &cobra.Command{
	Use:   "vars",
	Short: "Manage Ansible vars for an agent",
}

func init() {
	minionsVarsCmd.AddCommand(
		minionsVarsGetCmd,
		minionsVarsSetCmd,
		minionsVarsDeleteCmd,
	)
}

var minionsVarsGetCmd = &cobra.Command{
	Use:   "get <hostname>",
	Short: "Get Ansible vars for an agent",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		data, status, err := apiRequest("GET", "/api/admin/minions/"+args[0]+"/vars", nil)
		if err != nil {
			return err
		}
		if code := checkError(data, status); code != 0 {
			os.Exit(code)
		}

		var vars map[string]interface{}
		if err := json.Unmarshal(data, &vars); err != nil {
			return fmt.Errorf("parse response: %w", err)
		}

		return printOutput(globalFormat, vars, func(v interface{}) {
			m := v.(map[string]interface{})
			tw := newTabWriter()
			fmt.Fprintln(tw, "KEY\tVALUE")
			for k, val := range m {
				fmt.Fprintf(tw, "%s\t%v\n", k, val)
			}
			tw.Flush()
		})
	},
}

var minionsVarsSetCmd = &cobra.Command{
	Use:   "set <hostname> key=value [key=value ...]",
	Short: "Set Ansible vars for an agent",
	Args:  cobra.MinimumNArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		hostname := args[0]
		kvPairs := make(map[string]interface{})
		for _, pair := range args[1:] {
			parts := strings.SplitN(pair, "=", 2)
			if len(parts) != 2 {
				return fmt.Errorf("invalid key=value pair: %q", pair)
			}
			kvPairs[parts[0]] = parts[1]
		}

		data, status, err := apiRequest("POST", "/api/admin/minions/"+hostname+"/vars", kvPairs)
		if err != nil {
			return err
		}
		if code := checkError(data, status); code != 0 {
			os.Exit(code)
		}
		fmt.Printf("Vars updated for %s\n", hostname)
		return nil
	},
}

var minionsVarsDeleteCmd = &cobra.Command{
	Use:   "delete <hostname> <key>",
	Short: "Delete a var key from an agent",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		data, status, err := apiRequest("DELETE",
			"/api/admin/minions/"+args[0]+"/vars/"+args[1], nil)
		if err != nil {
			return err
		}
		if code := checkError(data, status); code != 0 {
			os.Exit(code)
		}
		fmt.Printf("Var %q deleted from %s\n", args[1], args[0])
		return nil
	},
}
