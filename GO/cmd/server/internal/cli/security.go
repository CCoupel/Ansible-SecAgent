package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// securityCmd is the top-level "security" subcommand.
var securityCmd = &cobra.Command{
	Use:   "security",
	Short: "Manage security keys, tokens and blacklist",
}

func init() {
	securityCmd.AddCommand(securityKeysCmd, securityTokensCmd, securityBlacklistCmd)
}

// ── security keys ─────────────────────────────────────────────────────────────

var securityKeysCmd = &cobra.Command{
	Use:   "keys",
	Short: "Manage JWT signing keys",
}

func init() {
	securityKeysCmd.AddCommand(securityKeysStatusCmd, securityKeysRotateCmd)
}

var securityKeysStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show current key rotation status",
	RunE: func(cmd *cobra.Command, args []string) error {
		data, status, err := apiRequest("GET", "/api/admin/security/keys/status", nil)
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
			fmt.Fprintln(tw, "FIELD\tVALUE")
			for _, k := range []string{
				"current_key_sha256", "previous_key_sha256",
				"rotation_active", "deadline", "agents_total",
			} {
				val := m[k]
				if val == nil {
					val = ""
				}
				fmt.Fprintf(tw, "%s\t%v\n", k, val)
			}
			tw.Flush()
		})
	},
}

var securityKeysRotateGrace string

var securityKeysRotateCmd = &cobra.Command{
	Use:   "rotate",
	Short: "Rotate JWT signing keys (sends rekey to connected agents)",
	RunE: func(cmd *cobra.Command, args []string) error {
		body := map[string]string{}
		if securityKeysRotateGrace != "" {
			body["grace"] = securityKeysRotateGrace
		}

		var reqBody interface{}
		if len(body) > 0 {
			reqBody = body
		}

		data, status, err := apiRequest("POST", "/api/admin/keys/rotate", reqBody)
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
			fmt.Fprintln(tw, "FIELD\tVALUE")
			for _, k := range []string{
				"current_key_sha256", "previous_key_sha256",
				"deadline", "agents_migrated", "agents_total",
			} {
				fmt.Fprintf(tw, "%s\t%v\n", k, m[k])
			}
			tw.Flush()
		})
	},
}

func init() {
	securityKeysRotateCmd.Flags().StringVar(&securityKeysRotateGrace, "grace", "", "Grace period (e.g. 24h, 2h30m) — default 24h")
}

// ── security tokens ───────────────────────────────────────────────────────────

var securityTokensCmd = &cobra.Command{
	Use:   "tokens",
	Short: "Manage agent JWT tokens",
}

func init() {
	securityTokensCmd.AddCommand(securityTokensListCmd)
}

var securityTokensListCmd = &cobra.Command{
	Use:   "list",
	Short: "List active agent JWT tokens",
	RunE: func(cmd *cobra.Command, args []string) error {
		data, status, err := apiRequest("GET", "/api/admin/security/tokens", nil)
		if err != nil {
			return err
		}
		if code := checkError(data, status); code != 0 {
			os.Exit(code)
		}

		var tokens []map[string]interface{}
		if err := json.Unmarshal(data, &tokens); err != nil {
			return fmt.Errorf("parse response: %w", err)
		}

		return printOutput(globalFormat, tokens, func(v interface{}) {
			list := v.([]map[string]interface{})
			tw := newTabWriter()
			fmt.Fprintln(tw, "HOSTNAME\tJTI\tSTATUS\tLAST_SEEN")
			for _, t := range list {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n",
					t["hostname"], t["jti"], t["status"], t["last_seen"])
			}
			tw.Flush()
		})
	},
}

// ── security blacklist ────────────────────────────────────────────────────────

var securityBlacklistCmd = &cobra.Command{
	Use:   "blacklist",
	Short: "Manage JTI blacklist",
}

func init() {
	securityBlacklistCmd.AddCommand(securityBlacklistListCmd, securityBlacklistPurgeCmd)
}

var securityBlacklistListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all blacklisted JTIs",
	RunE: func(cmd *cobra.Command, args []string) error {
		data, status, err := apiRequest("GET", "/api/admin/security/blacklist", nil)
		if err != nil {
			return err
		}
		if code := checkError(data, status); code != 0 {
			os.Exit(code)
		}

		var entries []map[string]interface{}
		if err := json.Unmarshal(data, &entries); err != nil {
			return fmt.Errorf("parse response: %w", err)
		}

		return printOutput(globalFormat, entries, func(v interface{}) {
			list := v.([]map[string]interface{})
			tw := newTabWriter()
			fmt.Fprintln(tw, "JTI\tHOSTNAME\tREASON\tREVOKED_AT\tEXPIRES_AT")
			for _, e := range list {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
					e["jti"], e["hostname"], e["reason"],
					e["revoked_at"], e["expires_at"])
			}
			tw.Flush()
		})
	},
}

var securityBlacklistPurgeCmd = &cobra.Command{
	Use:   "purge",
	Short: "Delete expired blacklist entries",
	RunE: func(cmd *cobra.Command, args []string) error {
		data, status, err := apiRequest("POST", "/api/admin/security/blacklist/purge", nil)
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

		deleted := result["deleted"]
		fmt.Printf("Purged %v expired blacklist entries\n", deleted)
		return nil
	},
}
