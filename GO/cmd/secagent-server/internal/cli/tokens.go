package cli

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// tokensCmd is the top-level "tokens" subcommand.
var tokensCmd = &cobra.Command{
	Use:   "tokens",
	Short: "Manage enrollment and plugin tokens",
}

func init() {
	tokensCmd.AddCommand(
		tokensCreateCmd,
		tokensListCmd,
		tokensRevokeCmd,
		tokensDeleteCmd,
		tokensPurgeCmd,
	)
}

// ── tokens create ─────────────────────────────────────────────────────────────

var (
	createRole            string
	createHostnamePattern string
	createReusable        bool
	createExpires         string
	createDescription     string
	createAllowedIPs      string
	createAllowedHostname string
)

var tokensCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create an enrollment or plugin token",
	Long: `Create an enrollment or plugin token.

Examples:
  secagent-server tokens create --role enrollment --hostname-pattern "vp.*" --reusable --expires 30d
  secagent-server tokens create --role plugin --description "Terraform" --allowed-ips "10.0.0.0/8" --expires 24h`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if createRole != "enrollment" && createRole != "plugin" {
			return fmt.Errorf("--role must be 'enrollment' or 'plugin'")
		}

		body := map[string]interface{}{
			"role": createRole,
		}

		switch createRole {
		case "enrollment":
			if strings.TrimSpace(createHostnamePattern) == "" {
				return fmt.Errorf("--hostname-pattern is required for enrollment tokens")
			}
			if _, err := regexp.Compile(createHostnamePattern); err != nil {
				return fmt.Errorf("invalid --hostname-pattern regexp: %w", err)
			}
			reusable := 0
			if createReusable {
				reusable = 1
			}
			body["hostname_pattern"] = createHostnamePattern
			body["reusable"] = reusable

		case "plugin":
			if createAllowedIPs != "" {
				if err := validateCIDRs(createAllowedIPs); err != nil {
					return err
				}
			}
			if createAllowedHostname != "" {
				if _, err := regexp.Compile(createAllowedHostname); err != nil {
					return fmt.Errorf("invalid --allowed-hostname-pattern regexp: %w", err)
				}
			}
			body["description"] = createDescription
			body["allowed_ips"] = createAllowedIPs
			body["allowed_hostname_pattern"] = createAllowedHostname
		}

		// Parse expiry
		if createExpires != "" && createExpires != "never" {
			exp, err := parseDuration(createExpires)
			if err != nil {
				return fmt.Errorf("invalid --expires value %q: %w", createExpires, err)
			}
			body["expires_at"] = exp.UTC().Format(time.RFC3339)
		}

		data, status, err := apiRequest("POST", "/api/admin/tokens", body)
		if err != nil {
			return err
		}
		if code := checkError(data, status); code != 0 {
			os.Exit(code)
		}

		var resp map[string]interface{}
		if err := json.Unmarshal(data, &resp); err != nil {
			return fmt.Errorf("parse response: %w", err)
		}

		return printOutput(globalFormat, resp, func(v interface{}) {
			r := v.(map[string]interface{})
			fmt.Println("Token created successfully.")
			fmt.Println()
			fmt.Printf("  Token (save now — shown only once): %s\n", r["token"])
			fmt.Printf("  ID:         %s\n", r["id"])
			fmt.Printf("  Role:       %s\n", r["role"])
			if p, ok := r["hostname_pattern"].(string); ok && p != "" {
				fmt.Printf("  Pattern:    %s\n", p)
			}
			if d, ok := r["description"].(string); ok && d != "" {
				fmt.Printf("  Desc:       %s\n", d)
			}
			if ips, ok := r["allowed_ips"].(string); ok && ips != "" {
				fmt.Printf("  Allowed IPs: %s\n", ips)
			}
			if hp, ok := r["allowed_hostname_pattern"].(string); ok && hp != "" {
				fmt.Printf("  Hostname pattern: %s\n", hp)
			}
			if exp, ok := r["expires_at"].(string); ok && exp != "" {
				fmt.Printf("  Expires:    %s\n", exp)
			} else {
				fmt.Printf("  Expires:    never\n")
			}
			fmt.Printf("  Created:    %s\n", r["created_at"])
		})
	},
}

func init() {
	tokensCreateCmd.Flags().StringVar(&createRole, "role", "", "Token role: enrollment or plugin (required)")
	tokensCreateCmd.Flags().StringVar(&createHostnamePattern, "hostname-pattern", "", "Regexp for hostname (enrollment tokens)")
	tokensCreateCmd.Flags().BoolVar(&createReusable, "reusable", false, "Allow multiple uses (enrollment tokens; default: one-shot)")
	tokensCreateCmd.Flags().StringVar(&createExpires, "expires", "never", "Expiry: 30d, 24h, 90m, never (default: never)")
	tokensCreateCmd.Flags().StringVar(&createDescription, "description", "", "Human-readable description (plugin tokens)")
	tokensCreateCmd.Flags().StringVar(&createAllowedIPs, "allowed-ips", "", "Comma-separated CIDRs (plugin tokens): \"10.0.0.0/8,192.168.1.0/24\"")
	tokensCreateCmd.Flags().StringVar(&createAllowedHostname, "allowed-hostname-pattern", "", "Regexp for caller hostname (plugin tokens)")
	tokensCreateCmd.MarkFlagRequired("role") //nolint:errcheck
}

// ── tokens list ───────────────────────────────────────────────────────────────

var listRole string

var tokensListCmd = &cobra.Command{
	Use:   "list",
	Short: "List tokens (hash only — no plain text)",
	RunE: func(cmd *cobra.Command, args []string) error {
		path := "/api/admin/tokens"
		if listRole != "" {
			if listRole != "enrollment" && listRole != "plugin" && listRole != "all" {
				return fmt.Errorf("--role must be enrollment, plugin, or all")
			}
			path += "?role=" + listRole
		}

		data, status, err := apiRequest("GET", path, nil)
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
			list, _ := v.([]map[string]interface{})
			if len(list) == 0 {
				fmt.Println("No tokens found.")
				return
			}

			tw := newTabWriter()
			fmt.Fprintln(tw, "ID\tROLE\tHASH (truncated)\tPATTERN/DESC\tEXPIRES\tUSED\tREVOKED")
			for _, t := range list {
				hash := fmt.Sprintf("%v", t["token_hash"])
				if len(hash) > 16 {
					hash = hash[:16] + "..."
				}
				role := fmt.Sprintf("%v", t["role"])
				label := ""
				if v, ok := t["hostname_pattern"].(string); ok && v != "" {
					label = v
				} else if v, ok := t["description"].(string); ok && v != "" {
					label = v
				}
				expires := "-"
				if v, ok := t["expires_at"].(string); ok && v != "" {
					expires = v
				}
				useCount := "-"
				if v, ok := t["use_count"]; ok {
					useCount = fmt.Sprintf("%v", v)
				}
				revoked := "-"
				if v, ok := t["revoked"]; ok {
					revoked = fmt.Sprintf("%v", v)
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
					t["id"], role, hash, label, expires, useCount, revoked)
			}
			tw.Flush()
		})
	},
}

func init() {
	tokensListCmd.Flags().StringVar(&listRole, "role", "", "Filter by role: enrollment, plugin (default: all)")
}

// ── tokens revoke ─────────────────────────────────────────────────────────────

var tokensRevokeCmd = &cobra.Command{
	Use:   "revoke <id>",
	Short: "Soft-revoke a plugin token (sets revoked=1)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		id := args[0]
		data, status, err := apiRequest("POST", "/api/admin/tokens/"+id+"/revoke", map[string]string{})
		if err != nil {
			return err
		}
		if code := checkError(data, status); code != 0 {
			os.Exit(code)
		}
		fmt.Printf("Token %s revoked\n", id)
		return nil
	},
}

// ── tokens delete ─────────────────────────────────────────────────────────────

var tokensDeleteCmd = &cobra.Command{
	Use:   "delete <id>",
	Short: "Hard-delete a token (enrollment or plugin)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		id := args[0]
		data, status, err := apiRequest("DELETE", "/api/admin/tokens/"+id, nil)
		if err != nil {
			return err
		}
		if code := checkError(data, status); code != 0 {
			os.Exit(code)
		}
		fmt.Printf("Token %s deleted\n", id)
		return nil
	},
}

// ── tokens purge ──────────────────────────────────────────────────────────────

var (
	purgeExpired bool
	purgeUsed    bool
)

var tokensPurgeCmd = &cobra.Command{
	Use:   "purge",
	Short: "Bulk-delete expired and/or consumed one-shot tokens",
	Long: `Purge tokens matching the selected criteria.

  --expired  Remove tokens whose expires_at < now
  --used     Remove one-shot enrollment tokens already consumed

At least one flag must be specified.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if !purgeExpired && !purgeUsed {
			return fmt.Errorf("specify at least one of --expired or --used")
		}

		path := "/api/admin/tokens/purge?"
		params := []string{}
		if purgeExpired {
			params = append(params, "expired=1")
		}
		if purgeUsed {
			params = append(params, "used=1")
		}
		path += strings.Join(params, "&")

		data, status, err := apiRequest("POST", path, map[string]string{})
		if err != nil {
			return err
		}
		if code := checkError(data, status); code != 0 {
			os.Exit(code)
		}

		var resp map[string]interface{}
		if err := json.Unmarshal(data, &resp); err != nil {
			return fmt.Errorf("parse response: %w", err)
		}

		return printOutput(globalFormat, resp, func(v interface{}) {
			r := v.(map[string]interface{})
			fmt.Printf("Purged %v token(s) at %s\n", r["deleted_count"], r["purged_at"])
		})
	},
}

func init() {
	tokensPurgeCmd.Flags().BoolVar(&purgeExpired, "expired", false, "Purge expired tokens")
	tokensPurgeCmd.Flags().BoolVar(&purgeUsed, "used", false, "Purge consumed one-shot enrollment tokens")
}

// ── helpers ───────────────────────────────────────────────────────────────────

// parseDuration converts a user-friendly duration string to an absolute time.Time.
// Supported formats:
//   - "Nd"  — N days from now (e.g. "30d")
//   - "Nh"  — N hours from now (e.g. "24h")
//   - "Nm"  — N minutes from now (e.g. "90m")
//   - RFC3339 string (e.g. "2026-12-31T00:00:00Z")
//
// "never" is handled by callers (returns no call to this function).
func parseDuration(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	now := time.Now().UTC()

	// Try day suffix "Nd"
	if strings.HasSuffix(s, "d") {
		n, err := strconv.Atoi(strings.TrimSuffix(s, "d"))
		if err != nil || n <= 0 {
			return time.Time{}, fmt.Errorf("invalid day count in %q", s)
		}
		return now.AddDate(0, 0, n), nil
	}

	// Try Go duration (hours, minutes, seconds: "24h", "90m", "3600s")
	if d, err := time.ParseDuration(s); err == nil {
		if d <= 0 {
			return time.Time{}, fmt.Errorf("duration must be positive")
		}
		return now.Add(d), nil
	}

	// Try RFC3339 absolute timestamp
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}

	return time.Time{}, fmt.Errorf("unrecognised duration format %q (use 30d, 24h, 90m, or RFC3339)", s)
}

// validateCIDRs parses a comma-separated list of CIDR strings and returns an
// error for the first invalid entry.
func validateCIDRs(cidrList string) error {
	for _, entry := range strings.Split(cidrList, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		// Accept plain IPs as /32 or /128
		if net.ParseIP(entry) != nil {
			continue
		}
		if _, _, err := net.ParseCIDR(entry); err != nil {
			return fmt.Errorf("invalid CIDR %q: %w", entry, err)
		}
	}
	return nil
}
