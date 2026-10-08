package cli

import (
	"encoding/json"
	"fmt"
	"log/slog"
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
	Short: "Manage enrollment, plugin and relay link tokens (relay-child / relay-parent)",
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
	createSub             string
	createAud             string
)

// maxLinkLifetime mirrors link.MaxTTL (the server enforces it too).
const maxLinkLifetime = 365 * 24 * time.Hour

func isLinkRole(r string) bool { return r == "relay-child" || r == "relay-parent" }

var relayIDRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,62}$`)

var tokensCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create an enrollment, plugin, relay-child or relay-parent token",
	Long: `Create an enrollment, plugin, relay-child or relay-parent token.

relay-child / relay-parent are LINK tokens (v3.0.4): Ed25519 JWTs minted on the ROOT relay only (a
node with a parent answers 409 not_root), shown ONCE.
  relay-child  (pull): --sub = the child X that presents it, --aud = its parent P that verifies it
  relay-parent (push): --sub = the parent P that presents it, --aud = the child X that verifies it
--expires defaults to 720h (at most 365d). Revoke with 'tokens revoke <id>': the link is closed
(4010) at every level and cannot come back with it.

Examples:
  secagent-server tokens create --role enrollment --hostname-pattern "vp.*" --reusable --expires 30d
  secagent-server tokens create --role plugin --description "Terraform" --allowed-ips "10.0.0.0/8" --expires 24h
  secagent-server tokens create --role relay-child --sub relay-b --aud relay-a
  secagent-server tokens create --role relay-parent --sub relay-a --aud relay-b --expires 90d`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if createRole != "enrollment" && createRole != "plugin" && !isLinkRole(createRole) {
			return fmt.Errorf("--role must be 'enrollment', 'plugin', 'relay-child' or 'relay-parent'")
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

		case "relay-child", "relay-parent":
			if !relayIDRe.MatchString(strings.TrimSpace(createSub)) {
				return fmt.Errorf("--sub (relay_id of the presenter) is required for link tokens and must match %s", relayIDRe)
			}
			if !relayIDRe.MatchString(strings.TrimSpace(createAud)) {
				return fmt.Errorf("--aud (relay_id of the verifier) is required for link tokens and must match %s", relayIDRe)
			}
			if strings.TrimSpace(createSub) == strings.TrimSpace(createAud) {
				return fmt.Errorf("--sub and --aud must differ")
			}
			body["sub"] = strings.TrimSpace(createSub)
			body["aud"] = strings.TrimSpace(createAud)
			body["description"] = createDescription
		}

		// Parse expiry
		if createExpires != "" && createExpires != "never" {
			exp, err := parseDuration(createExpires)
			if err != nil {
				return fmt.Errorf("invalid --expires value %q: %w", createExpires, err)
			}
			if isLinkRole(createRole) && time.Until(exp) > maxLinkLifetime {
				return fmt.Errorf("--expires %q exceeds the 365d maximum for link tokens", createExpires)
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

		return printOutput(globalFormat, resp, func(v interface{}) error {
			r := v.(map[string]interface{})
			_, _ = fmt.Println("Token created successfully.")
			_, _ = fmt.Println()
			_, _ = fmt.Printf("  Token (save now — shown only once): %s\n", r["token"])
			_, _ = fmt.Printf("  ID:         %s\n", r["id"])
			_, _ = fmt.Printf("  Role:       %s\n", r["role"])
			if sub, ok := r["sub"].(string); ok && sub != "" {
				_, _ = fmt.Printf("  Presenter (sub): %s\n", sub)
			}
			if aud, ok := r["aud"].(string); ok && aud != "" {
				_, _ = fmt.Printf("  Verifier (aud):  %s\n", aud)
			}
			if p, ok := r["hostname_pattern"].(string); ok && p != "" {
				_, _ = fmt.Printf("  Pattern:    %s\n", p)
			}
			if d, ok := r["description"].(string); ok && d != "" {
				_, _ = fmt.Printf("  Desc:       %s\n", d)
			}
			if ips, ok := r["allowed_ips"].(string); ok && ips != "" {
				_, _ = fmt.Printf("  Allowed IPs: %s\n", ips)
			}
			if hp, ok := r["allowed_hostname_pattern"].(string); ok && hp != "" {
				_, _ = fmt.Printf("  Hostname pattern: %s\n", hp)
			}
			if exp, ok := r["expires_at"].(string); ok && exp != "" {
				_, _ = fmt.Printf("  Expires:    %s\n", exp)
			} else {
				_, _ = fmt.Printf("  Expires:    never\n")
			}
			_, _ = fmt.Printf("  Created:    %s\n", r["created_at"])
			return nil
		})
	},
}

func init() {
	tokensCreateCmd.Flags().StringVar(&createRole, "role", "", "Token role: enrollment, plugin, relay-child or relay-parent (required)")
	tokensCreateCmd.Flags().StringVar(&createHostnamePattern, "hostname-pattern", "", "Regexp for hostname (enrollment tokens)")
	tokensCreateCmd.Flags().BoolVar(&createReusable, "reusable", false, "Allow multiple uses (enrollment tokens; default: one-shot)")
	tokensCreateCmd.Flags().StringVar(&createExpires, "expires", "never", "Expiry: 30d, 24h, 90m, never (default: never; link tokens: 720h by default when omitted, max 365d)")
	tokensCreateCmd.Flags().StringVar(&createDescription, "description", "", "Human-readable description (plugin tokens)")
	tokensCreateCmd.Flags().StringVar(&createAllowedIPs, "allowed-ips", "", "Comma-separated CIDRs (plugin tokens): \"10.0.0.0/8,192.168.1.0/24\"")
	tokensCreateCmd.Flags().StringVar(&createAllowedHostname, "allowed-hostname-pattern", "", "Regexp for caller hostname (plugin tokens)")
	tokensCreateCmd.Flags().StringVar(&createSub, "sub", "", "relay_id of the presenter of the link token (relay-child / relay-parent, required)")
	tokensCreateCmd.Flags().StringVar(&createAud, "aud", "", "relay_id of the verifier of the link token (relay-child / relay-parent, required)")
	if err := tokensCreateCmd.MarkFlagRequired("role"); err != nil {
		// MarkFlagRequired only fails when the flag name is invalid (programmer error).
		// Log the error and exit cleanly — no panic in production.
		slog.Error("tokens create: MarkFlagRequired failed", "flag", "role", "err", err)
		os.Exit(1)
	}
}

// ── tokens list ───────────────────────────────────────────────────────────────

var listRole string

var tokensListCmd = &cobra.Command{
	Use:   "list",
	Short: "List tokens (hash only — no plain text)",
	RunE: func(cmd *cobra.Command, args []string) error {
		path := "/api/admin/tokens"
		if listRole != "" {
			if listRole != "enrollment" && listRole != "plugin" && !isLinkRole(listRole) && listRole != "all" {
				return fmt.Errorf("--role must be enrollment, plugin, relay-child, relay-parent, or all")
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

		return printOutput(globalFormat, tokens, func(v interface{}) error {
			list, _ := v.([]map[string]interface{})
			if len(list) == 0 {
				_, _ = fmt.Println("No tokens found.")
				return nil
			}

			tp := newTabPrinter()
			tp.println("ID\tROLE\tHASH (truncated)\tPATTERN/DESC\tEXPIRES\tUSED\tREVOKED")
			for _, t := range list {
				hash := "-"
				if h, ok := t["token_hash"].(string); ok {
					hash = h
				}
				if len(hash) > 16 {
					hash = hash[:16] + "..."
				}
				role := fmt.Sprintf("%v", t["role"])
				label := ""
				if v, ok := t["hostname_pattern"].(string); ok && v != "" {
					label = v
				} else if v, ok := t["sub"].(string); ok && v != "" {
					label = v + " -> " + fmt.Sprint(t["aud"]) // link tokens: presenter -> verifier
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
				tp.printf("%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
					t["id"], role, hash, label, expires, useCount, revoked)
			}
			return tp.flush()
		})
	},
}

func init() {
	tokensListCmd.Flags().StringVar(&listRole, "role", "", "Filter by role: enrollment, plugin, relay-child, relay-parent (default: all)")
}

// ── tokens revoke ─────────────────────────────────────────────────────────────

var tokensRevokeCmd = &cobra.Command{
	Use:   "revoke <id>",
	Short: "Revoke a plugin or link token (link token: JTI blacklisted, links closed 4010, revocation pushed down the tree)",
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

		return printOutput(globalFormat, resp, func(v interface{}) error {
			r := v.(map[string]interface{})
			_, _ = fmt.Printf("Purged %v token(s) at %s\n", r["deleted_count"], r["purged_at"])
			return nil
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
