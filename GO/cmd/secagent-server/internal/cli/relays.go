// Phase 12 — relays.go
// CLI subcommand "relays" — manage relay nodes registered on a proxy.
//
//	secagent-server relays list   [--format table|json|yaml]
//	secagent-server relays add    --id <relay_id> --url <url> --token <token> [--mode push|pull] [--description <desc>]
//	secagent-server relays remove <relay_id_or_uuid>
//	secagent-server relays status [--format table|json|yaml]
package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

// relaysCmd is the top-level "relays" subcommand.
var relaysCmd = &cobra.Command{
	Use:   "relays",
	Short: "Manage relay nodes registered on a proxy",
}

func init() {
	relaysCmd.AddCommand(
		relaysListCmd,
		relaysAddCmd,
		relaysRemoveCmd,
		relaysStatusCmd,
	)
}

// ── relays list ───────────────────────────────────────────────────────────────

var relaysListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all registered relay nodes",
	RunE: func(cmd *cobra.Command, args []string) error {
		data, status, err := apiRequest("GET", "/api/admin/relays", nil)
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

		relays, _ := result["relays"].([]interface{})

		return printOutput(globalFormat, relays, func(v interface{}) error {
			list, _ := v.([]interface{})
			tp := newTabPrinter()
			tp.println("RELAY_ID\tMODE\tIS_PROXY\tSTATUS\tLAST_SEEN\tDESCRIPTION")
			for _, item := range list {
				m, _ := item.(map[string]interface{})
				relayID, _ := m["relay_id"].(string)
				mode, _ := m["mode"].(string)
				isProxy, _ := m["is_proxy"].(bool)
				status, _ := m["status"].(string)
				lastSeen, _ := m["last_seen"].(string)
				description, _ := m["description"].(string)
				isProxyStr := "no"
				if isProxy {
					isProxyStr = "yes"
				}
				if lastSeen == "" {
					lastSeen = "-"
				}
				tp.printf("%s\t%s\t%s\t%s\t%s\t%s\n",
					relayID, mode, isProxyStr, status, lastSeen, description)
			}
			return tp.flush()
		})
	},
}

// ── relays add ────────────────────────────────────────────────────────────────

var (
	addRelayID          string
	addRelayMode        string
	addRelayURL         string
	addRelayToken       string
	addRelayDescription string
)

var relaysAddCmd = &cobra.Command{
	Use:   "add",
	Short: "Register a new relay node",
	Long: `Register a new relay node on the proxy.

Examples:
  # Pull mode: relay connects to this proxy (JWT token returned)
  secagent-server relays add --id dmz1 --description "Zone DMZ1"

  # Push mode: proxy initiates connections to the relay
  secagent-server relays add --id dmz2 --mode push --url https://dmz2:7770 --token "secagent_relay_..." --description "Zone DMZ2"`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if strings.TrimSpace(addRelayID) == "" {
			return fmt.Errorf("--id is required")
		}
		if addRelayMode != "" && addRelayMode != "pull" && addRelayMode != "push" {
			return fmt.Errorf("--mode must be 'pull' or 'push'")
		}

		body := map[string]interface{}{
			"relay_id": addRelayID,
		}
		if addRelayMode != "" {
			body["mode"] = addRelayMode
		}
		if addRelayURL != "" {
			body["url"] = addRelayURL
		}
		if addRelayToken != "" {
			body["token"] = addRelayToken
		}
		if addRelayDescription != "" {
			body["description"] = addRelayDescription
		}

		data, status, err := apiRequest("POST", "/api/admin/relays", body)
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
			m := v.(map[string]interface{})
			tp := newTabPrinter()
			tp.println("FIELD\tVALUE")
			tp.printf("id\t%v\n", m["id"])
			tp.printf("relay_id\t%v\n", m["relay_id"])
			tp.printf("mode\t%v\n", m["mode"])
			tp.printf("status\t%v\n", m["status"])
			tp.printf("created_at\t%v\n", m["created_at"])
			if desc, ok := m["description"].(string); ok && desc != "" {
				tp.printf("description\t%v\n", desc)
			}
			if url, ok := m["url"].(string); ok && url != "" {
				tp.printf("url\t%v\n", url)
			}
			// Pull mode: show JWT token (one-time)
			if jwt, ok := m["jwt_token"].(string); ok && jwt != "" {
				if err := tp.flush(); err != nil {
					return err
				}
				_, _ = fmt.Println()
				_, _ = fmt.Println("JWT Token (shown once — store it securely on the relay):")
				_, _ = fmt.Println(jwt)
				return nil
			}
			return tp.flush()
		})
	},
}

func init() {
	relaysAddCmd.Flags().StringVar(&addRelayID, "id", "", "Relay unique ID (required)")
	relaysAddCmd.Flags().StringVar(&addRelayMode, "mode", "pull", "Connection mode: pull (relay→proxy) or push (proxy→relay)")
	relaysAddCmd.Flags().StringVar(&addRelayURL, "url", "", "Relay base URL (push mode only)")
	relaysAddCmd.Flags().StringVar(&addRelayToken, "token", "", "Bearer token to authenticate to the relay (push mode only)")
	relaysAddCmd.Flags().StringVar(&addRelayDescription, "description", "", "Human-readable description")
}

// ── relays remove ─────────────────────────────────────────────────────────────

var relaysRemoveCmd = &cobra.Command{
	Use:   "remove <id>",
	Short: "Remove a registered relay node by its UUID",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		id := strings.TrimSpace(args[0])
		if id == "" {
			return fmt.Errorf("relay id is required")
		}

		data, status, err := apiRequest("DELETE", "/api/admin/relays/"+id, nil)
		if err != nil {
			return err
		}

		// 204 No Content — success
		if status == 204 {
			fmt.Printf("Relay %s removed.\n", id)
			return nil
		}

		if code := checkError(data, status); code != 0 {
			os.Exit(code)
		}
		return nil
	},
}

// ── relays status ─────────────────────────────────────────────────────────────

var relaysStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show real-time connectivity status of all relay nodes",
	RunE: func(cmd *cobra.Command, args []string) error {
		data, status, err := apiRequest("GET", "/api/admin/relays/status", nil)
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

		relays, _ := result["relays"].([]interface{})
		timestamp, _ := result["timestamp"].(string)

		return printOutput(globalFormat, result, func(v interface{}) error {
			tp := newTabPrinter()
			tp.printf("Timestamp: %s\n\n", timestamp)
			tp.println("RELAY_ID\tMODE\tSTATUS\tLAST_SEEN")
			for _, item := range relays {
				m, _ := item.(map[string]interface{})
				relayID, _ := m["relay_id"].(string)
				mode, _ := m["mode"].(string)
				relayStatus, _ := m["status"].(string)
				lastSeen, _ := m["last_seen"].(string)
				if lastSeen == "" {
					lastSeen = "-"
				}
				tp.printf("%s\t%s\t%s\t%s\n", relayID, mode, relayStatus, lastSeen)
			}
			return tp.flush()
		})
	},
}
