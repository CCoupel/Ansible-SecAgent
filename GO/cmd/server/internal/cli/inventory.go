package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// inventoryCmd is the top-level "inventory" subcommand.
var inventoryCmd = &cobra.Command{
	Use:   "inventory",
	Short: "Manage Ansible dynamic inventory",
}

var inventoryOnlyConnected bool

func init() {
	inventoryCmd.AddCommand(inventoryListCmd)
}

var inventoryListCmd = &cobra.Command{
	Use:   "list",
	Short: "List inventory (Ansible-compatible JSON)",
	RunE: func(cmd *cobra.Command, args []string) error {
		path := "/api/inventory"
		if inventoryOnlyConnected {
			path += "?only_connected=true"
		}

		// Inventory uses port 7770 (public API), not 7771 (admin)
		// Override by calling apiURL base but with /api/inventory
		data, status, err := apiRequest("GET", path, nil)
		if err != nil {
			return err
		}
		if code := checkError(data, status); code != 0 {
			os.Exit(code)
		}

		var inv map[string]interface{}
		if err := json.Unmarshal(data, &inv); err != nil {
			return fmt.Errorf("parse response: %w", err)
		}

		return printOutput(globalFormat, inv, func(v interface{}) {
			inv := v.(map[string]interface{})
			tw := newTabWriter()
			// Print hostvars summary
			if meta, ok := inv["_meta"].(map[string]interface{}); ok {
				if hostvars, ok := meta["hostvars"].(map[string]interface{}); ok {
					fmt.Fprintln(tw, "HOSTNAME\tVARS")
					for host, vars := range hostvars {
						varsJSON, _ := json.Marshal(vars)
						fmt.Fprintf(tw, "%s\t%s\n", host, string(varsJSON))
					}
				}
			}
			tw.Flush()
		})
	},
}

func init() {
	inventoryListCmd.Flags().BoolVar(&inventoryOnlyConnected, "only-connected", false, "Show only connected agents")
}
