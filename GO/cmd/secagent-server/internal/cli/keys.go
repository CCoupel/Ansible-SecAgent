package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// keysCmd groups the link signing key operations of the ROOT relay (v3.0.4, #141).
var keysCmd = &cobra.Command{
	Use:   "keys",
	Short: "Link signing key of the root relay (public key export, rotation)",
	Long: `Operations on the Ed25519 key with which the ROOT relay signs the link tokens
(relay-child / relay-parent). All commands answer 409 not_root on a relay that has a parent and 503
master_key_required without RSA_MASTER_KEY. The private key is never printed or exported.`,
}

func init() {
	keysCmd.AddCommand(keysLinkPubkeyCmd, keysRotateLinkCmd, keysRetireLinkPreviousCmd, keysLinkStatusCmd)
	rootCmd.AddCommand(keysCmd)
}

func keysCall(method, path string, body interface{}) (map[string]interface{}, error) {
	data, status, err := apiRequest(method, path, body)
	if err != nil {
		return nil, err
	}
	if code := checkError(data, status); code != 0 {
		os.Exit(code)
	}
	var out map[string]interface{}
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}
	return out, nil
}

var keysLinkPubkeyCmd = &cobra.Command{
	Use:   "link-pubkey",
	Short: "Print the root PUBLIC link key (PEM) to pin on the children (REPEATER_ROOT_LINK_KEY_FILE)",
	Long: `Prints the public key of the root, as a PEM "PUBLIC KEY" block on stdout (redirect it to the
file pinned on the children). The root relay_id (REPEATER_ROOT_ID on the children) and the kid go to
stderr. Generates the key if it does not exist yet. Only the PUBLIC key is ever exported.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		r, err := keysCall("GET", "/api/admin/link/pubkey", nil)
		if err != nil {
			return err
		}
		pem, _ := r["current_pub_pem"].(string)
		if pem == "" {
			return fmt.Errorf("the server returned no public key")
		}
		_, _ = fmt.Fprintf(os.Stderr, "root_id=%v kid=%v\n", r["root_id"], r["current_kid"])
		_, _ = fmt.Print(pem)
		return nil
	},
}

var keysRotateLinkCmd = &cobra.Command{
	Use:   "rotate-link",
	Short: "Rotate the root link key (current becomes previous; link_keys is pushed to the children)",
	RunE: func(cmd *cobra.Command, args []string) error {
		r, err := keysCall("POST", "/api/admin/link/keys/rotate", map[string]string{})
		if err != nil {
			return err
		}
		return printOutput(globalFormat, r, func(interface{}) error {
			_, _ = fmt.Printf("Link key rotated: current=%v previous=%v seq=%v\n", r["current_kid"], r["previous_kid"], r["seq"])
			_, _ = fmt.Println("Check 'keys link-status' until every relay is confirmed, then 'keys retire-link-previous'.")
			return nil
		})
	},
}

var keysRetireForce bool

var keysRetireLinkPreviousCmd = &cobra.Command{
	Use:   "retire-link-previous",
	Short: "Close the double-acceptation window (refused while relays have not confirmed the rotation)",
	Long: `Removes the previous key: tokens signed with it are refused afterwards. Refused with
409 rotation_unconfirmed (and the list of relays) while relays below have not confirmed the rotation
(see 'keys link-status'): a relay that missed it can no longer verify the chain and is cut until
its trust anchor is re-pinned. --force overrides, with a [SECURITY WARNING] in the server log.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		r, err := keysCall("POST", "/api/admin/link/keys/retire-previous", map[string]bool{"force": keysRetireForce})
		if err != nil {
			return err
		}
		return printOutput(globalFormat, r, func(interface{}) error {
			_, _ = fmt.Printf("Previous link key retired (seq=%v)\n", r["seq"])
			if u, ok := r["unconfirmed"].([]interface{}); ok && len(u) > 0 {
				_, _ = fmt.Printf("WARNING: forced while not confirmed by: %v\n", u)
			}
			return nil
		})
	},
}

var keysLinkStatusCmd = &cobra.Command{
	Use:   "link-status",
	Short: "Link key state and rotation confirmation per relay",
	RunE: func(cmd *cobra.Command, args []string) error {
		r, err := keysCall("GET", "/api/admin/link/status", nil)
		if err != nil {
			return err
		}
		return printOutput(globalFormat, r, func(interface{}) error {
			_, _ = fmt.Printf("root_id=%v seq=%v current=%v previous=%v\n", r["root_id"], r["seq"], r["current_kid"], r["previous_kid"])
			rel, _ := r["relays"].([]interface{})
			tp := newTabPrinter()
			tp.println("RELAY\tLINK_SEQ\tKID\tCONFIRMED")
			for _, x := range rel {
				m, _ := x.(map[string]interface{})
				tp.printf("%v\t%v\t%v\t%v\n", m["relay_id"], m["link_seq"], m["link_kid"], m["confirmed"])
			}
			return tp.flush()
		})
	},
}

func init() {
	keysRetireLinkPreviousCmd.Flags().BoolVar(&keysRetireForce, "force", false, "Retire even if relays have not confirmed the rotation ([SECURITY WARNING])")
}
