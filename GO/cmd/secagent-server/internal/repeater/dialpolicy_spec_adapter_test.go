package repeater

// #151 (L7) — SPECIFICATION of the configurable dial policy (plan rev2 §5): REPEATER_DIAL_ALLOW_LOOPBACK,
// REPEATER_DIAL_DENY_CIDRS, REPEATER_DIAL_ALLOW_CIDRS on top of the built-in guard of #151a.
//
// The tests (dialpolicy_spec_*_test.go) never call the implementation directly: they go through the
// specDialPolicy below, wired by ONE file the dev owns (dev-agent, L7 #151):
//
//	// dialpolicy_spec_wire_test.go
//	func init() { specDialPolicyUnderTest = &specDialPolicy{ ... } }
//
// While it is nil every test that needs the policy is SKIPPED as "PENDING #151". The oracle tests run
// today (they prove the table of cases is right and kills the mutants "deny ignored", "allow ignored",
// "ALLOW lifts a built-in prohibition").
//
// Decision rule (rev2 §5), for EVERY resolved IP and for the IP actually dialed, in this order:
//  1. built-in prohibition, NOT liftable (link-local, metadata 169.254.169.254 / fd00:ec2::254 /
//     100.100.100.200 / 192.0.0.192 / 168.63.129.16, unspecified, multicast, broadcast) → "builtin"
//  2. loopback, unless ALLOW_LOOPBACK=true → "loopback"
//  3. IP in DENY → "deny"
//  4. ALLOW non empty and IP not in ALLOW → "not_allowed"
//  5. otherwise allowed ("")
//
// deny-wins, a single rule: with ALLOW non empty AND ALLOW_LOOPBACK=true, loopback must ALSO be in ALLOW.
// An IPv4-mapped IPv6 address is judged as the IPv4 address. Any configuration error = refuse to start.

import "net"

type specDialPolicy struct {
	// Configure parses and applies the three settings to the guard used by guardedDial and
	// ParseTargetURLs (what REPEATER_DIAL_* set at startup). deny / allow are the raw
	// comma-separated values of the variables. A non nil error = the process would refuse to start.
	// restore puts the previous policy back (the test also calls withGuard).
	Configure func(allowLoopback bool, deny, allow string) (restore func(), err error)

	// Category returns why ip is refused under the CURRENT configuration:
	// "builtin" | "loopback" | "deny" | "not_allowed", or "" when it is allowed.
	Category func(ip net.IP) string

	// FromEnv loads the settings from environment variables (name → value), as the server does at
	// startup, and returns an error when the process must refuse to start. Used for the strictness
	// of the boolean only (values other than "true"/"false" are refused).
	FromEnv func(env map[string]string) error
}

// specDialPolicyUnderTest is set by dialpolicy_spec_wire_test.go. nil = pending #151.
var specDialPolicyUnderTest *specDialPolicy
