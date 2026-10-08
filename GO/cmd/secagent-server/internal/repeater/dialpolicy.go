package repeater

// Configurable dial policy of the outgoing relay links (#151, plan rev2 §5), on top of the built-in
// SSRF guard of #151a (dialtarget.go, dialguard.go). Three settings, read ONCE at startup:
//
//	REPEATER_DIAL_ALLOW_LOOPBACK  strict boolean (true|false, default false): lifts loopback ONLY
//	REPEATER_DIAL_DENY_CIDRS      comma separated CIDRs: additional refusals
//	REPEATER_DIAL_ALLOW_CIDRS     comma separated CIDRs: when non empty, an allow list
//
// Decision for EVERY resolved IP and for the IP actually dialed, in this order (deny wins):
//  1. built-in prohibition, never liftable (link-local, cloud metadata, unspecified, multicast,
//     broadcast, 0.0.0.0/8, IPv6 transition addresses embedding one of those)      → "builtin"
//  2. loopback, unless REPEATER_DIAL_ALLOW_LOOPBACK=true                            → "loopback"
//  3. address in DENY                                                               → "deny"
//  4. ALLOW non empty and address not in ALLOW                                      → "not_allowed"
//  5. otherwise allowed. RFC 1918 and CGNAT stay allowed by default.
//
// An IPv4-mapped IPv6 address is judged as the IPv4 address. Any configuration error (bad CIDR,
// "/0", host bits set, empty/duplicate entry, whitespace, more than 256 entries, non strict boolean)
// refuses to start. Errors and logs never carry an address of a target nor a token.

import (
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"sync/atomic"
)

// Environment variables of the dial policy.
const (
	EnvDialAllowLoopback = "REPEATER_DIAL_ALLOW_LOOPBACK"
	EnvDialDenyCIDRs     = "REPEATER_DIAL_DENY_CIDRS"
	EnvDialAllowCIDRs    = "REPEATER_DIAL_ALLOW_CIDRS"

	maxDialPolicyEntries = 256
)

// Categories of a refusal (also the "category=" shown in the logs).
const (
	CategoryBuiltin    = "builtin"
	CategoryLoopback   = "loopback"
	CategoryDeny       = "deny"
	CategoryNotAllowed = "not_allowed"
)

// DialPolicy is an immutable, validated policy.
type DialPolicy struct {
	allowLoopback bool
	deny, allow   []*net.IPNet
}

// ErrDialPolicy wraps every configuration error of the dial policy (the process must not start).
var ErrDialPolicy = errors.New("invalid dial policy configuration")

// ParseDialPolicy validates the three settings (raw values of the variables).
func ParseDialPolicy(allowLoopback bool, deny, allow string) (*DialPolicy, error) {
	d, err := parseCIDRList(deny)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrDialPolicy, EnvDialDenyCIDRs, err)
	}
	a, err := parseCIDRList(allow)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrDialPolicy, EnvDialAllowCIDRs, err)
	}
	return &DialPolicy{allowLoopback: allowLoopback, deny: d, allow: a}, nil
}

// parseCIDRList never echoes the offending entry (it is operator input, but keep logs free of it).
func parseCIDRList(s string) ([]*net.IPNet, error) {
	if s == "" {
		return nil, nil
	}
	var out []*net.IPNet
	seen := map[string]bool{}
	for i, e := range strings.Split(s, ",") {
		n := i + 1
		if e == "" || strings.ContainsAny(e, " \t\r\n") {
			return nil, fmt.Errorf("entry %d is empty or contains whitespace", n)
		}
		ip, ipnet, err := net.ParseCIDR(e)
		if err != nil {
			return nil, fmt.Errorf("entry %d is not a valid CIDR", n)
		}
		if ones, _ := ipnet.Mask.Size(); ones == 0 {
			return nil, fmt.Errorf("entry %d: a /0 prefix is forbidden", n)
		}
		if !ip.Equal(ipnet.IP) {
			return nil, fmt.Errorf("entry %d is not canonical (host bits set)", n)
		}
		key := ipnet.String()
		if seen[key] {
			return nil, fmt.Errorf("entry %d is a duplicate", n)
		}
		seen[key] = true
		out = append(out, ipnet)
		if len(out) > maxDialPolicyEntries {
			return nil, fmt.Errorf("more than %d entries", maxDialPolicyEntries)
		}
	}
	return out, nil
}

func inNets(l []*net.IPNet, ip net.IP) bool {
	for _, n := range l {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// Category returns why ip is refused ("" when it is allowed). It reports the category only.
func (p *DialPolicy) Category(ip net.IP) string {
	c, _ := p.refusal(ip)
	return c
}

// refusal returns the category and the human reason (no address) of a refusal, "" "" when allowed.
func (p *DialPolicy) refusal(ip net.IP) (category, why string) {
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	if w := internalReason(ip); w != "" && !strings.HasPrefix(w, "loopback") {
		return CategoryBuiltin, w
	}
	if ip.Equal(net.IPv4bcast) {
		return CategoryBuiltin, "broadcast"
	}
	if w := internalReason(ip); strings.HasPrefix(w, "loopback") && !p.allowLoopback {
		return CategoryLoopback, "loopback (set " + EnvDialAllowLoopback + "=true to allow it)"
	}
	if inNets(p.deny, ip) {
		return CategoryDeny, "denied by " + EnvDialDenyCIDRs
	}
	if len(p.allow) > 0 && !inNets(p.allow, ip) {
		return CategoryNotAllowed, "not in " + EnvDialAllowCIDRs
	}
	return "", ""
}

// AllowsLoopback reports whether loopback is lifted (name "localhost" is then resolved, not refused).
func (p *DialPolicy) AllowsLoopback() bool { return p.allowLoopback }

var activePolicy atomic.Pointer[DialPolicy]

func init() { activePolicy.Store(&DialPolicy{}) }

// SetDialPolicy installs the policy used by the dialers and by the registration checks, and returns
// the function that puts the previous one back.
func SetDialPolicy(p *DialPolicy) (restore func()) {
	prev := activePolicy.Swap(p)
	return func() { activePolicy.Store(prev) }
}

func currentPolicy() *DialPolicy { return activePolicy.Load() }

// DialPolicyFromEnv reads the three variables. REPEATER_DIAL_ALLOW_LOOPBACK is a strict boolean.
func DialPolicyFromEnv(getenv func(string) string) (*DialPolicy, error) {
	loop := false
	switch v := getenv(EnvDialAllowLoopback); v {
	case "", "false":
	case "true":
		loop = true
	default:
		return nil, fmt.Errorf("%w: %s must be \"true\" or \"false\"", ErrDialPolicy, EnvDialAllowLoopback)
	}
	return ParseDialPolicy(loop, getenv(EnvDialDenyCIDRs), getenv(EnvDialAllowCIDRs))
}

// ConfigureDialPolicyFromEnv validates and installs the policy at startup. A configuration error is
// returned (the server refuses to start). It logs the policy summary, and a [SECURITY WARNING]
// when loopback is lifted.
func ConfigureDialPolicyFromEnv(getenv func(string) string) error {
	p, err := DialPolicyFromEnv(getenv)
	if err != nil {
		return err
	}
	SetDialPolicy(p)
	if p.allowLoopback {
		log.Printf("[SECURITY WARNING] %s=true: relay links may be dialed on loopback addresses (development and CI only)", EnvDialAllowLoopback)
	}
	if len(p.deny) > 0 || len(p.allow) > 0 {
		log.Printf("[RELAY] dial policy: %d deny entr(ies), %d allow entr(ies)", len(p.deny), len(p.allow))
	}
	return nil
}
