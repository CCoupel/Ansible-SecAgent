package repeater

// #151 (L7) — oracle of the dial policy, its mutants, and the table of cases (see the adapter).

import (
	"fmt"
	"net"
	"strings"
	"testing"
)

type specPolicyMutant string

const (
	specPolNone            specPolicyMutant = ""
	specPolDenyIgnored     specPolicyMutant = "deny-ignored"
	specPolAllowIgnored    specPolicyMutant = "allow-ignored"
	specPolAllowLiftsBuilt specPolicyMutant = "allow-lifts-builtin"
)

// specOraclePolicy is the reference implementation of the rule.
func specOraclePolicy(m specPolicyMutant) *specDialPolicy {
	var (
		loop        bool
		deny, allow []*net.IPNet
	)
	parse := func(list string) ([]*net.IPNet, error) {
		if list == "" {
			return nil, nil
		}
		var out []*net.IPNet
		seen := map[string]bool{}
		for _, e := range strings.Split(list, ",") {
			if e == "" || strings.ContainsAny(e, " \t\r\n") {
				return nil, fmt.Errorf("empty entry or whitespace")
			}
			ip, n, err := net.ParseCIDR(e)
			if err != nil {
				return nil, err
			}
			if ones, _ := n.Mask.Size(); ones == 0 {
				return nil, fmt.Errorf("/0 is forbidden")
			}
			if !ip.Equal(n.IP) {
				return nil, fmt.Errorf("host bits set: not canonical")
			}
			if seen[n.String()] {
				return nil, fmt.Errorf("duplicate")
			}
			seen[n.String()] = true
			out = append(out, n)
		}
		if len(out) > 256 {
			return nil, fmt.Errorf("more than 256 entries")
		}
		return out, nil
	}
	in := func(l []*net.IPNet, ip net.IP) bool {
		for _, n := range l {
			if n.Contains(ip) {
				return true
			}
		}
		return false
	}
	impl := &specDialPolicy{}
	impl.Configure = func(allowLoopback bool, d, a string) (func(), error) {
		dn, err := parse(d)
		if err != nil {
			return nil, err
		}
		an, err := parse(a)
		if err != nil {
			return nil, err
		}
		loop, deny, allow = allowLoopback, dn, an
		return func() {}, nil
	}
	impl.Category = func(ip net.IP) string {
		if v4 := ip.To4(); v4 != nil {
			ip = v4 // IPv4-mapped IPv6 is judged as the IPv4 address
		}
		if why := internalReason(ip); why != "" && why != "loopback" { // the built-in guard of #151a
			if !(m == specPolAllowLiftsBuilt && len(allow) > 0 && in(allow, ip)) {
				return "builtin"
			}
		}
		if ip.Equal(net.IPv4bcast) {
			return "builtin"
		}
		if ip.IsLoopback() && !loop {
			return "loopback"
		}
		if m != specPolDenyIgnored && in(deny, ip) {
			return "deny"
		}
		if m != specPolAllowIgnored && len(allow) > 0 && !in(allow, ip) {
			return "not_allowed"
		}
		return ""
	}
	return impl
}

type specPolicyCase struct {
	Name         string
	Loop         bool
	Deny, Allow  string
	IP           string
	Want         string
	AcceptConfig bool // a configuration error is an acceptable (fail closed) answer for this case
}

// specPolicyCases: the matrix category × lists of the plan (deny, allow, loopback, built-in not liftable).
var specPolicyCases = []specPolicyCase{
	// defaults: nothing configured
	{"default_builtin_metadata_v4", false, "", "", "169.254.169.254", "builtin", false},
	{"default_builtin_metadata_aws_v6", false, "", "", "fd00:ec2::254", "builtin", false},
	{"default_builtin_alibaba", false, "", "", "100.100.100.200", "builtin", false},
	{"default_builtin_oracle", false, "", "", "192.0.0.192", "builtin", false},
	{"default_builtin_azure", false, "", "", "168.63.129.16", "builtin", false},
	{"default_builtin_link_local", false, "", "", "169.254.1.1", "builtin", false},
	{"default_builtin_unspecified", false, "", "", "0.0.0.0", "builtin", false},
	{"default_builtin_unspecified_v6", false, "", "", "::", "builtin", false},
	{"default_builtin_multicast", false, "", "", "224.0.0.1", "builtin", false},
	{"default_builtin_multicast_v6", false, "", "", "ff02::1", "builtin", false},
	{"default_builtin_broadcast", false, "", "", "255.255.255.255", "builtin", false},
	{"default_loopback_v4", false, "", "", "127.0.0.1", "loopback", false},
	{"default_loopback_v4_other", false, "", "", "127.5.5.5", "loopback", false},
	{"default_loopback_v6", false, "", "", "::1", "loopback", false},
	{"default_loopback_mapped", false, "", "", "::ffff:127.0.0.1", "loopback", false},
	{"default_builtin_mapped", false, "", "", "::ffff:169.254.169.254", "builtin", false},
	{"default_rfc1918_10", false, "", "", "10.1.2.3", "", false},
	{"default_rfc1918_192", false, "", "", "192.168.1.5", "", false},
	{"default_rfc1918_172", false, "", "", "172.16.0.1", "", false},
	{"default_cgnat_allowed", false, "", "", "100.64.0.1", "", false},
	{"default_public_v4", false, "", "", "8.8.8.8", "", false},
	{"default_public_v6", false, "", "", "2001:4860:4860::8888", "", false},
	// ALLOW_LOOPBACK lifts ONLY loopback
	{"allow_loopback_lifts_loopback_v4", true, "", "", "127.0.0.1", "", false},
	{"allow_loopback_lifts_loopback_v6", true, "", "", "::1", "", false},
	{"allow_loopback_lifts_loopback_mapped", true, "", "", "::ffff:127.0.0.1", "", false},
	{"allow_loopback_never_lifts_metadata", true, "", "", "169.254.169.254", "builtin", false},
	{"allow_loopback_never_lifts_link_local", true, "", "", "169.254.1.1", "builtin", false},
	{"allow_loopback_never_lifts_unspecified", true, "", "", "0.0.0.0", "builtin", false},
	// DENY
	{"deny_refuses_inside", false, "10.0.0.0/8", "", "10.1.2.3", "deny", false},
	{"deny_lets_outside_pass", false, "10.0.0.0/8", "", "192.168.1.5", "", false},
	{"deny_v6", false, "fd00::/8", "", "fd12::1", "deny", false},
	{"deny_host_route", false, "10.1.2.3/32", "", "10.1.2.3", "deny", false},
	{"deny_host_route_neighbour_passes", false, "10.1.2.3/32", "", "10.1.2.4", "", false},
	{"deny_mapped_is_judged_as_v4", false, "10.0.0.0/8", "", "::ffff:10.1.2.3", "deny", false},
	{"deny_applies_to_loopback_even_when_allowed", true, "127.0.0.0/8", "", "127.0.0.1", "deny", false},
	// ALLOW
	{"allow_lets_inside_pass", false, "", "192.168.0.0/16", "192.168.1.5", "", false},
	{"allow_refuses_outside_private", false, "", "192.168.0.0/16", "10.1.2.3", "not_allowed", false},
	{"allow_refuses_outside_public", false, "", "192.168.0.0/16", "8.8.8.8", "not_allowed", false},
	{"allow_refuses_outside_v6", false, "", "2001:db8::/32", "2001:4860:4860::8888", "not_allowed", false},
	{"allow_inside_v6", false, "", "2001:db8::/32", "2001:db8::1", "", false},
	{"allow_mapped_is_judged_as_v4", false, "", "192.168.0.0/16", "::ffff:192.168.1.1", "", false},
	// ALLOW can never lift a built-in prohibition (a configuration error is also acceptable: fail closed)
	{"allow_cannot_lift_metadata", false, "", "169.254.0.0/16", "169.254.169.254", "builtin", true},
	{"allow_cannot_lift_alibaba", false, "", "100.64.0.0/10", "100.100.100.200", "builtin", false},
	{"allow_cannot_lift_aws_v6", false, "", "fc00::/7", "fd00:ec2::254", "builtin", false},
	{"allow_cannot_lift_azure", false, "", "168.63.129.0/24", "168.63.129.16", "builtin", false},
	{"allow_cannot_lift_multicast", false, "", "224.0.0.0/4", "224.0.0.1", "builtin", true},
	{"allow_cannot_lift_unspecified", false, "", "0.0.0.0/8", "0.0.0.0", "builtin", true},
	// loopback needs ALLOW_LOOPBACK even when ALLOW names it; and ALLOW names must include it when set
	{"allow_naming_loopback_does_not_lift_it", false, "", "127.0.0.0/8", "127.0.0.1", "loopback", false},
	{"allow_loopback_with_allow_list_requires_loopback_in_the_list", true, "", "192.168.0.0/16", "127.0.0.1", "not_allowed", false},
	{"allow_loopback_with_loopback_in_the_list", true, "", "127.0.0.0/8,192.168.0.0/16", "127.0.0.1", "", false},
	// deny-wins when both lists match
	{"deny_wins_over_allow", false, "10.1.0.0/16", "10.0.0.0/8", "10.1.2.3", "deny", false},
	{"allow_still_serves_outside_the_denied_range", false, "10.1.0.0/16", "10.0.0.0/8", "10.2.0.1", "", false},
}

type specConfigCase struct {
	Name        string
	Deny, Allow string
	Valid       bool
}

// specConfigCases: syntax and validation, fail closed (§5: any error = refuse to start).
var specConfigCases = []specConfigCase{
	{"empty_lists_are_valid", "", "", true},
	{"one_cidr", "10.0.0.0/8", "", true},
	{"several_cidrs_both_families", "10.0.0.0/8,192.168.0.0/16,fd00::/8", "2001:db8::/32", true},
	{"host_routes_v4_and_v6", "10.1.2.3/32,fd00::1/128", "", true},
	{"slash_0_v4_in_deny", "0.0.0.0/0", "", false},
	{"slash_0_v6_in_deny", "::/0", "", false},
	{"slash_0_v4_in_allow", "", "0.0.0.0/0", false},
	{"slash_0_v6_in_allow", "", "::/0", false},
	{"slash_0_among_valid_entries", "10.0.0.0/8,0.0.0.0/0", "", false},
	{"host_bits_set_v4", "10.0.0.1/8", "", false},
	{"host_bits_set_v6", "fd00::1/8", "", false},
	{"host_bits_set_in_allow", "", "192.168.1.5/16", false},
	{"prefix_too_long_v4", "10.0.0.0/33", "", false},
	{"prefix_too_long_v6", "fd00::/129", "", false},
	{"no_prefix_bare_ip", "10.0.0.1", "", false},
	{"garbage", "not-a-cidr", "", false},
	{"empty_entry_between_commas", "10.0.0.0/8,,192.168.0.0/16", "", false},
	{"trailing_comma", "10.0.0.0/8,", "", false},
	{"leading_comma", ",10.0.0.0/8", "", false},
	{"leading_space", " 10.0.0.0/8", "", false},
	{"space_after_comma", "10.0.0.0/8, 192.168.0.0/16", "", false},
	{"space_inside_entry", "10.0.0.0 /8", "", false},
	{"duplicate_entry", "10.0.0.0/8,10.0.0.0/8", "", false},
	{"duplicate_entry_in_allow", "", "192.168.0.0/16,192.168.0.0/16", false},
	{"hostname_instead_of_cidr", "relay.example.com/24", "", false},
	{"more_than_256_entries", specManyCIDRs(257), "", false},
	{"exactly_256_entries", specManyCIDRs(256), "", true},
}

func specManyCIDRs(n int) string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("10.%d.%d.1/32", i/250, i%250)
	}
	return strings.Join(out, ",")
}

// specRunPolicyCases returns the names of the cases the policy fails.
func specRunPolicyCases(t *testing.T, p *specDialPolicy) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, c := range specPolicyCases {
		restore, err := p.Configure(c.Loop, c.Deny, c.Allow)
		if err != nil {
			if !c.AcceptConfig {
				out[c.Name] = "valid configuration refused: " + err.Error()
			}
			continue
		}
		if got := p.Category(net.ParseIP(c.IP)); got != c.Want {
			out[c.Name] = fmt.Sprintf("%s under loop=%v deny=%q allow=%q: category %q, want %q", c.IP, c.Loop, c.Deny, c.Allow, got, c.Want)
		}
		restore()
	}
	for _, c := range specConfigCases {
		restore, err := p.Configure(false, c.Deny, c.Allow)
		switch {
		case c.Valid && err != nil:
			out["config/"+c.Name] = "must be accepted: " + err.Error()
		case !c.Valid && err == nil:
			out["config/"+c.Name] = "must be refused (refuse to start), accepted"
		}
		if err == nil {
			restore()
		}
	}
	return out
}

// The table is right: the reference implementation passes it entirely.
func TestSpecDialPolicy_OraclePassesEveryCase(t *testing.T) {
	if f := specRunPolicyCases(t, specOraclePolicy(specPolNone)); len(f) != 0 {
		t.Fatalf("the reference fails cases (the table is wrong): %v", f)
	}
}

// The table bites: the mutants "deny ignored" and "allow ignored" of the plan, plus "ALLOW lifts a
// built-in prohibition", are each killed by the cases written for them.
func TestSpecDialPolicy_MutantsAreKilled(t *testing.T) {
	for _, tc := range []struct {
		m      specPolicyMutant
		killBy []string
	}{
		{specPolDenyIgnored, []string{"deny_refuses_inside", "deny_v6", "deny_wins_over_allow", "deny_applies_to_loopback_even_when_allowed"}},
		{specPolAllowIgnored, []string{"allow_refuses_outside_private", "allow_refuses_outside_public", "allow_loopback_with_allow_list_requires_loopback_in_the_list"}},
		{specPolAllowLiftsBuilt, []string{"allow_cannot_lift_alibaba", "allow_cannot_lift_aws_v6", "allow_cannot_lift_azure"}},
	} {
		t.Run(string(tc.m), func(t *testing.T) {
			f := specRunPolicyCases(t, specOraclePolicy(tc.m))
			if len(f) == 0 {
				t.Fatalf("mutant %q survives", tc.m)
			}
			for _, name := range tc.killBy {
				if _, ok := f[name]; !ok {
					t.Errorf("mutant %q must be killed by %q; failing: %v", tc.m, name, f)
				}
			}
		})
	}
}
