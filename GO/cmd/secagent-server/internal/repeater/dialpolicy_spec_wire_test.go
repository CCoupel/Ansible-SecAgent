package repeater

// Wiring of the real dial policy (dialpolicy.go) into the specification tests of test-writer.

import "net"

func init() {
	specDialPolicyUnderTest = &specDialPolicy{
		Configure: func(allowLoopback bool, deny, allow string) (func(), error) {
			p, err := ParseDialPolicy(allowLoopback, deny, allow)
			if err != nil {
				return nil, err
			}
			return SetDialPolicy(p), nil
		},
		Category: func(ip net.IP) string { return currentPolicy().Category(ip) },
		FromEnv: func(env map[string]string) error {
			_, err := DialPolicyFromEnv(func(k string) string { return env[k] })
			return err
		},
	}
}
