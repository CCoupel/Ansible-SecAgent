package server

// Wiring of the real dial policy into the stored push line spec (#151).

import "secagent-server/cmd/secagent-server/internal/repeater"

func init() {
	specConfigureDialPolicy = func(allowLoopback bool, deny, allow string) (func(), error) {
		p, err := repeater.ParseDialPolicy(allowLoopback, deny, allow)
		if err != nil {
			return nil, err
		}
		return repeater.SetDialPolicy(p), nil
	}
}
