package auth

// Wiring of the L1c implementation (auth/linkjwt.go) into the spec tests
// (linkjwt_spec_adapter_test.go).

import (
	"crypto/ed25519"
	"errors"
	"time"
)

func init() {
	toTrust := func(t specLinkTrust) LinkTrust {
		return LinkTrust{Current: t.Current, Previous: t.Previous, Blacklisted: t.Blacklisted, LastSeq: t.LastSeq}
	}
	fromTrust := func(t LinkTrust) specLinkTrust {
		return specLinkTrust{Current: t.Current, Previous: t.Previous, Blacklisted: t.Blacklisted, LastSeq: t.LastSeq}
	}
	specLinkImplUnderTest = &specLinkImpl{
		KidOf: LinkKID,
		VerifyToken: func(trust specLinkTrust, token string, want specLinkWant, now time.Time) (bool, error) {
			_, err := VerifyLinkToken(toTrust(trust), token, LinkWant{LocalID: want.LocalID, RootID: specRootID, Role: want.Role}, now)
			if err == nil {
				return false, nil
			}
			var le *LinkError
			if errors.As(err, &le) {
				return le.Permanent, err
			}
			return true, err
		},
		SignToken: func(priv ed25519.PrivateKey, iss, sub, aud, role string, ttl time.Duration) (string, string, error) {
			return SignLinkToken(priv, iss, sub, aud, role, ttl)
		},
		SignRevocations: func(priv ed25519.PrivateKey, seq uint64, entries []specRevEntry) ([]byte, error) {
			es := make([]LinkRevocation, len(entries))
			for i, e := range entries {
				es[i] = LinkRevocation{JTI: e.JTI, Exp: e.Exp}
			}
			return SignLinkRevocations(priv, seq, es)
		},
		VerifyRevocations: func(trust specLinkTrust, msg []byte) (uint64, []specRevEntry, error) {
			seq, es, err := VerifyLinkRevocations(toTrust(trust), msg)
			if err != nil {
				return 0, nil, err
			}
			out := make([]specRevEntry, len(es))
			for i, e := range es {
				out[i] = specRevEntry{JTI: e.JTI, Exp: e.Exp}
			}
			return seq, out, nil
		},
		SignLinkKeys: SignLinkKeys,
		ApplyLinkKeys: func(trust specLinkTrust, msg []byte) (specLinkTrust, error) {
			nt, err := ApplyLinkKeys(toTrust(trust), msg)
			if err != nil {
				return trust, err
			}
			return fromTrust(nt), nil
		},
	}
}
