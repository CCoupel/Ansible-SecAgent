package auth

// #141 / #146 (L1c) — conformance of the REAL link verifier to the specification (plan rev2 §3,
// tests 1 to 5 and 6 for the messages, mutations 12). Same table as the oracle tests; skipped until
// the dev wires the implementation (see linkjwt_spec_adapter_test.go).

import "testing"

func TestSpecLink_RealVerifierConformsToTheSpecification(t *testing.T) {
	impl := specLinkImplUnderTest
	if impl == nil {
		t.Skip("PENDING L1c: auth/linkjwt.go is not wired yet (create linkjwt_spec_wire_test.go that sets specLinkImplUnderTest)")
	}
	for _, c := range specLinkCases() {
		t.Run(c.Name, func(t *testing.T) {
			if why := c.Run(t, impl); why != "" {
				t.Error(why)
			}
		})
	}
}
