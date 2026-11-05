// SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
// SPDX-License-Identifier: AGPL-3.0-or-later

package ws

import (
	"fmt"
	"testing"
	"time"
)

// B47 (#222): the integration test TestRevocation_Code4012IsRetried no longer requires the child to log every
// received 4012 (the TCP close can overtake the frame). The emission side is checked here, on the wire, for EVERY
// close: each CloseRelay(…, 4012) must reach the peer as a close frame carrying exactly 4012 (correctable
// refusal), never 4010 (permanent) nor an abnormal closure.
func TestCloseRelay_EveryCloseSends4012(t *testing.T) {
	setTreeHooks(t, "central", nil, nil, nil)
	srv := setupRelayTestServer(t)
	defer srv.Close()

	const closes = 5
	for i := 0; i < closes; i++ {
		id := fmt.Sprintf("relay-4012-%d", i)
		c := dialRelay(t, srv, makeRelayJWT(id, "relay"))
		if !awaitRelayConnected(t, id, 2*time.Second) {
			t.Fatalf("%s not connected", id)
		}
		if !CloseRelay(id, WSRelayCloseRetry, "snapshot refused") {
			t.Fatalf("%s must be closed", id)
		}
		if code := expectClose(t, c); code != WSRelayCloseRetry {
			t.Errorf("close #%d: code = %d, want 4012", i+1, code)
		}
	}
}
