// SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
// SPDX-License-Identifier: AGPL-3.0-or-later

package integration

import (
	"net/http"
	"testing"
	"time"
)

// DETERMINISTIC documentation of a window that exists since v3.0.5 (checked on cd0036a): the ENROLLMENT of a host
// (host.new) is enough for its ancestors to route it, a few milliseconds later, while its agent is not connected
// yet; an exec in that window reaches the relay, which does not hold the agent, and is refused (503
// host_not_found) instead of hanging. TestTopology_UnlinkingRelay… failed 2-5 % under CPU starvation because the
// client returns from its dial before the relay has registered the connection: it now waits for that.
func TestRouting_EnrolledButNotConnectedHostIsRoutedButRefused(t *testing.T) {
	parallel(t)
	root, _, leaf := pushChain(t)
	leaf.enrollAgent("enrolled-only") // enrolled, never connected
	routed := false
	for t0 := time.Now(); time.Since(t0) < 10*time.Second; time.Sleep(10 * time.Millisecond) {
		if root.hasHost("enrolled-only") {
			routed = true
			break
		}
	}
	if !routed {
		t.Fatal("the root must route a host as soon as it is enrolled below it (host.new)")
	}
	if r := root.exec("enrolled-only", execBody("id")); r.Code == http.StatusOK {
		t.Errorf("exec on a host whose agent is not connected must be refused, got %d %v", r.Code, r.Body)
	}
}
