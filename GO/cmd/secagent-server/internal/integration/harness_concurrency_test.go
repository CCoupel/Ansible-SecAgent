// SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
// SPDX-License-Identifier: AGPL-3.0-or-later

package integration

import (
	"sync"
	"testing"
)

// The harness caches the plugin token of a node on first use; startExecs (and any helper running requests from
// goroutines) calls pluginToken concurrently. An unsynchronized lazy initialisation was a DATA RACE that failed
// the CI under -race. Run with -race: every caller must get the SAME token and the race detector must stay quiet.
func TestHarness_PluginTokenIsSafeForConcurrentFirstCallers(t *testing.T) {
	parallel(t)
	n := startNode(t, nodeSpec{ID: "root"})
	const callers = 24
	got := make([]string, callers)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			got[i] = n.pluginToken()
		}(i)
	}
	close(start)
	wg.Wait()
	if got[0] == "" {
		t.Fatal("no plugin token was created")
	}
	for i, tok := range got {
		if tok != got[0] {
			t.Fatalf("caller %d got a different token: the token must be created once", i)
		}
	}
	if n.pluginTokenIfAny() != got[0] {
		t.Error("the cached token differs from the one returned")
	}
}
