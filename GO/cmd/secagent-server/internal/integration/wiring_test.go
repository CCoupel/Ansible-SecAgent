package integration

import (
	"os"
	"regexp"
	"sort"
	"testing"
)

// The harness re-implements the wiring of main.go (package main cannot be imported). This guard
// fails when main.go starts using a hook / constructor the harness does not call, so the
// integration tests cannot silently drift away from the real server.
func TestNodeWiringMatchesMain(t *testing.T) {
	t.Parallel()
	mainSrc, err := os.ReadFile("../../main.go")
	if err != nil {
		t.Fatal(err)
	}
	harness, err := os.ReadFile("node_process_test.go")
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`\b(ws\.(?:Set\w+|Relay\w+Func|DispatchFunc)|handlers\.(?:Set\w+|InitServerState)|repeater\.(?:New\w+)|forward\.Forwarder|hooks\.GlobalDispatcher|proxy\.NewProxyRouter)\b`)
	// not part of the relay tree: NATS, the RSA/JWT bootstrap and the CLI mode are out of scope
	exempt := map[string]string{"handlers.InitServerState": "RSA-4096 generation, irrelevant to the tree (documented in node_process_test.go)"}
	used := map[string]bool{}
	for _, m := range re.FindAllSubmatch(mainSrc, -1) {
		used[string(m[1])] = true
	}
	var missing []string
	for name := range used {
		if _, ok := exempt[name]; ok {
			continue
		}
		if !regexp.MustCompile(regexp.QuoteMeta(name) + `\b`).Match(harness) {
			missing = append(missing, name)
		}
	}
	sort.Strings(missing)
	if len(used) < 20 {
		t.Fatalf("the guard found only %d wiring calls in main.go: its pattern is out of date", len(used))
	}
	if len(missing) > 0 {
		t.Errorf("main.go wires %v but the integration harness (node_process_test.go) does not: add them to assembleNode", missing)
	}
	// the public /health: only the degraded flag (never the links block), same as main.go
	healthSrc := regexp.MustCompile(`(?s)func handleHealth\(.*?\n}\n`).Find(mainSrc)
	if healthSrc == nil || !regexp.MustCompile(`body\["degraded"\]`).Match(healthSrc) || regexp.MustCompile(`body\["links"\]`).Match(healthSrc) {
		t.Fatalf("main.go's handleHealth changed shape: re-align the /health handler of the harness\n%s", healthSrc)
	}
	if regexp.MustCompile(`body\["links"\]`).Match(harness) {
		t.Error("the harness /health must not expose the links block (main.go does not)")
	}
}
