package integration

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"sort"
	"strings"
	"testing"
)

// ── Drift guard between main.go and the harness ───────────────────────────────
//
// The harness (node_process_test.go) re-implements the wiring of main.go because package main
// cannot be imported. A wiring omission in main.go — a missing blacklist hook, SetRelay*Func, push
// dialer, link-status func — would NOT be caught by the end-to-end tests, and several security
// defects of the relay tree were exactly wiring defects. These tests therefore parse BOTH files
// (go/ast) and compare their wiring items:
//
//   - TestMainWiringIsExactlyTheExpectedList: main.go's wiring must equal expectedMainWiring. Any
//     new / removed call fails with the exact item, forcing a conscious update of the list AND of
//     the harness.
//   - TestHarnessReproducesMainWiring: every expected item must be done by the harness, except
//     the explicit, justified exemptions.
//   - TestHarnessWiresNothingMainDoesNot: the harness must not wire what main.go does not.

// wiringItems extracts the wiring of a Go source file as "kind:name" items:
//
//	call:ws.SetRelayLocalIDFunc        a call to a wiring function of an internal package
//	assign:ws.DispatchFunc             an assignment to an exported package variable (hook)
//	option:repeater.Options.OnTask     a field set in a repeater/forward option literal
//	route:handlers.ExecCommand         an HTTP handler registered on a mux
func wiringItems(t *testing.T, path string) map[string]bool {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	internal := map[string]bool{"ws": true, "handlers": true, "repeater": true, "forward": true, "hooks": true, "proxy": true, "storage": false, "config": true}
	items := map[string]bool{}
	pkgOf := func(e ast.Expr) (pkg, name string, ok bool) {
		sel, isSel := e.(*ast.SelectorExpr)
		if !isSel {
			return "", "", false
		}
		id, isID := sel.X.(*ast.Ident)
		if !isID || !internal[id.Name] {
			return "", "", false
		}
		return id.Name, sel.Sel.Name, true
	}
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.CallExpr:
			if pkg, name, ok := pkgOf(x.Fun); ok {
				switch {
				case pkg == "ws" && strings.HasPrefix(name, "Set"),
					pkg == "handlers" && (strings.HasPrefix(name, "Set") || name == "InitServerState"),
					pkg == "repeater" && strings.HasPrefix(name, "New"),
					pkg == "hooks" && (name == "NewDispatcher" || name == "LoadConfig"),
					pkg == "proxy" && name == "NewProxyRouter",
					pkg == "config" && name == "LoadRepeaterConfig",
					pkg == "ws" && name == "RelayIdentity":
					items["call:"+pkg+"."+name] = true
				}
			}
			// mux.HandleFunc("pattern", pkg.Handler)
			if sel, ok := x.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "HandleFunc" && len(x.Args) == 2 {
				if pkg, name, ok := pkgOf(x.Args[1]); ok {
					items["route:"+pkg+"."+name] = true
				} else if id, isID := x.Args[1].(*ast.Ident); isID {
					items["route:main."+id.Name] = true
				}
			}
		case *ast.AssignStmt:
			for _, l := range x.Lhs {
				if pkg, name, ok := pkgOf(l); ok {
					items["assign:"+pkg+"."+name] = true
				}
			}
		case *ast.CompositeLit:
			if pkg, name, ok := pkgOf(x.Type); ok && (name == "Options" || name == "DialerOptions" || name == "Forwarder") {
				for _, el := range x.Elts {
					if kv, ok := el.(*ast.KeyValueExpr); ok {
						if k, ok := kv.Key.(*ast.Ident); ok {
							items["option:"+pkg+"."+name+"."+k.Name] = true
						}
					}
				}
			}
		}
		return true
	})
	return items
}

// expectedMainWiring is the wiring of main.go the harness is aligned with. Keep it in sync with
// main.go AND assembleNode (node_process_test.go).
var expectedMainWiring = []string{
	"assign:handlers.NATSHealthCheck",
	"assign:hooks.GlobalDispatcher",
	"assign:ws.DispatchFunc",
	"assign:ws.RelayIsProxyUpdateFunc",
	"assign:ws.RelayRoutingBulkUpsertFunc",
	"assign:ws.RelayStatusUpdateFunc",
	"call:config.LoadRepeaterConfig",
	"call:handlers.InitServerState",
	"call:handlers.SetAdminStore",
	"call:handlers.SetLinkStatusFunc",
	"call:handlers.SetProxyRouter",
	"call:handlers.SetRegisterStore",
	"call:handlers.SetRelayPushHooks",
	"call:hooks.LoadConfig",
	"call:hooks.NewDispatcher",
	"call:proxy.NewProxyRouter",
	"call:repeater.New",
	"call:repeater.NewDialerManager",
	"call:repeater.NewLinksStatus",
	"call:repeater.NewUplink",
	"call:ws.RelayIdentity",
	"call:ws.SetJWTSecretsFunc",
	"call:ws.SetRekeyFunc",
	"call:ws.SetRelayAncestorsFunc",
	"call:ws.SetRelayConflictFunc",
	"call:ws.SetRelayEventUpstreamFunc",
	"call:ws.SetRelayHostRouteFunc",
	"call:ws.SetRelayJTIBlacklistFunc",
	"call:ws.SetRelayLocalIDFunc",
	"call:ws.SetRelayNodeRegisterFunc",
	"call:ws.SetRelayParentLinkFunc",
	"call:ws.SetRelayRevokedFunc",
	"call:ws.SetRelayRouteChainsFunc",
	"call:ws.SetRelayRouteUpsertFunc",
	"option:forward.Forwarder.NextHop",
	"option:repeater.DialerOptions.Identity",
	"option:repeater.DialerOptions.Serve",
	"option:repeater.DialerOptions.WouldLoop",
	"option:repeater.Options.DirectAgents",
	"option:repeater.Options.Events",
	"option:repeater.Options.OnTask",
	"option:repeater.Options.Snapshot",
	"route:handlers.AdminAuthorize",
	"route:handlers.AdminDeleteMinion",
	"route:handlers.AdminDeleteMinionVar",
	"route:handlers.AdminDeleteToken",
	"route:handlers.AdminGetInventory",
	"route:handlers.AdminGetMinion",
	"route:handlers.AdminGetMinionVars",
	"route:handlers.AdminHooksLog",
	"route:handlers.AdminListMinions",
	"route:handlers.AdminPurgeTokens",
	"route:handlers.AdminResumeMinion",
	"route:handlers.AdminRevokeMinion",
	"route:handlers.AdminRotateKeys",
	"route:handlers.AdminSecurityBlacklist",
	"route:handlers.AdminSecurityBlacklistPurge",
	"route:handlers.AdminSecurityKeysStatus",
	"route:handlers.AdminSecurityTokens",
	"route:handlers.AdminSetMinionState",
	"route:handlers.AdminSetMinionVars",
	"route:handlers.AdminStats",
	"route:handlers.AdminSuspendMinion",
	"route:handlers.AsyncStatus",
	"route:handlers.RegisterAgent",
	"route:handlers.TokenRefresh",
	"route:handlers.AdminCreateRelay",
	"route:handlers.AdminCreateToken",
	"route:handlers.AdminDeleteRelay",
	"route:handlers.AdminListRelays",
	"route:handlers.AdminListTokens",
	"route:handlers.AdminRelaysStatus",
	"route:handlers.AdminRevokeRelay",
	"route:handlers.AdminRevokeToken",
	"route:handlers.AdminStatus",
	"route:handlers.ExecCommand",
	"route:handlers.FetchFile",
	"route:handlers.GetInventory",
	"route:handlers.UploadFile",
	"route:main.handleHealth",
	"route:ws.AgentHandler",
	"route:ws.RelayHandler",
}

// harnessExemptions are main.go wiring items the harness knowingly does NOT reproduce. Each one
// is a coverage hole of the end-to-end suite and must stay justified here.
var harnessExemptions = map[string]string{
	"assign:handlers.NATSHealthCheck": "no NATS in the harness (degraded mode); NATS is not part of the relay tree",
	"call:handlers.InitServerState":   "RSA-4096 keypair / key rotation bootstrap: irrelevant to the relay tree, minutes under -race",
	"call:hooks.LoadConfig":           "hooks config file: no hooks configured; host.conflict is asserted on the logs",
	"call:ws.SetRekeyFunc":            "agent rekey is exercised by the handlers tests, the harness only wires it",
	"route:main.handleHealth":         "the harness re-implements /health (checked by TestHarnessHealthMatchesMain)",
}

// relayTreeRoutes are the main.go routes that belong to the relay tree (links, tokens, relays,
// exec/file/inventory, agents, status): the harness MUST mount every one of them. The other
// routes (minions CRUD, hooks log, key rotation, enrollment…) are not part of this suite.
var relayTreeRoutes = []string{
	"route:handlers.AdminCreateRelay", "route:handlers.AdminCreateToken", "route:handlers.AdminDeleteRelay",
	"route:handlers.AdminListRelays", "route:handlers.AdminListTokens", "route:handlers.AdminRelaysStatus",
	"route:handlers.AdminRevokeRelay", "route:handlers.AdminRevokeToken", "route:handlers.AdminStatus",
	"route:handlers.ExecCommand", "route:handlers.FetchFile", "route:handlers.GetInventory",
	"route:handlers.UploadFile", "route:ws.AgentHandler", "route:ws.RelayHandler",
}

// Test-only wiring the harness adds on top of main.go (listener, TLS, intervals, control endpoint).
var harnessOnly = map[string]string{
	"call:ws.CloseRelay":                             "/__test/close-relay control endpoint",
	"option:repeater.Options.TLSConfig":              "self-signed test certificate",
	"option:repeater.Options.MinBackoff":             "short backoff so the suite runs in seconds",
	"option:repeater.Options.MaxBackoff":             "short backoff so the suite runs in seconds",
	"option:repeater.Options.AgentListInterval":      "short agent_list interval so the suite runs in seconds",
	"option:repeater.DialerOptions.TLSConfig":        "self-signed test certificate",
	"option:repeater.DialerOptions.MinBackoff":       "short backoff so the suite runs in seconds",
	"option:repeater.DialerOptions.MaxBackoff":       "short backoff so the suite runs in seconds",
	"option:repeater.DialerOptions.HandshakeTimeout": "explicit zero (default) kept for readability",
}

func TestMainWiringIsExactlyTheExpectedList(t *testing.T) {
	got := wiringItems(t, "../../main.go")
	want := map[string]bool{}
	for _, w := range expectedMainWiring {
		want[w] = true
	}
	var added, removed []string
	for k := range got {
		if !want[k] {
			added = append(added, k)
		}
	}
	for k := range want {
		if !got[k] {
			removed = append(removed, k)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	if len(got) < 40 {
		t.Fatalf("only %d wiring items found in main.go: the extractor is out of date", len(got))
	}
	if len(added) > 0 || len(removed) > 0 {
		t.Errorf("main.go wiring changed.\n  new in main.go (add to assembleNode in node_process_test.go, then to expectedMainWiring in wiring_test.go): %v\n  gone from main.go (remove from the harness and from expectedMainWiring): %v", added, removed)
	}
}

func TestHarnessReproducesMainWiring(t *testing.T) {
	harness := wiringItems(t, "node_process_test.go")
	var missing []string
	required := map[string]bool{}
	for _, w := range expectedMainWiring {
		if !strings.HasPrefix(w, "route:") {
			required[w] = true
		}
	}
	for _, w := range relayTreeRoutes {
		required[w] = true
	}
	for w := range required {
		if harness[w] {
			continue
		}
		if _, exempt := harnessExemptions[w]; exempt {
			continue
		}
		missing = append(missing, w)
	}
	sort.Strings(missing)
	for _, w := range relayTreeRoutes {
		found := false
		for _, e := range expectedMainWiring {
			found = found || e == w
		}
		if !found {
			t.Errorf("relayTreeRoutes lists %s which main.go does not register any more", w)
		}
	}
	if len(missing) > 0 {
		t.Errorf("the integration harness does not reproduce main.go's wiring — add to assembleNode in node_process_test.go (or justify in harnessExemptions): %v", missing)
	}
	for k, why := range harnessExemptions {
		if why == "" {
			t.Errorf("exemption %s has no justification", k)
		}
	}
}

func TestHarnessWiresNothingMainDoesNot(t *testing.T) {
	mainItems := wiringItems(t, "../../main.go")
	var extra []string
	for k := range wiringItems(t, "node_process_test.go") {
		if !mainItems[k] && !strings.HasPrefix(k, "route:") { // routes: the harness adds the test endpoints
			if _, ok := harnessOnly[k]; !ok {
				extra = append(extra, k)
			}
		}
	}
	sort.Strings(extra)
	if len(extra) > 0 {
		t.Errorf("the harness wires things main.go does not (it would hide a missing main.go wiring): %v", extra)
	}
}

// The public /health of main.go exposes only the degraded flag; the harness copy must too.
func TestHarnessHealthMatchesMain(t *testing.T) {
	src := func(path string) string {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	mainSrc, harness := src("../../main.go"), src("node_process_test.go")
	hasFlag := func(s string) bool { return strings.Contains(s, `["degraded"]`) }
	hasLinks := func(s string) bool { return strings.Contains(s, `["links"]`) }
	if !hasFlag(mainSrc) || hasLinks(mainSrc) {
		t.Fatal("main.go's handleHealth changed shape: re-align the /health handler of the harness and this test")
	}
	if !hasFlag(harness) || hasLinks(harness) {
		t.Error("the harness /health must expose only the degraded flag, like main.go")
	}
}
