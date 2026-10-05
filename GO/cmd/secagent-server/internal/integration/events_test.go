package integration

// Event propagation (#126 / #137) on REAL nodes: host.up / host.down / host.new travel up the tree
// with an exact relay_chain, run the hooks of every node they cross, and every guard of the
// receiving side (shape, subtree, local ownership, chain length) refuses what it must.
//
// Topology note: a node only accepts events whose intermediate relays it knows from the child's
// topology_snapshot. Scenarios that need events to cross three levels therefore link the top node
// LAST (root ──push──▶ mid ◀──pull── leaf): mid's snapshot at link-up declares leaf. The opposite
// join order is the documented late-joining-relay gap (see chain_test.go).

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// standardHooks writes one line per event: "<KIND> <host> status=… chain=… origin=…".
func standardHooks(out string) string {
	line := func(kind string) map[string]any {
		return map[string]any{"event": kindEvent(kind), "actions": []map[string]any{{
			"type": "file", "path": out,
			"append": kind + " {{hostname}} status={{status}} chain={{relay_chain}} origin={{relay_origin}} enrolled={{enrolled_at}}\n",
		}}}
	}
	return mustJSONString(map[string]any{"hooks": []any{line("UP"), line("DOWN"), line("NEW"), line("CONFLICT")}})
}

func kindEvent(kind string) string {
	return map[string]string{"UP": "host.up", "DOWN": "host.down", "NEW": "host.new", "CONFLICT": "host.conflict"}[kind]
}

func mustJSONString(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(b)
}

// pushChain builds root ──push──▶ mid ◀──pull── leaf, the leaf being declared to the root by mid's
// snapshot. Every node runs the standard hooks.
func pushChain(t *testing.T) (root, mid, leaf *node) {
	t.Helper()
	root = startNode(t, nodeSpec{ID: "root", Hooks: standardHooks})
	mid = startNode(t, nodeSpec{ID: "mid", Hooks: standardHooks})
	leaf = startNode(t, nodeSpec{ID: "leaf", ParentURL: mid.wssURL(), ParentToken: mid.registerChild("leaf"), Hooks: standardHooks})
	waitFor(t, "leaf linked to mid", func() bool { return leaf.upstreamState() == "connected" })
	linkPush(t, root, mid)
	return
}

// linkPush makes parent dial child (push) and waits for the link on both sides.
func linkPush(t *testing.T, parent, child *node) {
	t.Helper()
	tok, _ := child.mintParentToken(parent.id)
	if code, m := parent.admin("POST", "/api/admin/relays", map[string]any{"relay_id": child.id, "mode": "push", "url": child.wssURL(), "token": tok}); code != http.StatusCreated {
		t.Fatalf("register push %s on %s: %d %v", child.id, parent.id, code, m)
	}
	waitFor(t, parent.id+" dialer connected", func() bool { return parent.pushState(child.id) == "connected" })
	waitFor(t, parent.id+" received the snapshot of "+child.id, func() bool { return parent.logs.count("topology_snapshot: relay_id="+child.id) >= 1 })
}

// ── a fake child relay: speaks the protocol by hand so that hostile messages can be sent ────────

type fakeChild struct {
	t    *testing.T
	conn *websocket.Conn
}

func newFakeChild(t *testing.T, parent *node, id string, declared ...[]string) *fakeChild {
	t.Helper()
	tok := parent.registerChild(id)
	h := http.Header{}
	h.Set("Authorization", "Bearer "+tok)
	d := websocket.Dialer{TLSClientConfig: tlsClientConfig(), HandshakeTimeout: 5 * time.Second}
	conn, _, err := d.Dial(parent.wssURL()+"/ws/relay", h)
	if err != nil {
		t.Fatalf("fake child %s: %v", id, err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	f := &fakeChild{t: t, conn: conn}
	f.send(map[string]any{"type": "relay_hello", "relay_id": id, "node_type": "relay", "mode": "pull", "version": "3.0", "ancestors": []string{}})
	f.expect("relay_ack")
	relays := []map[string]any{}
	for _, chain := range declared {
		relays = append(relays, map[string]any{"relay_id": chain[len(chain)-1], "relay_chain": chain})
	}
	f.send(map[string]any{"type": "topology_snapshot", "relays": relays, "agents": []any{}})
	f.expect("topology_ack")
	// keep reading so that pings are answered and the link stays up
	go func() {
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}()
	return f
}

func (f *fakeChild) send(m map[string]any) {
	f.t.Helper()
	if err := f.conn.WriteJSON(m); err != nil {
		f.t.Fatalf("fake child write: %v", err)
	}
}

func (f *fakeChild) expect(typ string) {
	f.t.Helper()
	_ = f.conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	for {
		var m map[string]any
		if err := f.conn.ReadJSON(&m); err != nil {
			f.t.Fatalf("waiting for %s: %v", typ, err)
		}
		if m["type"] == typ {
			_ = f.conn.SetReadDeadline(time.Time{})
			return
		}
	}
}

func (f *fakeChild) event(kind, host, status string, chain ...string) {
	f.t.Helper()
	f.send(map[string]any{"type": "event_forward", "event": kind, "hostname": host, "status": status, "relay_chain": chain})
}

// ── real enrollment (host.new) ───────────────────────────────────────────────

// enroll runs the real two-phase enrollment of hostname on the node: a host.new is dispatched.
func enroll(t *testing.T, n *node, hostname string) {
	t.Helper()
	code, m := n.admin("POST", "/api/admin/tokens", map[string]any{"role": "enrollment", "hostname_pattern": "^" + hostname + "$"})
	if code != http.StatusCreated {
		t.Fatalf("enrollment token: %d %v", code, m)
	}
	token, _ := m["token"].(string)

	key, err := rsa.GenerateKey(rand.Reader, 4096) // the server refuses weaker agent keys
	if err != nil {
		t.Fatal(err)
	}
	pubDER, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))

	post := func(body map[string]any) (int, map[string]any) {
		c, raw := n.call("POST", "/api/register", "", body)
		var out map[string]any
		_ = json.Unmarshal(raw, &out)
		return c, out
	}
	c1, r1 := post(map[string]any{"hostname": hostname, "public_key_pem": pubPEM, "enrollment_token": token})
	if c1 != http.StatusOK {
		t.Fatalf("enrollment phase 1: %d %v", c1, r1)
	}
	challenge, _ := base64.StdEncoding.DecodeString(r1["challenge"].(string))
	nonce, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, key, challenge, nil)
	if err != nil {
		t.Fatalf("decrypt the challenge: %v", err)
	}
	block, _ := pem.Decode([]byte(r1["server_public_key_pem"].(string)))
	srvPub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, srvPub.(*rsa.PublicKey), append(nonce, []byte(token)...), nil)
	if err != nil {
		t.Fatal(err)
	}
	if c2, r2 := post(map[string]any{"hostname": hostname, "public_key_pem": pubPEM, "enrollment_token": token,
		"challenge_response": base64.StdEncoding.EncodeToString(resp)}); c2 != http.StatusOK {
		t.Fatalf("enrollment phase 2: %d %v", c2, r2)
	}
}

// ── scenarios ────────────────────────────────────────────────────────────────

// #137-1: host.up / host.down / host.new climb from level to level; every node's hooks run with the
// relay_chain it received (origin first, the sending relay last), and nothing secret travels.
func TestEvents_PropagateUpWithExactRelayChain(t *testing.T) {
	parallel(t)
	root, mid, leaf := pushChain(t)

	m := connectMinion(t, leaf, "ev-host")
	waitFor(t, "root's hook ran for host.up", func() bool { return root.hookHas("UP ev-host") })
	waitFor(t, "mid's hook ran for host.up", func() bool { return mid.hookHas("UP ev-host") })
	waitFor(t, "leaf's hook ran for host.up", func() bool { return leaf.hookHas("UP ev-host") })
	want := map[*node]string{
		leaf: "UP ev-host status=connected chain= origin= enrolled=",
		mid:  "UP ev-host status=connected chain=leaf origin=leaf enrolled=",
		root: "UP ev-host status=connected chain=leaf,mid origin=leaf enrolled=",
	}
	for n, line := range want {
		if got := n.hookLines(); len(got) != 1 || got[0] != line {
			t.Errorf("%s hook lines = %q, want exactly %q (local event: empty chain; received: origin first, sender last)", n.id, got, line)
		}
	}
	if !root.hasHost("ev-host") {
		t.Error("the host.up must have routed the deep host at the root")
	}

	_ = m.conn.Close() // the machine goes away
	waitFor(t, "root's hook ran for host.down", func() bool { return root.hookHas("DOWN ev-host") })
	if got := root.hookLines(); got[len(got)-1] != "DOWN ev-host status=disconnected chain=leaf,mid origin=leaf enrolled=" {
		t.Errorf("root host.down hook = %q", got)
	}
	if !mid.hookHas("DOWN ev-host status=disconnected chain=leaf origin=leaf") {
		t.Errorf("mid host.down hooks = %q", mid.hookLines())
	}

	// host.new: a REAL enrollment on the leaf
	enroll(t, leaf, "enrolled-host")
	waitFor(t, "root's hook ran for host.new", func() bool { return root.hookHas("NEW enrolled-host") })
	for n, chain := range map[*node]string{root: "leaf,mid", mid: "leaf"} {
		found := ""
		for _, l := range n.hookLines() {
			if strings.HasPrefix(l, "NEW enrolled-host") {
				found = l
			}
		}
		if !strings.Contains(found, "status=disconnected chain="+chain+" origin=leaf enrolled=20") {
			t.Errorf("%s host.new hook = %q (chain %s, RFC 3339 enrolled_at expected)", n.id, found, chain)
		}
	}

	// nothing secret in the events, the hook outputs or the logs
	if r := root.exec("ev-host", execBody("id")); r.Code == http.StatusOK {
		t.Log("host is down: exec must not succeed") // the host disconnected above
	}
	connectMinion(t, leaf, "ev-host-2")
	waitFor(t, "root routes ev-host-2", func() bool { return root.hasHost("ev-host-2") })
	if r := root.exec("ev-host-2", execBody("whoami")); r.Code != http.StatusOK {
		t.Fatalf("exec through the event-learned route = %d %v", r.Code, r.Body)
	}
	hookOutputs := ""
	for _, n := range []*node{root, mid, leaf} {
		hookOutputs += strings.Join(n.hookLines(), "\n")
	}
	assertNoSecrets(t, allLogs(root, mid, leaf)+hookOutputs, nodeSecrets(root, mid, leaf)...)
}

// #137-2: relay_chain_contains selects the hook; the first matching hook wins.
func TestEvents_HookFilterRelayChainContains(t *testing.T) {
	parallel(t)
	hooksWith := func(filtered, plain string, relay string) func(string) string {
		return func(out string) string {
			act := func(tag string) []map[string]any {
				return []map[string]any{{"type": "file", "path": out, "append": tag + " {{hostname}} chain={{relay_chain}}\n"}}
			}
			return mustJSONString(map[string]any{"hooks": []any{
				map[string]any{"event": "host.up", "filter": map[string]any{"relay_chain_contains": relay}, "actions": act(filtered)},
				map[string]any{"event": "host.up", "actions": act(plain)},
			}})
		}
	}
	root := startNode(t, nodeSpec{ID: "root", Hooks: hooksWith("FILTERED", "PLAIN", "leaf")})
	mid := startNode(t, nodeSpec{ID: "mid", Hooks: hooksWith("FILTERED", "PLAIN", "nobody")})
	leaf := startNode(t, nodeSpec{ID: "leaf", ParentURL: mid.wssURL(), ParentToken: mid.registerChild("leaf")})
	waitFor(t, "leaf linked", func() bool { return leaf.upstreamState() == "connected" })
	linkPush(t, root, mid)

	connectMinion(t, leaf, "deep-one")  // chain at the root: leaf,mid ; at mid: leaf
	connectMinion(t, root, "local-one") // chain empty at the root
	waitFor(t, "root: both hooks decided", func() bool { return root.hookCount("FILTERED")+root.hookCount("PLAIN") >= 2 })
	waitFor(t, "mid: the event was handled", func() bool { return mid.hookCount("FILTERED")+mid.hookCount("PLAIN") >= 1 })
	// barrier: a later event on the same links is handled after the previous ones
	connectMinion(t, leaf, "deep-barrier")
	waitFor(t, "barrier at the root", func() bool { return root.hookCount("FILTERED") >= 2 })

	if !root.hookHas("FILTERED deep-one chain=leaf,mid") || root.hookHas("PLAIN deep-one") {
		t.Errorf("root: the event whose chain contains 'leaf' must run the filtered hook only: %q", root.hookLines())
	}
	if !root.hookHas("PLAIN local-one chain=") || root.hookHas("FILTERED local-one") {
		t.Errorf("root: a local event (empty chain) must skip the filtered hook: %q", root.hookLines())
	}
	if !mid.hookHas("PLAIN deep-one chain=leaf") || mid.hookHas("FILTERED") {
		t.Errorf("mid: a filter on a relay that is not in the chain must not match: %q", mid.hookLines())
	}
}

// #137-3: an invalid hooks file is refused as a whole, at start-up and at reload (SIGHUP): the
// previous configuration stays in force.
func TestEvents_InvalidHooksConfigIsRejectedWholeAndPreviousKept(t *testing.T) {
	parallel(t)
	hooksV := func(tag string, extra string) func(string) string {
		return func(out string) string {
			return `{"hooks":[{"event":"host.up","actions":[{"type":"file","path":"` + out + `","append":"` + tag + ` {{hostname}}\n"}]}` + extra + `]}`
		}
	}
	invalid := func(out string) string { // a valid hook followed by one with an empty filter: the WHOLE file is refused
		return hooksV("V2", `,{"event":"host.down","filter":{},"actions":[{"type":"file","path":"`+out+`","append":"X\n"}]}`)(out)
	}
	n := startNode(t, nodeSpec{ID: "n1", Hooks: hooksV("V1", "")})
	connectMinion(t, n, "first")
	waitFor(t, "V1 ran", func() bool { return n.hookHas("V1 first") })

	n.setHooks(invalid(n.hookOut))
	n.reloadHooks()
	waitFor(t, "the reload error is logged", func() bool { return n.logs.has("hooks config reload error") })
	connectMinion(t, n, "second")
	waitFor(t, "the PREVIOUS config still runs", func() bool { return n.hookHas("V1 second") })
	if n.hookHas("V2") {
		t.Error("a refused file must not be partially applied")
	}

	n.setHooks(hooksV("V3", "")(n.hookOut))
	n.reloadHooks()
	connectMinion(t, n, "third")
	waitFor(t, "the new valid config applies", func() bool { return n.hookHas("V3 third") })

	// at start-up: an invalid file means NO hook at all
	bad := startNode(t, nodeSpec{ID: "n2", Hooks: invalid})
	if !bad.logs.has("hooks config parse error") {
		t.Errorf("the start-up refusal must be logged:\n%s", bad.logs.String())
	}
	connectMinion(t, bad, "x1")
	bad.setHooks(hooksV("OK", "")(bad.hookOut)) // valid again: proves the earlier event ran no hook
	bad.reloadHooks()
	connectMinion(t, bad, "x2")
	waitFor(t, "hooks run once the file is valid", func() bool { return bad.hookHas("OK x2") })
	if len(bad.hookLines()) != 1 {
		t.Errorf("no hook may have run while the file was invalid: %q", bad.hookLines())
	}
}

// #137-4: what a child relay must never be able to do. Hostile events are neither dispatched to
// the hooks nor forwarded; a valid event sent after them goes through, which proves the pipeline
// was alive and in order.
func TestEvents_HostileEventsAreNeitherDispatchedNorForwarded(t *testing.T) {
	parallel(t)
	root := startNode(t, nodeSpec{ID: "root", Hooks: standardHooks})
	mid := startNode(t, nodeSpec{ID: "mid", Hooks: standardHooks})
	fake := newFakeChild(t, mid, "fakeA")
	other := startNode(t, nodeSpec{ID: "other", ParentURL: mid.wssURL(), ParentToken: mid.registerChild("other")})
	waitFor(t, "other linked", func() bool { return other.upstreamState() == "connected" })
	connectMinion(t, mid, "mid-local")
	connectMinion(t, other, "foreign-host")
	waitFor(t, "mid routes foreign-host via other", func() bool { return mid.hasHost("foreign-host") })
	linkPush(t, root, mid)
	baseMid, baseRoot := len(mid.hookLines()), len(root.hookLines())

	long := make([]string, 0, 33)
	for i := 0; i < 32; i++ {
		long = append(long, fmt.Sprintf("r%d", i))
	}
	long = append(long, "fakeA") // 33 elements
	tooLong := func(kind, host string) {
		fake.send(map[string]any{"type": "event_forward", "event": kind, "hostname": host, "status": "connected", "relay_chain": long})
	}

	bad := []struct {
		name   string
		send   func()
		marker string // what mid must log
	}{
		{"host.down of a host connected at the receiver", func() { fake.event("host.down", "mid-local", "disconnected", "fakeA") }, "is connected locally"},
		{"host.up for a direct agent of the receiver", func() { fake.event("host.up", "mid-local", "connected", "fakeA") }, "host.conflict: hostname=mid-local"},
		{"host.down of a host routed through another relay", func() { fake.event("host.down", "foreign-host", "disconnected", "fakeA") }, "routed through another relay"},
		{"unsupported event kind host.revoked", func() { fake.event("host.revoked", "victim", "disconnected", "fakeA") }, "unsupported event kind"},
		{"unsupported event kind relay.up", func() { fake.event("relay.up", "victim", "connected", "fakeA") }, "unsupported event kind"},
		{"hostname with a shell injection", func() { fake.event("host.up", "a;touch /tmp/pwned", "connected", "fakeA") }, "invalid hostname"},
		{"hostname with a template / command substitution", func() { fake.event("host.up", "$(id){{hostname}}", "connected", "fakeA") }, "invalid hostname"},
		{"hostname with a newline (log / file injection)", func() { fake.event("host.up", "x\nUP forged status=connected", "connected", "fakeA") }, "invalid hostname"},
		{"hostname that is a path", func() { fake.event("host.up", "../../etc/passwd", "connected", "fakeA") }, "invalid hostname"},
		{"unknown status", func() { fake.event("host.up", "weird-status", "exploded", "fakeA") }, "invalid status"},
		{"relay_chain longer than 32", func() { tooLong("host.up", "long-chain") }, "relay_chain too long"},
		{"relay_chain whose last element is not the sender", func() { fake.event("host.up", "spoofed-sender", "connected", "someone-else") }, "last element must be the authenticated peer"},
		{"relay_chain through an undeclared relay", func() { fake.event("host.up", "undeclared", "connected", "ghost", "fakeA") }, "unknown descendant"},
		{"enrolled_at on a host.up", func() {
			fake.send(map[string]any{"type": "event_forward", "event": "host.up", "hostname": "bad-enrol", "status": "connected", "enrolled_at": "2026-01-01T00:00:00Z", "relay_chain": []string{"fakeA"}})
		}, "enrolled_at only belongs to host.new"},
	}
	for _, b := range bad {
		before := mid.logs.count(b.marker)
		b.send()
		waitFor(t, "mid refuses: "+b.name, func() bool { return mid.logs.count(b.marker) > before })
	}

	// a VALID host.up of the child's own subtree, sent after all the hostile ones, goes through at
	// every level: it proves the hostile ones were refused, not merely slow
	fake.event("host.up", "control-host", "connected", "fakeA")
	waitFor(t, "the valid event reaches mid's hooks", func() bool { return mid.hookHas("UP control-host status=connected chain=fakeA origin=fakeA") })
	waitFor(t, "the valid event reaches the root's hooks", func() bool { return root.hookHas("UP control-host status=connected chain=fakeA,mid origin=fakeA") })
	fake.event("host.down", "control-host", "disconnected", "fakeA") // a host of its OWN subtree may go down
	waitFor(t, "a host.down of the child's own subtree is accepted", func() bool { return root.hookHas("DOWN control-host") && mid.hookHas("DOWN control-host") })

	for _, n := range []*node{mid, root} {
		base := baseMid
		if n == root {
			base = baseRoot
		}
		var accepted []string
		conflicts := 0
		for _, l := range n.hookLines()[base:] {
			if strings.HasPrefix(l, "CONFLICT mid-local status=local->fakeA") {
				conflicts++ // the claim on a live local agent is REPORTED (host.conflict), once, never applied
				continue
			}
			accepted = append(accepted, l)
		}
		if conflicts != 1 {
			t.Errorf("%s: %d host.conflict hooks for the claim on the local agent, want exactly 1", n.id, conflicts)
		}
		if len(accepted) != 2 {
			t.Errorf("%s ran %d other hooks after the hostile events, want exactly the 2 valid ones: %q", n.id, len(accepted), accepted)
		}
		for _, l := range n.hookLines()[base:] {
			for _, forbidden := range []string{"foreign-host", "victim", "touch", "$(", "{{", "forged", "passwd", "weird-status", "long-chain", "spoofed", "undeclared", "bad-enrol"} {
				if strings.Contains(l, forbidden) {
					t.Errorf("%s: a hostile event reached the hooks: %q", n.id, l)
				}
			}
			if strings.HasPrefix(l, "UP mid-local") || strings.HasPrefix(l, "DOWN mid-local") {
				t.Errorf("%s: an event about the receiver's local agent was dispatched: %q", n.id, l)
			}
		}
	}
	if _, err := os.Stat("/tmp/pwned"); err == nil {
		t.Error("the injected command was executed")
	}
	if root.logs.count("event_forward rejected") != 0 {
		t.Errorf("hostile events must not even reach the root:\n%s", root.logs.String())
	}
	assertNoSecrets(t, allLogs(root, mid, other), nodeSecrets(root, mid, other)...)
}

// #137-5: an event emitted while there is no parent link is dropped — not replayed on the next
// link; the snapshot resynchronises the parent instead.
func TestEvents_EventWithoutParentLinkIsDroppedNotReplayed(t *testing.T) {
	parallel(t)
	root := startNode(t, nodeSpec{ID: "root", Hooks: standardHooks})
	mid := startNode(t, nodeSpec{ID: "mid", Hooks: standardHooks}) // no parent yet
	connectMinion(t, mid, "pre-link")
	waitFor(t, "mid's own hook ran", func() bool { return mid.hookHas("UP pre-link") })

	linkPush(t, root, mid)
	waitFor(t, "the snapshot resynchronises the root", func() bool { return root.hasHost("pre-link") })
	// barrier: an event after the link travels; the stale one must not have preceded it
	connectMinion(t, mid, "post-link")
	waitFor(t, "post-link reaches the root", func() bool { return root.hookHas("UP post-link") })
	if root.hookHas("UP pre-link") {
		t.Errorf("a stale event emitted with no parent link must not be replayed: %q", root.hookLines())
	}
}

// #137-6: a conflict detected below climbs as host.conflict and is reported a small, stable number
// of times, not at every agent_list round.
func TestEvents_HostConflictClimbsWithoutStorm(t *testing.T) {
	parallel(t)
	root := startNode(t, nodeSpec{ID: "root", Hooks: standardHooks})
	mid := startNode(t, nodeSpec{ID: "mid", ParentURL: root.wssURL(), ParentToken: root.registerChild("mid")})
	waitFor(t, "mid linked", func() bool { return mid.upstreamState() == "connected" })
	leafA := startNode(t, nodeSpec{ID: "leafA", ParentURL: mid.wssURL(), ParentToken: mid.registerChild("leafA")})
	leafB := startNode(t, nodeSpec{ID: "leafB", ParentURL: mid.wssURL(), ParentToken: mid.registerChild("leafB")})
	waitFor(t, "leaves linked", func() bool { return leafA.upstreamState() == "connected" && leafB.upstreamState() == "connected" })

	connectMinion(t, leafA, "twin")
	connectMinion(t, leafB, "twin")
	waitFor(t, "the root's hook saw the conflict", func() bool { return root.hookHas("CONFLICT twin") })
	rounds := func(n int) {
		base := mid.logs.count("agent_list: relay_id=leafA") + mid.logs.count("agent_list: relay_id=leafB")
		waitFor(t, "more agent_list rounds", func() bool {
			return mid.logs.count("agent_list: relay_id=leafA")+mid.logs.count("agent_list: relay_id=leafB") >= base+n
		})
	}
	rounds(8)
	settled := root.hookCount("CONFLICT twin")
	rounds(16)
	// one report per direction of the flip, plus one when the two claims interleave: bounded, and above
	// all STABLE once the claims have settled (a storm would grow with every agent_list round)
	if now := root.hookCount("CONFLICT twin"); now != settled || now < 1 || now > 4 {
		t.Errorf("host.conflict hooks at the root went from %d to %d over 16 more rounds: want a small stable count (1..4)", settled, now)
	}
}
