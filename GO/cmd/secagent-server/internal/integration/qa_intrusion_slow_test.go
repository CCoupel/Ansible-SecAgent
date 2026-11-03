//go:build slow

package integration

// QA v3.0.4 — real intrusion attempts against real nodes (written by the QA agent, scratchpad only).

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"

	"secagent-server/cmd/secagent-server/internal/auth"
)

func qaRootPub(t *testing.T, root *node) (ed25519.PublicKey, string) {
	t.Helper()
	code, m := root.admin("GET", "/api/admin/link/pubkey", nil)
	pemS, _ := m["current_pub_pem"].(string)
	if code != 200 || pemS == "" {
		t.Fatalf("pubkey: %d %v", code, m)
	}
	b, _ := pem.Decode([]byte(pemS))
	k, err := x509.ParsePKIXPublicKey(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return k.(ed25519.PublicKey), pemS
}

func qaClaims(iss, sub, aud, role string) jwt.MapClaims {
	now := time.Now()
	return jwt.MapClaims{"iss": iss, "sub": sub, "aud": aud, "role": role, "jti": uuid.New().String(), "iat": now.Unix(), "exp": now.Add(time.Hour).Unix()}
}

func qaForge(t *testing.T, m jwt.SigningMethod, key any, kid string, c jwt.MapClaims) string {
	t.Helper()
	tk := jwt.NewWithClaims(m, c)
	if kid != "" {
		tk.Header["kid"] = kid
	}
	s, err := tk.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// qaLinkAccepted: true when the node ACCEPTS the link (relay_hello answered by relay_ack).
func qaLinkAccepted(parent *node, token string) (bool, string) {
	return qaLinkAcceptedAs(parent, token, "evil")
}

func qaLinkAcceptedAs(parent *node, token, hello string) (bool, string) {
	c, resp, err := dialRelayLink(parent, token)
	if err != nil {
		st := 0
		if resp != nil {
			st = resp.StatusCode
		}
		return false, fmt.Sprintf("dial refused (http %d)", st)
	}
	defer func() { _ = c.Close() }()
	_ = c.WriteJSON(map[string]any{"type": "relay_hello", "relay_id": hello, "node_type": "relay", "mode": "pull", "version": "3.0", "ancestors": []string{}})
	_ = c.SetReadDeadline(time.Now().Add(4 * time.Second))
	for {
		var m map[string]any
		if err := c.ReadJSON(&m); err != nil {
			if ce, ok := err.(*websocket.CloseError); ok {
				return false, fmt.Sprintf("closed %d", ce.Code)
			}
			return false, "no ack: " + err.Error()
		}
		if m["type"] == "relay_ack" {
			return true, "relay_ack"
		}
	}
}

func TestQAIntrusion_ForgedLinkTokens(t *testing.T) {
	parallel(t)
	root := startNode(t, nodeSpec{ID: "root"})
	other := startNode(t, nodeSpec{ID: "evilroot"}) // a second tree, another signing key
	pub, pemS := qaRootPub(t, root)
	kid := auth.LinkKID(pub)
	_, evilPriv, _ := auth.GenerateLinkKey()
	evilKID := auth.LinkKID(evilPriv.Public().(ed25519.PublicKey))
	good := qaClaims("root", "evil", "root", "relay-child")

	// control: a legitimate token is accepted
	legit := root.registerChild("evil")
	if ok, why := qaLinkAccepted(root, legit); !ok {
		t.Fatalf("control failed, legit token refused: %s", why)
	}

	cases := []struct {
		name string
		tok  func() string
	}{
		{"HS256 keyed with the raw root public key", func() string { return qaForge(t, jwt.SigningMethodHS256, []byte(pub), kid, good) }},
		{"HS256 keyed with the root public key PEM", func() string { return qaForge(t, jwt.SigningMethodHS256, []byte(pemS), kid, good) }},
		{"HS256 keyed with the node legacy JWT secret", func() string {
			return qaForge(t, jwt.SigningMethodHS256, []byte(root.jwtSecret), "", qaClaims("root", "evil", "root", "relay"))
		}},
		{"HS256 legacy secret, role relay-child", func() string { return qaForge(t, jwt.SigningMethodHS256, []byte(root.jwtSecret), kid, good) }},
		{"alg none", func() string { return qaForge(t, jwt.SigningMethodNone, jwt.UnsafeAllowNoneSignatureType, kid, good) }},
		{"EdDSA by an attacker key, its own kid", func() string { return qaForge(t, jwt.SigningMethodEdDSA, evilPriv, evilKID, good) }},
		{"EdDSA by an attacker key, spoofed root kid", func() string { return qaForge(t, jwt.SigningMethodEdDSA, evilPriv, kid, good) }},
		{"EdDSA by an attacker key, unknown kid", func() string { return qaForge(t, jwt.SigningMethodEdDSA, evilPriv, "AAAAAAAAAAAAAAAAAAAAAA", good) }},
		{"EdDSA by an attacker key, no kid", func() string { return qaForge(t, jwt.SigningMethodEdDSA, evilPriv, "", good) }},
		{"EdDSA attacker key, sub==aud", func() string {
			return qaForge(t, jwt.SigningMethodEdDSA, evilPriv, kid, qaClaims("root", "root", "root", "relay-child"))
		}},
		{"real token of ANOTHER root (wrong iss + wrong key)", func() string {
			_, tk := other.admin("POST", "/api/admin/tokens", map[string]any{"role": "relay-child", "sub": "evil", "aud": "root"})
			s, _ := tk["token"].(string)
			return s
		}},
		{"root-signed token minted for another audience", func() string {
			_, tk := root.admin("POST", "/api/admin/tokens", map[string]any{"role": "relay-child", "sub": "evil", "aud": "somebody-else"})
			s, _ := tk["token"].(string)
			return s
		}},
		{"plugin token", func() string { return root.pluginToken() }},
		{"admin token", func() string { return root.adminTok }},
		{"empty bearer", func() string { return "" }},
		{"garbage", func() string { return "a.b.c" }},
	}
	for _, c := range cases {
		tok := c.tok()
		ok, why := qaLinkAccepted(root, tok)
		t.Logf("%-62s -> accepted=%v (%s)", c.name, ok, why)
		if ok {
			t.Errorf("INTRUSION SUCCEEDED: %s", c.name)
		}
	}

	// revoked token: refused after revocation, and a connected link is cut
	tokR, idR := root.registerChildWithID("victim")
	if ok, why := qaLinkAcceptedAs(root, tokR, "victim"); !ok {
		t.Fatalf("control revoked: %s", why)
	}
	c, _, err := dialRelayLink(root, tokR)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	// find the token id by sub then revoke
	id, _ := linkTokenIDBySub(t, root, "victim")
	_ = idR
	if code, m := root.admin("POST", "/api/admin/tokens/"+id+"/revoke", map[string]any{}); code != 200 {
		t.Fatalf("revoke: %d %v", code, m)
	}
	if ok, why := qaLinkAcceptedAs(root, tokR, "victim"); ok {
		t.Errorf("INTRUSION SUCCEEDED: revoked token accepted")
	} else {
		t.Logf("revoked token -> refused (%s)", why)
	}
	t.Logf("connected link after revocation closed with code %d", closeCodeOf(t, c))
	_ = os.Stdout
}

type qaLink struct {
	t *testing.T
	c *websocket.Conn
}

func (l *qaLink) send(m map[string]any) error { return l.c.WriteJSON(m) }

// readTry waits for a message of type typ; error when the link closes first.
func (l *qaLink) readTry(typ string, d time.Duration) (map[string]any, error) {
	_ = l.c.SetReadDeadline(time.Now().Add(d))
	for {
		var m map[string]any
		if err := l.c.ReadJSON(&m); err != nil {
			return nil, err
		}
		if m["type"] == typ {
			return m, nil
		}
	}
}

func qaRawChild(t *testing.T, root *node, id string) *qaLink {
	t.Helper()
	tok := root.registerChild(id)
	c, _, err := dialRelayLink(root, tok)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	l := &qaLink{t: t, c: c}
	_ = l.send(map[string]any{"type": "relay_hello", "relay_id": id, "node_type": "relay", "mode": "pull", "version": "3.0", "ancestors": []string{}})
	if _, err := l.readTry("relay_ack", 10*time.Second); err != nil {
		t.Fatalf("relay_ack: %v", err)
	}
	return l
}

// #180: a lying child cannot grant, clear or forge the suspension flag of a host that is not its own.
func TestQAIntrusion_LyingChild180(t *testing.T) {
	parallel(t)
	root := startNode(t, nodeSpec{ID: "root"})
	vic := startNode(t, nodeSpec{ID: "vic", ParentURL: root.wssURL(), ParentToken: root.registerChild("vic")})
	waitFor(t, "vic linked", func() bool { return vic.upstreamState() == "connected" })
	connectMinion(t, vic, "v-susp")
	connectMinion(t, vic, "v-ok")
	connectMinion(t, root, "r-local")
	waitFor(t, "root routes the victim hosts", func() bool { return root.hasHost("v-susp") && root.hasHost("v-ok") })
	if code, _ := vic.admin("POST", "/api/admin/minions/v-susp/suspend", map[string]any{}); code != 200 {
		t.Fatal("suspend")
	}
	waitFor(t, "root sees v-susp suspended", func() bool { return suspendedAt(root, "v-susp") })
	st := func() string {
		return fmt.Sprintf("v-susp=%v v-ok=%v r-local=%v", suspendedAt(root, "v-susp"), suspendedAt(root, "v-ok"), suspendedAt(root, "r-local"))
	}
	const want = "v-susp=true v-ok=false r-local=false"
	if st() != want {
		t.Fatalf("baseline %s", st())
	}

	// 1. snapshot declaring hosts of OTHERS with lying flags
	l1 := qaRawChild(t, root, "liar1")
	_ = l1.send(map[string]any{"type": "topology_snapshot", "relays": []any{}, "agents": []any{
		map[string]any{"hostname": "v-susp", "relay_id": "liar1", "relay_chain": []string{"liar1"}, "suspended": false},
		map[string]any{"hostname": "v-ok", "relay_id": "liar1", "relay_chain": []string{"liar1"}, "suspended": true},
		map[string]any{"hostname": "r-local", "relay_id": "liar1", "relay_chain": []string{"liar1"}, "suspended": true},
	}})
	ack, err := l1.readTry("topology_ack", 5*time.Second)
	t.Logf("1. lying snapshot over foreign hosts: ack=%v err=%v", ack != nil, err)
	time.Sleep(700 * time.Millisecond)
	t.Logf("   state after: %s", st())
	if st() != want {
		t.Errorf("AUTHORITY GRANTED to a lying snapshot: %s (want %s)", st(), want)
	}

	// 2. events on foreign hosts
	l2 := qaRawChild(t, root, "liar2")
	for _, e := range []struct{ ev, h string }{{"host.suspended", "v-ok"}, {"host.suspended", "r-local"}, {"host.resumed", "v-susp"}, {"host.suspended", "ghost"}} {
		_ = l2.send(map[string]any{"type": "event_forward", "event": e.ev, "hostname": e.h, "relay_chain": []string{"liar2"}})
	}
	time.Sleep(900 * time.Millisecond)
	t.Logf("2. forged events on foreign hosts: state %s", st())
	if st() != want {
		t.Errorf("AUTHORITY GRANTED to a lying event: %s (want %s)", st(), want)
	}
	if root.hasHost("ghost") {
		t.Errorf("an event created a host")
	}

	// 3. snapshot declaring ITS OWN host as suspended: accepted as information only, never authority
	l3 := qaRawChild(t, root, "liar3")
	_ = l3.send(map[string]any{"type": "topology_snapshot", "relays": []any{}, "agents": []any{
		map[string]any{"hostname": "own-3", "relay_id": "liar3", "relay_chain": []string{"liar3"}, "suspended": true},
	}})
	if _, err := l3.readTry("topology_ack", 5*time.Second); err != nil {
		t.Fatalf("liar3: its own flagged host snapshot must be acknowledged: %v", err)
	}
	_ = l3.send(map[string]any{"type": "agent_list", "agents": []any{map[string]any{"hostname": "own-3", "status": "connected"}}})
	waitFor(t, "own-3 routed", func() bool { return root.hasHost("own-3") })
	t.Logf("3. own host flagged: suspended=%v (informative); state of others %s", suspendedAt(root, "own-3"), st())
	done := make(chan execResult, 1)
	go func() { done <- root.exec("own-3", map[string]any{"cmd": "true", "timeout": 8}) }()
	if task, e := l3.readTry("task_dispatch", 8*time.Second); e != nil {
		t.Errorf("root did not dispatch to the lying child's flagged host: %v", e)
	} else {
		_ = l3.send(map[string]any{"type": "task_result", "task_id": task["task_id"], "rc": 0})
	}
	if r := <-done; r.Code != http.StatusOK {
		t.Errorf("exec on flagged host: %d %v", r.Code, r.Body)
	}
	if st() != want {
		t.Errorf("state drifted: %s", st())
	}
	_ = strconv.Itoa
	_ = strings.TrimSpace
	_ = os.Stdout
}

func qaRSS(pid int) float64 {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return -1
	}
	for _, l := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(l, "VmRSS:") {
			f := strings.Fields(l)
			kb, _ := strconv.Atoi(f[1])
			return float64(kb) / 1024
		}
	}
	return -1
}

// Buffers (#141 QA / 32167f8): 100 declared descendants x link_state of 1 MiB / giant kid. The memory
// of the root must not grow.
func TestQAIntrusion_LinkStateBuffersDoNotGrowTheRoot(t *testing.T) {
	root := startNode(t, nodeSpec{ID: "root", NodeBinary: buildPlainNodeBinary(t)})
	pid := root.cmd.Process.Pid
	rss := startRSSSampler(t, pid)
	connect := func(name, prefix string) *qaLink {
		var rels []any
		for i := 0; i < 100; i++ {
			id := fmt.Sprintf("%s%03d", prefix, i)
			rels = append(rels, map[string]any{"relay_id": id, "relay_chain": []string{name, id}})
		}
		l := qaRawChild(t, root, name)
		_ = l.send(map[string]any{"type": "topology_snapshot", "relays": rels, "agents": []any{}})
		if _, err := l.readTry("topology_ack", 15*time.Second); err != nil {
			t.Fatalf("%s snapshot: %v", name, err)
		}
		return l
	}
	l := connect("liar", "d")
	time.Sleep(2 * time.Second)
	before := qaRSS(pid)
	t.Logf("RSS before attack: %.1f MiB", before)

	big := strings.Repeat("A", 1<<20)
	closedAt := -1
	// (a) 100 descendants x 1 MiB kid
	for i := 0; i < 100; i++ {
		if err := l.send(map[string]any{"type": "link_state", "relay_id": fmt.Sprintf("d%03d", i), "seq": 1, "current_kid": big}); err != nil {
			closedAt = i
			t.Logf("(a) write failed at frame %d: %v", i, err)
			break
		}
	}
	time.Sleep(2 * time.Second)
	_, err := l.readTry("zzz", 2*time.Second)
	t.Logf("(a) 100 x 1 MiB kid sent; link state after: %v (closedAt=%d); RSS %.1f MiB", err, closedAt, qaRSS(pid))
	// the size limit of the link frames is what refuses a 1 MiB link_state (the kid validation is a second line of
	// defence, which alone would keep the RSS flat): the root must have said so and closed the link
	if !root.logs.has("link frame refused") {
		t.Errorf("(a) the root did not refuse the oversized link_state frame (no 'link frame refused' log):\n%s", root.logs.String())
	}

	// (b) 100 x kid just under the 512 B frame limit (invalid kid), one fresh link each time if closed
	l = connect("liar-b", "b")
	kid400 := strings.Repeat("B", 300)
	for round := 0; round < 20; round++ {
		for i := 0; i < 100; i++ {
			if err := l.send(map[string]any{"type": "link_state", "relay_id": fmt.Sprintf("b%03d", i), "seq": round + 1, "current_kid": kid400}); err != nil {
				break
			}
		}
	}
	time.Sleep(2 * time.Second)
	t.Logf("(b) 2000 x 300-char invalid kid: RSS %.1f MiB", qaRSS(pid))

	// (c) valid kids, many distinct values, 100 descendants x 100 rounds
	l = connect("liar-c", "c")
	for round := 0; round < 100; round++ {
		for i := 0; i < 100; i++ {
			var raw [16]byte
			binary.BigEndian.PutUint64(raw[8:], uint64(round*100+i))
			kid := base64.RawURLEncoding.EncodeToString(raw[:])
			if !auth.ValidLinkKID(kid) {
				t.Fatal("test kid invalid")
			}
			if err := l.send(map[string]any{"type": "link_state", "relay_id": fmt.Sprintf("c%03d", i), "seq": round + 1, "current_kid": kid}); err != nil {
				break
			}
		}
	}
	time.Sleep(2 * time.Second)
	t.Logf("(c) 10000 link_state with 22-char kids: RSS %.1f MiB", qaRSS(pid))

	// (d) one big non-link frame under the generic limit, repeated (control: the generic 10 MiB limit)
	after := qaRSS(pid)
	peak, _ := rss.finish()
	t.Logf("RSS after: %.1f MiB (before %.1f) ; peak (VmHWM/VmRSS sampler) %.1f MiB", after, before, float64(peak)/(1<<20))
	if after > before+150 {
		t.Errorf("root memory grew by %.1f MiB", after-before)
	}
	if !root.logs.has("link_state ignored") && !root.logs.has("link frame") {
		t.Logf("no refusal log seen:\n%s", root.logs.String())
	}
}
