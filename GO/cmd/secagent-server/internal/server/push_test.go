package server

import (
	"log"
	"os"
	"strings"
	"testing"
	"time"

	"secagent-server/cmd/secagent-server/internal/handlers"
	"secagent-server/cmd/secagent-server/internal/repeater"
	"secagent-server/cmd/secagent-server/internal/storage"
)

type fakePushStarter struct {
	targets []repeater.DialTarget
	err     error
}

func (f *fakePushStarter) Start(t repeater.DialTarget) error {
	if f.err != nil {
		return f.err
	}
	f.targets = append(f.targets, t)
	return nil
}

func seedRelay(t *testing.T, st *storage.Store, id, mode, url, tokenField string) {
	t.Helper()
	var urls []string
	if url != "" {
		urls = strings.Split(url, ",")
	}
	n := storage.RelayNode{ID: "uuid-" + id, RelayID: id, Mode: mode, URLs: urls, CreatedAt: time.Now().Unix(), Status: "disconnected"}
	if mode == "push" {
		n.TokenSecret = tokenField // the sealed token: the state refuses anything else
	} else {
		n.TokenHash = tokenField
	}
	if err := st.UpsertRelayNode(n); err != nil {
		t.Fatal(err)
	}
}

func TestStartPushDialers_OnlyPushNodesWithASealedToken(t *testing.T) {
	t.Setenv("RSA_MASTER_KEY", "main-test-master-key")
	st, err := storage.OpenTemp()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()

	sealed, err := handlers.SealPushToken("dmz1", "child-jwt")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(sealed, "child-jwt") {
		t.Fatal("token not sealed")
	}
	seedRelay(t, st, "dmz1", "push", "wss://dmz1:7772", sealed)
	seedRelay(t, st, "pull1", "pull", "", "sha256-of-jwt")

	f := &fakePushStarter{}
	startPushDialers(st, f)

	got := map[string]repeater.DialTarget{}
	for _, tg := range f.targets {
		got[tg.RelayID] = tg
	}
	if len(got) != 1 || got["dmz1"].Token != "child-jwt" || len(got["dmz1"].URLs) != 1 || got["dmz1"].URLs[0] != "wss://dmz1:7772" {
		t.Errorf("targets = %+v", got)
	}
	if _, ok := got["pull1"]; ok {
		t.Error("pull relays must not be dialed")
	}
}

func TestStartPushDialers_SkipsUndecryptableAndInvalidRows(t *testing.T) {
	st, err := storage.OpenTemp()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()

	t.Setenv("RSA_MASTER_KEY", "k1")
	sealed, _ := handlers.SealPushToken("dmz1", "child-jwt")
	t.Setenv("RSA_MASTER_KEY", "") // key lost: the sealed row cannot be opened
	seedRelay(t, st, "dmz1", "push", "wss://dmz1:7772", sealed)

	f := &fakePushStarter{}
	startPushDialers(st, f)
	if len(f.targets) != 0 {
		t.Errorf("an undecryptable row must be skipped, got %+v", f.targets)
	}
}

// validatingStarter refuses what repeater.ValidateDialTarget refuses, like the real dialer manager.
type validatingStarter struct{ started []string }

func (v *validatingStarter) Start(t repeater.DialTarget) error {
	if err := repeater.ValidateDialTarget(t); err != nil {
		return err
	}
	v.started = append(v.started, t.RelayID)
	return nil
}

func TestStartPushDialers_ForbiddenStoredAddressIsNeverDialed(t *testing.T) {
	t.Setenv("RSA_MASTER_KEY", "main-test-master-key")
	st, err := storage.OpenTemp()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	for _, id := range []string{"bad", "good"} {
		sealed, err := handlers.SealPushToken(id, "child-jwt")
		if err != nil {
			t.Fatal(err)
		}
		urls := "wss://10.1.2.3:7772"
		if id == "bad" {
			urls = "wss://10.1.2.3:7772,wss://169.254.169.254:7772" // one forbidden address refuses the whole list
		}
		seedRelay(t, st, id, "push", urls, sealed)
	}
	var out strings.Builder
	log.SetOutput(&out)
	defer log.SetOutput(os.Stderr)

	v := &validatingStarter{}
	startPushDialers(st, v)

	if len(v.started) != 1 || v.started[0] != "good" {
		t.Fatalf("started = %v, want only \"good\"", v.started)
	}
	if !strings.Contains(out.String(), "[SECURITY WARNING]") || !strings.Contains(out.String(), `"bad"`) {
		t.Errorf("a security warning naming the relay is expected, got: %s", out.String())
	}
	if strings.Contains(out.String(), "169.254.169.254") {
		t.Errorf("the forbidden address must not be logged: %s", out.String())
	}
}
