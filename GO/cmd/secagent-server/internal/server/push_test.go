package server

import (
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
	if err := st.UpsertRelayNode(storage.RelayNode{
		ID: "uuid-" + id, RelayID: id, Mode: mode, URL: url, TokenHash: tokenField,
		CreatedAt: time.Now().Unix(), Status: "disconnected",
	}); err != nil {
		t.Fatal(err)
	}
}

func TestStartPushDialers_OnlyPushNodesWithClearToken(t *testing.T) {
	t.Setenv("RSA_MASTER_KEY", "main-test-master-key")
	st, err := storage.NewStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()

	sealed, err := handlers.SealPushToken("child-jwt")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(sealed, "child-jwt") {
		t.Fatal("token not sealed")
	}
	seedRelay(t, st, "dmz1", "push", "wss://dmz1:7772", sealed)
	seedRelay(t, st, "dmz2", "push", "wss://dmz2:7772", "legacy-plain")
	seedRelay(t, st, "pull1", "pull", "", "sha256-of-jwt")

	f := &fakePushStarter{}
	startPushDialers(st, f)

	got := map[string]repeater.DialTarget{}
	for _, tg := range f.targets {
		got[tg.RelayID] = tg
	}
	if len(got) != 2 || got["dmz1"].Token != "child-jwt" || got["dmz1"].URL != "wss://dmz1:7772" ||
		got["dmz2"].Token != "legacy-plain" {
		t.Errorf("targets = %+v", got)
	}
	if _, ok := got["pull1"]; ok {
		t.Error("pull relays must not be dialed")
	}
}

func TestStartPushDialers_SkipsUndecryptableAndInvalidRows(t *testing.T) {
	st, err := storage.NewStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()

	t.Setenv("RSA_MASTER_KEY", "k1")
	sealed, _ := handlers.SealPushToken("child-jwt")
	t.Setenv("RSA_MASTER_KEY", "") // key lost: the sealed row cannot be opened
	seedRelay(t, st, "dmz1", "push", "wss://dmz1:7772", sealed)

	f := &fakePushStarter{}
	startPushDialers(st, f)
	if len(f.targets) != 0 {
		t.Errorf("an undecryptable row must be skipped, got %+v", f.targets)
	}
}
