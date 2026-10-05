package storage

import (
	"testing"
)

func TestRelayGroupVars_StoreListClear(t *testing.T) {
	s := newRelayTestStore(t)
	seedNodes(t, s, "dmz1", "dmz2")
	if ok, err := s.SetRelayGroupVars("dmz1", `{"env":"staging"}`); err != nil || !ok {
		t.Fatalf("set: %v %v", ok, err)
	}
	if ok, _ := s.SetRelayGroupVars("ghost", `{"a":1}`); ok {
		t.Error("an unknown relay must report false")
	}
	got, err := s.ListRelayGroupVars()
	if err != nil || len(got) != 1 || got["dmz1"] != `{"env":"staging"}` {
		t.Fatalf("list = %v %v", got, err)
	}
	if _, err := s.SetRelayGroupVars("dmz1", ""); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.ListRelayGroupVars(); len(got) != 0 {
		t.Errorf("cleared vars still listed: %v", got)
	}
}
