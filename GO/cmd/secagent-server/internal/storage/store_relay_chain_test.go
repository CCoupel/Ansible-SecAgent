package storage

import (
	"reflect"
	"testing"
)

func TestRelayChain_SetListClear(t *testing.T) {
	s, err := NewStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	if ok, err := s.SetRelayChain("ghost", []string{"a"}); ok || err != nil {
		t.Errorf("unknown relay: %v %v", ok, err)
	}
	for _, id := range []string{"r2", "r3"} {
		if err := s.UpsertRelayNode(RelayNode{ID: "id-" + id, RelayID: id, Mode: "pull", Status: "connected"}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.SetRelayChain("r3", []string{"r2", "r3"}); err != nil {
		t.Fatal(err)
	}
	got, err := s.ListRelayChains()
	if err != nil || !reflect.DeepEqual(got, map[string][]string{"r3": {"r2", "r3"}}) {
		t.Fatalf("chains = %v %v", got, err)
	}
	if _, err := s.SetRelayChain("r3", nil); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.ListRelayChains(); len(got) != 0 {
		t.Errorf("cleared chain still listed: %v", got)
	}
}
