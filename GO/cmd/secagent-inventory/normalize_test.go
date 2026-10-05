package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func marshalInv(t *testing.T, inv AnsibleInventory) (string, map[string]json.RawMessage) {
	t.Helper()
	b, err := json.Marshal(inv)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	return string(b), doc
}

func TestMarshalNoNullAnywhere(t *testing.T) {
	tests := []struct {
		name string
		inv  AnsibleInventory
		want map[string]string // groupe -> JSON attendu
	}{
		{"groupe sans hôte", AnsibleInventory{Groups: map[string]AnsibleGroup{"root": {Children: []string{"relay1"}}}},
			map[string]string{"root": `{"hosts":[],"children":["relay1"]}`}},
		{"children seulement + hosts vide non-nil", AnsibleInventory{Groups: map[string]AnsibleGroup{"r": {Hosts: []string{}, Children: []string{"c"}}}},
			map[string]string{"r": `{"hosts":[],"children":["c"]}`}},
		{"groupe vide", AnsibleInventory{Groups: map[string]AnsibleGroup{"empty": {}}},
			map[string]string{"empty": `{"hosts":[]}`}},
		{"vars vide omis", AnsibleInventory{Groups: map[string]AnsibleGroup{"g": {Hosts: []string{"h"}, Vars: map[string]json.RawMessage{}}}},
			map[string]string{"g": `{"hosts":["h"]}`}},
		{"inventaire vide", AnsibleInventory{},
			map[string]string{"all": `{"hosts":[]}`}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, doc := marshalInv(t, tt.inv)
			if strings.Contains(s, "null") {
				t.Errorf("null in output: %s", s)
			}
			if string(doc["_meta"]) != `{"hostvars":{}}` {
				t.Errorf("_meta = %s", doc["_meta"])
			}
			for g, w := range tt.want {
				if string(doc[g]) != w {
					t.Errorf("group %s = %s, want %s", g, doc[g], w)
				}
			}
		})
	}
}

func TestMarshalNullHostvarBecomesObject(t *testing.T) {
	inv := AnsibleInventory{Meta: AnsibleMeta{Hostvars: map[string]json.RawMessage{"h": json.RawMessage("null")}}}
	s, _ := marshalInv(t, inv)
	if strings.Contains(s, "null") {
		t.Errorf("null in output: %s", s)
	}
}
