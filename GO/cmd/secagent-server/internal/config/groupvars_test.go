package config

import (
	"errors"
	"strings"
	"testing"
)

func TestLoadGroupVars_UnsetAndEmpty(t *testing.T) {
	for _, v := range []string{"", "   ", "null"} {
		t.Setenv(EnvRelayGroupVars, v)
		m, err := LoadGroupVars()
		if err != nil || len(m) != 0 {
			t.Errorf("%q: %v %v", v, m, err)
		}
	}
}

func TestLoadGroupVars_ValidExample(t *testing.T) {
	t.Setenv(EnvRelayGroupVars, `{"env": "staging", "datacenter": "paris", "ansible_python_interpreter": "/usr/bin/python3", "ntp": ["a","b"], "limits": {"cpu": 2, "swap": false, "note": null}}`)
	m, err := LoadGroupVars()
	if err != nil {
		t.Fatal(err)
	}
	if m["env"] != "staging" || m["ansible_python_interpreter"] != "/usr/bin/python3" || len(m) != 5 {
		t.Errorf("m = %v", m)
	}
}

func TestParseGroupVars_Rejects(t *testing.T) {
	long := strings.Repeat("a", 1025)
	deep := `{"a":{"b":{"c":{"d":{"e":1}}}}}`
	var many []string
	for i := 0; i < 65; i++ {
		many = append(many, `"k`+strings.Repeat("x", i%7)+string(rune('a'+i%26))+string(rune('a'+i/26))+`":1`)
	}
	tests := []struct{ name, in string }{
		{"not JSON", `{env: staging}`},
		{"not an object", `["a"]`},
		{"string", `"x"`},
		{"trailing data", `{"a":1} {"b":2}`},
		{"bad key (dash)", `{"my-var":1}`},
		{"bad key (space)", `{"my var":1}`},
		{"bad key (leading digit)", `{"1var":1}`},
		{"ansible_connection", `{"ansible_connection":"local"}`},
		{"ansible_host", `{"ansible_host":"10.0.0.1"}`},
		{"ansible_user", `{"ansible_user":"root"}`},
		{"ansible_become_password", `{"ansible_become_password":"x"}`},
		{"ansible_ssh_common_args", `{"ansible_ssh_common_args":"-o ProxyCommand=x"}`},
		{"secagent_ namespace", `{"secagent_status":"connected"}`},
		{"interpreter relative", `{"ansible_python_interpreter":"python3"}`},
		{"interpreter with shell chars", `{"ansible_python_interpreter":"/usr/bin/python3; id"}`},
		{"interpreter not a string", `{"ansible_python_interpreter":["/usr/bin/python3"]}`},
		{"jinja expression", `{"x":"{{ lookup('pipe','id') }}"}`},
		{"jinja statement", `{"x":"{% for i in range(9) %}"}`},
		{"jinja comment", `{"x":"a{#b"}`},
		{"jinja nested in a list", `{"x":["ok","{{ 1 }}"]}`},
		{"jinja nested in an object", `{"x":{"y":"{{ 1 }}"}}`},
		{"newline in a string", "{\"x\":\"a\\nb\"}"},
		{"NUL in a string", "{\"x\":\"a\\u0000b\"}"},
		{"value too long", `{"x":"` + long + `"}`},
		{"nested too deep", deep},
		{"too many variables", "{" + strings.Join(many, ",") + "}"},
		{"bad nested key", `{"x":{"bad-key":1}}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := ParseGroupVars([]byte(tt.in))
			if err == nil {
				t.Fatalf("accepted: %v", m)
			}
			if !errors.Is(err, ErrInvalidGroupVars) {
				t.Errorf("error must wrap ErrInvalidGroupVars: %v", err)
			}
		})
	}
}

func TestParseGroupVars_TooLarge(t *testing.T) {
	var parts []string
	for i := 0; i < 30; i++ {
		parts = append(parts, `"v`+strings.Repeat("a", i)+`":"`+strings.Repeat("c", 900)+`"`)
	}
	if _, err := ParseGroupVars([]byte("{" + strings.Join(parts, ",") + "}")); err == nil {
		t.Error("a document larger than 16 KiB must be refused")
	}
}

func TestValidateGroupVars_AllowedInterpreters(t *testing.T) {
	for _, v := range []string{"auto", "auto_silent", "/usr/bin/python3", "/opt/py-3.11/bin/python"} {
		if err := ValidateGroupVars(map[string]any{"ansible_python_interpreter": v}); err != nil {
			t.Errorf("%q: %v", v, err)
		}
	}
}

func TestEncodeGroupVars(t *testing.T) {
	if s, err := EncodeGroupVars(nil); s != "" || err != nil {
		t.Errorf("nil: %q %v", s, err)
	}
	s, err := EncodeGroupVars(map[string]any{"b": 1.0, "a": "x"})
	if err != nil || s != `{"a":"x","b":1}` {
		t.Errorf("encode = %q %v (canonical, sorted keys)", s, err)
	}
	if _, err := EncodeGroupVars(map[string]any{"ansible_connection": "local"}); err == nil {
		t.Error("EncodeGroupVars must validate")
	}
}
