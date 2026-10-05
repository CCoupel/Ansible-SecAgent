package hooks

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"secagent-server/cmd/secagent-server/internal/actionlog"
)

// Every json field of ActionDef must be classified for the audit journal. RedactAction is secure
// by default (an unlisted field is masked), but a field added to ActionDef must be a CONSCIOUS
// choice: kept in clear (and added to actionlog.keptActionFields) or masked (and added here).
func TestRedactActionClassifiesEveryActionField(t *testing.T) {
	const (
		kept    = "kept"    // written as is
		masked  = "masked"  // value replaced by actionlog.Mask
		special = "special" // dedicated rule (url, headers)
	)
	classes := map[string]string{
		"type": kept, "method": kept, "cmd": kept, "path": kept, "max_retries": kept, "timeout_seconds": kept,
		"url": special, "headers": special, "env": special, "args": special,
		"secret": masked, "body": masked, "append": masked,
	}

	// the actionlog allow-list and this table must agree
	for _, f := range actionlog.KeptActionFields() {
		if classes[f] != kept {
			t.Errorf("actionlog keeps %q but this table does not classify it as kept", f)
		}
	}

	typ := reflect.TypeOf(ActionDef{})
	m := map[string]any{}
	for i := 0; i < typ.NumField(); i++ {
		name := strings.Split(typ.Field(i).Tag.Get("json"), ",")[0]
		if name == "" || name == "-" {
			t.Fatalf("field %s has no json name", typ.Field(i).Name)
		}
		if _, ok := classes[name]; !ok {
			t.Errorf("ActionDef field %q is not classified: add it to the kept list of actionlog (no secret) or to this table as masked", name)
			continue
		}
		switch typ.Field(i).Type.Kind() {
		case reflect.String:
			m[name] = "SENTINEL-" + name
		case reflect.Int:
			m[name] = 424242
		case reflect.Map:
			m[name] = map[string]any{"K": "SENTINEL-" + name}
		case reflect.Slice:
			m[name] = []any{"SENTINEL-" + name}
		default:
			m[name] = "SENTINEL-" + name
		}
		if name == "url" {
			m[name] = "https://h.example/p?q=SENTINEL-url"
		}
	}
	raw, _ := json.Marshal(m)
	out := actionlog.RedactAction(raw)
	for name, c := range classes {
		if _, present := m[name]; !present {
			continue
		}
		leaked := strings.Contains(out, "SENTINEL-"+name)
		switch c {
		case masked, special:
			if leaked {
				t.Errorf("field %q must be masked: %s", name, out)
			}
		case kept:
			if reflect.TypeOf(m[name]).Kind() == reflect.String && !leaked {
				t.Errorf("field %q must be kept: %s", name, out)
			}
		}
	}
	if strings.Contains(out, "q=SENTINEL") {
		t.Errorf("url query leaks: %s", out)
	}
}
