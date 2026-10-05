package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"unicode/utf8"
)

// EnvRelayGroupVars holds the Ansible group variables of this relay (JSON object).
const EnvRelayGroupVars = "RELAY_GROUP_VARS"

// Limits applied to group vars, whether they come from the local environment or from a remote relay.
const (
	maxGroupVarKeys    = 64
	maxGroupVarsBytes  = 16 * 1024
	maxGroupVarString  = 1024
	maxGroupVarDepth   = 4
	maxGroupVarListLen = 64
)

var (
	groupVarKeyPattern    = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}$`)
	pythonInterpreterExpr = regexp.MustCompile(`^(auto|auto_silent|/[A-Za-z0-9_./+-]{1,200})$`)
)

// ErrInvalidGroupVars wraps every validation failure.
var ErrInvalidGroupVars = errors.New("invalid group vars")

// LoadGroupVars reads RELAY_GROUP_VARS. An unset / empty variable gives (nil, nil); invalid JSON
// or content that does not validate is an error (the server refuses to start).
func LoadGroupVars() (map[string]any, error) {
	raw := strings.TrimSpace(os.Getenv(EnvRelayGroupVars))
	if raw == "" {
		return nil, nil
	}
	return ParseGroupVars([]byte(raw))
}

// ParseGroupVars decodes and validates a JSON object of group vars.
func ParseGroupVars(data []byte) (map[string]any, error) {
	if len(data) > maxGroupVarsBytes {
		return nil, fmt.Errorf("%w: larger than %d bytes", ErrInvalidGroupVars, maxGroupVarsBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("%w: %s must be a JSON object: %v", ErrInvalidGroupVars, EnvRelayGroupVars, err)
	}
	if dec.More() {
		return nil, fmt.Errorf("%w: trailing data after the JSON object", ErrInvalidGroupVars)
	}
	if m == nil {
		return nil, nil // JSON null
	}
	if err := ValidateGroupVars(m); err != nil {
		return nil, err
	}
	return m, nil
}

// validInterpreter accepts auto, auto_silent or a clean absolute path: no "." / ".." / empty
// component (path traversal such as /usr/bin/../../tmp/x, double or trailing slash).
func validInterpreter(s string) bool {
	if !pythonInterpreterExpr.MatchString(s) {
		return false
	}
	if !strings.HasPrefix(s, "/") {
		return true // auto / auto_silent
	}
	for _, c := range strings.Split(s[1:], "/") {
		if c == "" || c == "." || c == ".." {
			return false
		}
	}
	return true
}

// ValidateGroupVars checks the variables a relay may publish for its Ansible group. They end up in
// the inventory consumed by Ansible on the controller, so the rules are strict:
//   - keys are plain identifiers; connection / privilege / delegation variables (ansible_*, except
//     ansible_python_interpreter) and the secagent_* namespace are reserved;
//   - string values cannot contain Jinja markers ({{ {% {#): a remote relay must not be able to make
//     the controller evaluate a template (lookups run on the controller);
//   - no control characters, bounded sizes and nesting.
func ValidateGroupVars(m map[string]any) error {
	if len(m) > maxGroupVarKeys {
		return fmt.Errorf("%w: more than %d variables", ErrInvalidGroupVars, maxGroupVarKeys)
	}
	for k, v := range m {
		if !groupVarKeyPattern.MatchString(k) {
			return fmt.Errorf("%w: invalid variable name %q", ErrInvalidGroupVars, k)
		}
		if strings.HasPrefix(k, "secagent_") {
			return fmt.Errorf("%w: variable %q is in the reserved secagent_ namespace", ErrInvalidGroupVars, k)
		}
		if strings.HasPrefix(k, "ansible_") {
			if k != "ansible_python_interpreter" {
				return fmt.Errorf("%w: variable %q is reserved (connection / privilege settings cannot be set by a relay)", ErrInvalidGroupVars, k)
			}
			s, ok := v.(string)
			if !ok || !validInterpreter(s) {
				return fmt.Errorf("%w: ansible_python_interpreter must be an absolute path, auto or auto_silent", ErrInvalidGroupVars)
			}
		}
		if err := validateGroupVarValue(k, v, 1); err != nil {
			return err
		}
	}
	enc, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidGroupVars, err)
	}
	if len(enc) > maxGroupVarsBytes {
		return fmt.Errorf("%w: larger than %d bytes", ErrInvalidGroupVars, maxGroupVarsBytes)
	}
	return nil
}

func validateGroupVarValue(name string, v any, depth int) error {
	if depth > maxGroupVarDepth {
		return fmt.Errorf("%w: %q is nested deeper than %d levels", ErrInvalidGroupVars, name, maxGroupVarDepth)
	}
	switch x := v.(type) {
	case nil, bool, float64:
		return nil
	case string:
		if len(x) > maxGroupVarString {
			return fmt.Errorf("%w: %q has a value longer than %d bytes", ErrInvalidGroupVars, name, maxGroupVarString)
		}
		if !utf8.ValidString(x) {
			return fmt.Errorf("%w: %q is not valid UTF-8", ErrInvalidGroupVars, name)
		}
		for _, r := range x {
			if r < 0x20 || r == 0x7f {
				return fmt.Errorf("%w: %q contains a control character", ErrInvalidGroupVars, name)
			}
		}
		if strings.Contains(x, "{{") || strings.Contains(x, "{%") || strings.Contains(x, "{#") {
			return fmt.Errorf("%w: %q contains a template marker (templating is not allowed in relay group vars)", ErrInvalidGroupVars, name)
		}
		return nil
	case []any:
		if len(x) > maxGroupVarListLen {
			return fmt.Errorf("%w: %q has more than %d elements", ErrInvalidGroupVars, name, maxGroupVarListLen)
		}
		for _, e := range x {
			if err := validateGroupVarValue(name, e, depth+1); err != nil {
				return err
			}
		}
		return nil
	case map[string]any:
		if len(x) > maxGroupVarKeys {
			return fmt.Errorf("%w: %q has more than %d keys", ErrInvalidGroupVars, name, maxGroupVarKeys)
		}
		for k, e := range x {
			if !groupVarKeyPattern.MatchString(k) {
				return fmt.Errorf("%w: invalid key %q inside %q", ErrInvalidGroupVars, k, name)
			}
			if err := validateGroupVarValue(name+"."+k, e, depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	return fmt.Errorf("%w: %q has an unsupported value type", ErrInvalidGroupVars, name)
}

// EncodeGroupVars returns the canonical JSON of validated group vars ("" for none).
func EncodeGroupVars(m map[string]any) (string, error) {
	if len(m) == 0 {
		return "", nil
	}
	if err := ValidateGroupVars(m); err != nil {
		return "", err
	}
	b, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
