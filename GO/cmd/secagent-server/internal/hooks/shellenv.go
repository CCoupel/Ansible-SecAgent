package hooks

import (
	"sort"
	"strings"
)

// safePath is the PATH of a shell hook: fixed, it does not depend on the server's environment.
const safePath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

// sanitizeEnvValue replaces every control character (below 0x20, so newline, NUL, ESC…, and 0x7F)
// by "_": an agent-controlled value (a hostname such as "a\nB=c") can neither add a variable nor
// make the process start fail (NUL). Only the event data is sanitised, never a value the operator
// declared in env.
func sanitizeEnvValue(v string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return '_'
		}
		return r
	}, v)
}

func sanitizeVars(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = sanitizeEnvValue(v)
	}
	return out
}

// shellEnvironment builds the environment of a shell hook from an ALLOW-list; it never starts from
// the server's environment (ADMIN_TOKEN, JWT_SECRET_KEY, RSA_MASTER_KEY, REPEATER_UPSTREAM_TOKEN…
// would leak to any script). Passed on: a fixed PATH, HOME (else /nonexistent), LANG, LC_*, TZ
// taken from environ (the server's), the declared env of the action (Render'ed), and the event
// variables SECAGENT_*, which win over everything. There is deliberately no switch to turn the
// allow-list off.
func shellEnvironment(environ []string, declared map[string]string, rawVars map[string]string) []string {
	vars := sanitizeVars(rawVars)
	out := map[string]string{"PATH": safePath, "HOME": "/nonexistent"}
	for _, kv := range environ {
		name, value, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		if name == "HOME" || name == "LANG" || name == "TZ" || strings.HasPrefix(name, "LC_") {
			out[name] = value
		}
	}
	for name, value := range declared {
		out[name] = Render(value, vars)
	}
	out["SECAGENT_EVENT"] = vars["event"]
	out["SECAGENT_HOSTNAME"] = vars["hostname"]
	out["SECAGENT_TIMESTAMP"] = vars["timestamp"]
	out["SECAGENT_STATUS"] = vars["status"]
	if ea := vars["enrolled_at"]; ea != "" {
		out["SECAGENT_ENROLLED_AT"] = ea
	}
	if rc := vars["relay_chain"]; rc != "" {
		out["SECAGENT_RELAY_CHAIN"] = rc
		out["SECAGENT_RELAY_ORIGIN"] = vars["relay_origin"]
	}
	names := make([]string, 0, len(out))
	for n := range out {
		names = append(names, n)
	}
	sort.Strings(names)
	env := make([]string, 0, len(names))
	for _, n := range names {
		env = append(env, n+"="+out[n])
	}
	return env
}
