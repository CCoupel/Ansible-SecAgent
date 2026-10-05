package hooks

import (
	"sort"
	"strings"
)

// safePath is the PATH of a shell hook: fixed, it does not depend on the server's environment.
const safePath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

// shellEnvironment builds the environment of a shell hook from an ALLOW-list; it never starts from
// the server's environment (ADMIN_TOKEN, JWT_SECRET_KEY, RSA_MASTER_KEY, REPEATER_UPSTREAM_TOKEN…
// would leak to any script). Passed on: a fixed PATH, HOME (else /nonexistent), LANG, LC_*, TZ
// taken from environ (the server's), the declared env of the action (Render'ed), and the event
// variables SECAGENT_*, which win over everything. There is deliberately no switch to turn the
// allow-list off.
func shellEnvironment(environ []string, declared map[string]string, vars map[string]string) []string {
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
