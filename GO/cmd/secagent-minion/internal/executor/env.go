package executor

import (
	"os"
	"runtime"
	"strings"
)

// Environment of the tasks (#186). The subprocess of a task does NOT inherit the minion's
// environment (RELAY_ENROLLMENT_TOKEN, RELAY_JWT_PATH, RELAY_PRIVATE_KEY, any *_TOKEN/_KEY/_SECRET/
// _PASSWORD of the systemd unit or container...): a playbook author or a plugin-token holder
// would read them with a plain `env`. Only an allow-list of the variables Ansible needs is passed.
//
// `environment:` of a playbook keeps working: the protocol does not carry environment variables,
// Ansible's shell plugin writes them in the command line itself (`VAR=value cmd`), which the shell
// started by /bin/sh -c interprets. become_pass travels on stdin, never in the environment.

// allowedEnvNames are copied from the minion's environment when defined there.
var allowedEnvNames = map[string]bool{
	"PATH": true, "HOME": true, "TZ": true, "USER": true, "LOGNAME": true, "SHELL": true, "TMPDIR": true, "LANG": true,
}

// DefaultPath is used when the minion itself has no PATH.
const DefaultPath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

// forbiddenEnv reports a name that is never passed, whatever the allow-list says (defence in
// depth: the allow-list is the rule, this guards against a future edit of it).
func forbiddenEnv(name string) bool {
	u := strings.ToUpper(name)
	if strings.HasPrefix(u, "RELAY_") {
		return true
	}
	for _, suffix := range []string{"_TOKEN", "_KEY", "_SECRET", "_PASSWORD", "_PASS"} {
		if strings.HasSuffix(u, suffix) {
			return true
		}
	}
	return false
}

// TaskEnv builds the environment of a task from environ ("NAME=value" entries, os.Environ()
// format): the allow-listed variables (PATH, LANG, LC_*, HOME, TZ, USER, LOGNAME, SHELL, TMPDIR)
// that are defined, a default PATH when there is none, and nothing else.
func TaskEnv(environ []string) []string {
	var out []string
	havePath := false
	for _, kv := range environ {
		name, _, ok := strings.Cut(kv, "=")
		if !ok || name == "" || forbiddenEnv(name) {
			continue
		}
		if allowedEnvNames[name] || strings.HasPrefix(name, "LC_") {
			out = append(out, kv)
			if name == "PATH" {
				havePath = true
			}
		}
	}
	if !havePath && runtime.GOOS != "windows" {
		out = append(out, "PATH="+DefaultPath)
	}
	return out
}

// hostEnv is the minion's environment (a variable so that tests can feed a fixed one).
var hostEnv = os.Environ
