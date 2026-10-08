package main

import (
	"fmt"
	"io"
)

// Version is printed by --version. Override at build time with
//
//	-ldflags "-X main.Version=X.Y.Z"
//
// (the symbol is main.Version: this is the main package of cmd/secagent-minion).
var Version = "dev"

const usageText = `secagent-minion — Ansible-SecAgent agent daemon.

Usage:
  secagent-minion              start the agent (everything is driven by the environment)
  secagent-minion --version    print the version and exit
  secagent-minion --help       print this help and exit

The agent takes no other argument.

Environment variables:
  RELAY_SERVER_URL         HTTPS URL(s) of the relay server (default: https://localhost:7770; comma separated list)
  RELAY_WS_URL             WSS URL(s) of the relay server (default: wss://localhost:7772/ws/agent; same length as RELAY_SERVER_URL)
  RELAY_AGENT_HOSTNAME     Agent hostname (default: os.Hostname())
  RELAY_PRIVATE_KEY        RSA private key path (default: /etc/secagent-minion/id_rsa)
  RELAY_JWT_PATH           Persisted JWT path (default: /etc/secagent-minion/token.jwt)
  RELAY_ENROLLMENT_TOKEN   Enrollment token (required for the first start), or RELAY_ENROLLMENT_TOKEN_FILE (path of a 0600 file)
  RELAY_CA_BUNDLE          Custom CA bundle (PEM; default: system store)
  RELAY_ASYNC_DIR          Async registry directory (default: /var/lib/secagent-minion/async)
  RELAY_INSECURE_TLS       "true" disables TLS verification (tests only)
  MAX_CONCURRENT_TASKS     Simultaneous exec tasks (default: 10)
`

// handleArgs applies the command line contract BEFORE anything is initialised (no log line, no
// configuration, no secret read, no key generated):
//   - no argument: proceed (the agent starts, the environment drives everything);
//   - exactly --version / -v: print "secagent-minion version <Version>" and stop (exit 0);
//   - exactly --help / -h: print the help and stop (exit 0);
//   - anything else (unknown word, flag, number, or several arguments): error on stderr + help, stop
//     with exit code 1. The offending argument is never echoed (it could be a secret).
//
// proceed=false means main must exit with code.
func handleArgs(args []string, stdout, stderr io.Writer) (proceed bool, code int) {
	if len(args) == 0 {
		return true, 0
	}
	if len(args) == 1 {
		switch args[0] {
		case "--version", "-v":
			_, _ = fmt.Fprintf(stdout, "secagent-minion version %s\n", Version)
			return false, 0
		case "--help", "-h":
			_, _ = fmt.Fprint(stdout, usageText)
			return false, 0
		}
	}
	_, _ = fmt.Fprintf(stderr, "secagent-minion: unexpected argument(s) (%d given): the agent is configured by environment variables only; accepted: --version, --help\n\n", len(args))
	_, _ = fmt.Fprint(stderr, usageText)
	return false, 1
}
