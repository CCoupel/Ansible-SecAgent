// Command secagent-server is both the Ansible-SecAgent server and its admin CLI.
// main() only reads the environment and runs the server; the wiring lives in
// internal/server so that the real start-up sequence is testable (#155).
package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"secagent-server/cmd/secagent-server/internal/cli"
	"secagent-server/cmd/secagent-server/internal/server"
)

// isCLIMode returns true when the binary is invoked as a CLI tool.
// CLI mode is active when the first argument is a known subcommand (not a server flag).
// Server flags start with "-" or are absent.
func isCLIMode() bool {
	if len(os.Args) < 2 {
		return false
	}
	first := os.Args[1]
	// Server mode flags start with "-" (e.g. -d, --config)
	if len(first) > 0 && first[0] == '-' {
		return false
	}
	// Known CLI top-level commands
	switch first {
	case "minions", "security", "inventory", "server", "tokens", "hooks", "relays", "state", "status", "help", "completion":
		return true
	}
	return false
}

func main() {
	// Dual-mode: CLI or server
	if isCLIMode() {
		cli.Execute()
		return
	}

	// environment → Config → lock loop → build → run → exit code (internal/server.RunInstance)
	cfg, err := server.ConfigFromEnv()
	if err != nil {
		log.Fatal(err)
	}

	// SIGTERM / SIGINT → graceful shutdown, then the lock is released
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	// SIGHUP → hot-reload hooks config (the node exists once this instance is the master)
	sighup := make(chan os.Signal, 1)
	signal.Notify(sighup, syscall.SIGHUP)
	go func() {
		for range sighup {
			server.ReloadHooksOfCurrentNode()
		}
	}()

	code, err := server.RunInstance(ctx, cfg)
	if err != nil {
		log.Print(err)
	}
	stop()
	os.Exit(code)
}
