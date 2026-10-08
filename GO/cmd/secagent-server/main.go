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

// isCLIMode returns true when the binary is invoked with ANY argument. Server mode is the invocation
// WITHOUT argument (the environment drives everything). Every argument goes to the cobra CLI, which
// handles known commands, --help/-h/--version, and rejects the rest with an error and a non-zero
// exit code: an unknown or mistyped word (e.g. "kyes") never silently starts a server.
func isCLIMode() bool {
	return len(os.Args) >= 2
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
