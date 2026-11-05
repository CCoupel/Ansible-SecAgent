// SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
// SPDX-License-Identifier: AGPL-3.0-or-later

package hooks

// Tests de LoadConfig — désérialisation du fichier hooks.json
//
// Référence : DOC/server/HOOKS_SPEC.md §2
//
// Ce fichier compile une fois que config.go est implémenté (tâche dev-relay).
// Types attendus :
//   HooksConfig  { Hooks []HookDef }
//   HookDef      { Event string; Actions []ActionDef }
//   ActionDef    { Type, URL, Secret, Cmd, Args, Path, Append, Method, Headers, Body,
//                  MaxRetries, TimeoutSeconds string/int }
//   LoadConfig(path string) (*HooksConfig, error)

import (
	"os"
	"path/filepath"
	"testing"
)

// ========================================================================
// TestLoadConfig_missing
// Fichier absent → (nil, nil) — pas d'erreur, démarrage silencieux
// ========================================================================

func TestLoadConfig_missing(t *testing.T) {
	cfg, err := LoadConfig("/nonexistent/hooks/file.json")
	if err != nil {
		t.Errorf("expected nil error for missing file, got %v", err)
	}
	if cfg != nil {
		t.Errorf("expected nil config for missing file, got %+v", cfg)
	}
}

// ========================================================================
// TestLoadConfig_invalid_json
// JSON invalide → erreur non nil
// ========================================================================

func TestLoadConfig_invalid_json(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hooks.json")
	if err := os.WriteFile(path, []byte("{invalid json here"), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	_, err := LoadConfig(path)
	if err == nil {
		t.Error("expected error for invalid JSON, got nil")
	}
}

// ========================================================================
// TestLoadConfig_valid_minimal
// {"hooks": []} → HooksConfig valide, Hooks non nil, longueur 0
// ========================================================================

func TestLoadConfig_valid_minimal(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hooks.json")
	if err := os.WriteFile(path, []byte(`{"hooks": []}`), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil config, got nil")
	}
	if len(cfg.Hooks) != 0 {
		t.Errorf("expected 0 hooks, got %d", len(cfg.Hooks))
	}
}

// ========================================================================
// TestLoadConfig_valid_full
// Config avec 4 types d'actions sur un seul hook host.new — vérification de tous les champs
// ========================================================================

func TestLoadConfig_valid_full(t *testing.T) {
	const raw = `{
		"hooks": [
			{
				"event": "host.new",
				"actions": [
					{
						"type":            "webhook",
						"url":             "https://cmdb.internal/api/assets",
						"secret":          "hmac-key-prod",
						"max_retries":     3,
						"timeout_seconds": 10
					},
					{
						"type":            "shell",
						"cmd":             "/opt/secagent/hooks/register.sh",
						"args":            ["{{hostname}}", "{{event}}"],
						"timeout_seconds": 30
					},
					{
						"type":   "file",
						"path":   "/var/log/secagent/events.log",
						"append": "{{timestamp}} NEW {{hostname}}\n"
					},
					{
						"type":            "api",
						"method":          "PATCH",
						"url":             "http://monitoring.internal/hosts/{{hostname}}",
						"headers":         { "X-Api-Key": "secret123" },
						"body":            { "status": "{{status}}", "seen_at": "{{timestamp}}" },
						"max_retries":     1,
						"timeout_seconds": 5
					}
				]
			}
		]
	}`

	dir := t.TempDir()
	path := filepath.Join(dir, "hooks.json")
	if err := os.WriteFile(path, []byte(raw), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
	if len(cfg.Hooks) != 1 {
		t.Fatalf("expected 1 hook, got %d", len(cfg.Hooks))
	}

	hook := cfg.Hooks[0]
	if hook.Event != "host.new" {
		t.Errorf("hook.event: got %q, want %q", hook.Event, "host.new")
	}
	if len(hook.Actions) != 4 {
		t.Fatalf("expected 4 actions, got %d", len(hook.Actions))
	}

	// ---- action[0] : webhook
	wh := hook.Actions[0]
	if wh.Type != "webhook" {
		t.Errorf("action[0].type: got %q, want webhook", wh.Type)
	}
	if wh.URL != "https://cmdb.internal/api/assets" {
		t.Errorf("action[0].url: got %q", wh.URL)
	}
	if wh.Secret != "hmac-key-prod" {
		t.Errorf("action[0].secret: got %q", wh.Secret)
	}
	if wh.MaxRetries != 3 {
		t.Errorf("action[0].max_retries: got %d, want 3", wh.MaxRetries)
	}
	if wh.TimeoutSeconds != 10 {
		t.Errorf("action[0].timeout_seconds: got %d, want 10", wh.TimeoutSeconds)
	}

	// ---- action[1] : shell
	sh := hook.Actions[1]
	if sh.Type != "shell" {
		t.Errorf("action[1].type: got %q, want shell", sh.Type)
	}
	if sh.Cmd != "/opt/secagent/hooks/register.sh" {
		t.Errorf("action[1].cmd: got %q", sh.Cmd)
	}
	if len(sh.Args) != 2 || sh.Args[0] != "{{hostname}}" || sh.Args[1] != "{{event}}" {
		t.Errorf("action[1].args: got %v", sh.Args)
	}
	if sh.TimeoutSeconds != 30 {
		t.Errorf("action[1].timeout_seconds: got %d, want 30", sh.TimeoutSeconds)
	}

	// ---- action[2] : file
	f := hook.Actions[2]
	if f.Type != "file" {
		t.Errorf("action[2].type: got %q, want file", f.Type)
	}
	if f.Path != "/var/log/secagent/events.log" {
		t.Errorf("action[2].path: got %q", f.Path)
	}
	if f.Append != "{{timestamp}} NEW {{hostname}}\n" {
		t.Errorf("action[2].append: got %q", f.Append)
	}

	// ---- action[3] : api
	api := hook.Actions[3]
	if api.Type != "api" {
		t.Errorf("action[3].type: got %q, want api", api.Type)
	}
	if api.Method != "PATCH" {
		t.Errorf("action[3].method: got %q, want PATCH", api.Method)
	}
	if api.URL != "http://monitoring.internal/hosts/{{hostname}}" {
		t.Errorf("action[3].url: got %q", api.URL)
	}
	if api.Headers["X-Api-Key"] != "secret123" {
		t.Errorf("action[3].headers[X-Api-Key]: got %q", api.Headers["X-Api-Key"])
	}
	if api.MaxRetries != 1 {
		t.Errorf("action[3].max_retries: got %d, want 1", api.MaxRetries)
	}
	if api.TimeoutSeconds != 5 {
		t.Errorf("action[3].timeout_seconds: got %d, want 5", api.TimeoutSeconds)
	}
}

// ========================================================================
// TestLoadConfig_unknown_fields
// Champs inconnus dans le JSON ignorés — pas d'erreur, struct correctement initialisée
// ========================================================================

func TestLoadConfig_unknown_fields(t *testing.T) {
	const raw = `{
		"hooks": [],
		"version": "2",
		"unknown_field": 42,
		"extra": { "nested": true }
	}`

	dir := t.TempDir()
	path := filepath.Join(dir, "hooks.json")
	if err := os.WriteFile(path, []byte(raw), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("expected no error for unknown fields, got %v", err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
	if len(cfg.Hooks) != 0 {
		t.Errorf("expected 0 hooks (unknown fields ignored), got %d", len(cfg.Hooks))
	}
}

// ========================================================================
// TestLoadConfig_multiple_hooks
// Config avec plusieurs events — chaque hook correctement mappé
// ========================================================================

func TestLoadConfig_multiple_hooks(t *testing.T) {
	const raw = `{
		"hooks": [
			{ "event": "host.new",     "actions": [{ "type": "file", "path": "/tmp/a", "append": "a" }] },
			{ "event": "host.up",      "actions": [{ "type": "file", "path": "/tmp/b", "append": "b" }] },
			{ "event": "host.down",    "actions": [{ "type": "file", "path": "/tmp/c", "append": "c" }] },
			{ "event": "host.revoked", "actions": [{ "type": "file", "path": "/tmp/d", "append": "d" }] },
			{ "event": "host.deleted", "actions": [{ "type": "file", "path": "/tmp/e", "append": "e" }] }
		]
	}`

	dir := t.TempDir()
	path := filepath.Join(dir, "hooks.json")
	if err := os.WriteFile(path, []byte(raw), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
	if len(cfg.Hooks) != 5 {
		t.Errorf("expected 5 hooks, got %d", len(cfg.Hooks))
	}

	events := make(map[string]bool)
	for _, h := range cfg.Hooks {
		events[h.Event] = true
	}
	for _, want := range []string{"host.new", "host.up", "host.down", "host.revoked", "host.deleted"} {
		if !events[want] {
			t.Errorf("expected event %q in config, not found", want)
		}
	}
}
