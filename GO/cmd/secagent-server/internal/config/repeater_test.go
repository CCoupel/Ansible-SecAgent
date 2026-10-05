package config

import (
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestLoadRepeaterConfig(t *testing.T) {
	tests := []struct {
		name    string
		env     map[string]string
		wantNil bool
		wantErr bool
	}{
		{"all absent -> root", map[string]string{}, true, false},
		{"id only -> root", map[string]string{"REPEATER_ID": "central"}, true, false},
		{"valid child", map[string]string{"REPEATER_ID": "dmz1", "REPEATER_UPSTREAM_URL": "wss://central:7772", "REPEATER_UPSTREAM_TOKEN": "tok"}, false, false},
		{"missing id", map[string]string{"REPEATER_UPSTREAM_URL": "wss://c", "REPEATER_UPSTREAM_TOKEN": "tok"}, true, true},
		{"missing token", map[string]string{"REPEATER_ID": "dmz1", "REPEATER_UPSTREAM_URL": "wss://c"}, true, true},
		{"token without url", map[string]string{"REPEATER_ID": "dmz1", "REPEATER_UPSTREAM_TOKEN": "tok"}, true, true},
		{"ws scheme refused", map[string]string{"REPEATER_ID": "dmz1", "REPEATER_UPSTREAM_URL": "ws://c", "REPEATER_UPSTREAM_TOKEN": "tok"}, true, true},
		{"https scheme refused", map[string]string{"REPEATER_ID": "dmz1", "REPEATER_UPSTREAM_URL": "https://c", "REPEATER_UPSTREAM_TOKEN": "tok"}, true, true},
		{"userinfo user only", map[string]string{"REPEATER_ID": "dmz1", "REPEATER_UPSTREAM_URL": "wss://alice@c:7772", "REPEATER_UPSTREAM_TOKEN": "tok"}, true, true},
		{"userinfo user:pass", map[string]string{"REPEATER_ID": "dmz1", "REPEATER_UPSTREAM_URL": "wss://alice:hunter2@c:7772", "REPEATER_UPSTREAM_TOKEN": "tok"}, true, true},
		{"no host", map[string]string{"REPEATER_ID": "dmz1", "REPEATER_UPSTREAM_URL": "wss://", "REPEATER_UPSTREAM_TOKEN": "tok"}, true, true},
		{"bad id chars", map[string]string{"REPEATER_ID": "dmz 1!", "REPEATER_UPSTREAM_URL": "wss://c", "REPEATER_UPSTREAM_TOKEN": "tok"}, true, true},
		{"bad id without url", map[string]string{"REPEATER_ID": "a/b"}, true, true},
		{"whitespace only url -> root", map[string]string{"REPEATER_UPSTREAM_URL": "  "}, true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := loadRepeaterConfig(env(tt.env))
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil && !errors.Is(err, ErrInvalidRepeaterConfig) {
				t.Errorf("error not wrapping ErrInvalidRepeaterConfig: %v", err)
			}
			if (cfg == nil) != tt.wantNil {
				t.Fatalf("cfg = %v, wantNil %v", cfg, tt.wantNil)
			}
			if cfg != nil && (cfg.ID != "dmz1" || cfg.UpstreamToken != "tok") {
				t.Errorf("unexpected cfg %+v", cfg)
			}
		})
	}
}

func TestIsRepeaterClientMode(t *testing.T) {
	t.Setenv(EnvRepeaterUpstreamURL, "")
	if IsRepeaterClientMode() {
		t.Error("want false when URL empty")
	}
	t.Setenv(EnvRepeaterUpstreamURL, "wss://c")
	if !IsRepeaterClientMode() {
		t.Error("want true when URL set")
	}
}

func TestLoadRepeaterConfig_FromOS(t *testing.T) {
	t.Setenv(EnvRepeaterID, "dmz1")
	t.Setenv(EnvRepeaterUpstreamURL, "wss://central:7772")
	t.Setenv(EnvRepeaterUpstreamToken, "secret-token")
	cfg, err := LoadRepeaterConfig()
	if err != nil || cfg == nil || cfg.ID != "dmz1" {
		t.Fatalf("cfg=%v err=%v", cfg, err)
	}
}

func TestRepeaterConfig_TokenNeverPrinted(t *testing.T) {
	cfg := RepeaterConfig{ID: "dmz1", UpstreamURL: "wss://c", UpstreamToken: "secret-token"}
	for _, s := range []string{
		cfg.String(),
		fmt.Sprintf("%v %+v %#v %s", cfg, cfg, cfg, &cfg),
		slog.GroupValue(slog.Any("cfg", cfg)).String(),
		cfg.LogValue().String(),
	} {
		if strings.Contains(s, "secret-token") {
			t.Errorf("token leaked: %s", s)
		}
	}
}

func TestLoadRepeaterConfig_UserinfoNotInError(t *testing.T) {
	_, err := loadRepeaterConfig(env(map[string]string{
		"REPEATER_ID": "dmz1", "REPEATER_UPSTREAM_URL": "wss://alice:hunter2@c", "REPEATER_UPSTREAM_TOKEN": "tok",
	}))
	if err == nil {
		t.Fatal("want error")
	}
	if strings.Contains(err.Error(), "alice") || strings.Contains(err.Error(), "hunter2") {
		t.Errorf("userinfo leaked in error: %v", err)
	}
}

func TestLoadRepeaterConfig_AddressList(t *testing.T) {
	base := func(v string) map[string]string {
		return map[string]string{"REPEATER_ID": "dmz1", "REPEATER_UPSTREAM_URL": v, "REPEATER_UPSTREAM_TOKEN": "tok"}
	}
	cfg, err := loadRepeaterConfig(env(base("wss://a:7772, wss://b:7772")))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.UpstreamURLs) != 2 || cfg.UpstreamURLs[0] != "wss://a:7772" || cfg.UpstreamURLs[1] != "wss://b:7772" {
		t.Errorf("UpstreamURLs = %v", cfg.UpstreamURLs)
	}
	// a single value: same behaviour as before (one address)
	cfg, err = loadRepeaterConfig(env(base("wss://central:7772")))
	if err != nil || len(cfg.UpstreamURLs) != 1 || cfg.UpstreamURLs[0] != "wss://central:7772" || cfg.UpstreamURL != "wss://central:7772" {
		t.Errorf("single value: cfg=%+v err=%v", cfg, err)
	}
	for name, v := range map[string]string{
		"one bad scheme in the list": "wss://a:7772,ws://b:7772",
		"one userinfo in the list":   "wss://a:7772,wss://u:pw@b:7772",
		"duplicate":                  "wss://a:7772,wss://a:7772",
		"empty element":              "wss://a:7772,,wss://b:7772",
	} {
		_, err := loadRepeaterConfig(env(base(v)))
		if err == nil || !errors.Is(err, ErrInvalidRepeaterConfig) {
			t.Errorf("%s: want ErrInvalidRepeaterConfig, got %v", name, err)
		}
		if err != nil && (strings.Contains(err.Error(), "pw") || strings.Contains(err.Error(), "b:7772")) {
			t.Errorf("%s: the error echoes an address: %v", name, err)
		}
	}
}
