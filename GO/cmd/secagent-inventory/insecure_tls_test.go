package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestCheckInsecureTLS(t *testing.T) {
	tests := []struct {
		name     string
		cfg      config
		wantErr  bool
		wantWarn bool
	}{
		{"verification normale, aucun avertissement", config{serverURL: "https://relay.example.com"}, false, false},
		{"bouclage localhost", config{serverURL: "https://localhost:7770", insecure: true}, false, true},
		{"bouclage 127.0.0.0/8", config{serverURL: "https://127.5.4.3:7770", insecure: true}, false, true},
		{"bouclage ::1", config{serverURL: "https://[::1]:7770", insecure: true}, false, true},
		{"distant sans ACK", config{serverURL: "https://relay.example.com", insecure: true}, true, false},
		{"distant mauvais ACK", config{serverURL: "https://relay.example.com", insecure: true, insecureAck: "yes"}, true, false},
		{"distant avec ACK", config{serverURL: "https://relay.example.com", insecure: true, insecureAck: insecureAckValue}, false, true},
		{"faux bouclage (suffixe)", config{serverURL: "https://localhost.evil.com", insecure: true}, true, false},
		{"URL invalide", config{serverURL: "://bad", insecure: true}, true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			err := checkInsecureTLS(tt.cfg, &buf)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if warned := strings.Contains(buf.String(), "[SECURITY WARNING] TLS verification disabled"); warned != tt.wantWarn {
				t.Errorf("warning = %v, want %v (%q)", warned, tt.wantWarn, buf.String())
			}
		})
	}
}

func TestCheckInsecureTLSNeverLogsToken(t *testing.T) {
	var buf bytes.Buffer
	cfg := config{serverURL: "https://localhost:7770", insecure: true, token: "s3cr3t-token"}
	if err := checkInsecureTLS(cfg, &buf); err != nil {
		t.Fatal(err)
	}
	cfg.serverURL = "https://relay.example.com"
	err := checkInsecureTLS(cfg, &buf)
	if err == nil || strings.Contains(err.Error(), "s3cr3t-token") || strings.Contains(buf.String(), "s3cr3t-token") {
		t.Errorf("token leaked or no refusal: err=%v out=%q", err, buf.String())
	}
}

func TestLoadConfigInsecureAck(t *testing.T) {
	t.Setenv("RELAY_INSECURE_TLS_ACK", insecureAckValue)
	if got := loadConfig().insecureAck; got != insecureAckValue {
		t.Errorf("insecureAck = %q", got)
	}
}
