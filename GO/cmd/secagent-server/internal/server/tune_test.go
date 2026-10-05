package server

import (
	"testing"
	"time"

	"secagent-server/cmd/secagent-server/internal/repeater"
)

// Build applies Config.Tune to BOTH option sets before the client / uplink and the dialers are
// created; without Tune the production defaults stay in place.
func TestBuild_AppliesTuneToUplinkAndDialerOptions(t *testing.T) {
	t.Setenv("RELAY_HOOKS_CONFIG", t.TempDir()+"/absent.json")
	var gotUp repeater.Options
	var gotDial repeater.DialerOptions
	called := 0
	n, err := Build(Config{
		JWTSecret: "s", AdminToken: "a", NATSURL: "nats://127.0.0.1:1", DatabaseURL: ":memory:",
		Tune: func(o *repeater.Options, d *repeater.DialerOptions) {
			called++
			o.MinBackoff, o.MaxBackoff = 11*time.Millisecond, 22*time.Millisecond
			o.AgentListInterval, o.PingInterval = 33*time.Millisecond, 44*time.Millisecond
			d.MinBackoff, d.MaxBackoff = 55*time.Millisecond, 66*time.Millisecond
			gotUp, gotDial = *o, *d
			if o.Snapshot == nil || o.DirectAgents == nil || o.OnTask == nil || d.Serve == nil || d.Identity == nil || d.WouldLoop == nil {
				t.Error("Tune must see the production callbacks already in place (it adjusts, it does not wire)")
			}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	if called != 1 {
		t.Fatalf("Tune called %d times, want exactly once", called)
	}
	if gotUp.MinBackoff != 11*time.Millisecond || gotDial.MaxBackoff != 66*time.Millisecond {
		t.Errorf("options seen by Tune = %+v / %+v", gotUp, gotDial)
	}
	// the tuned values are the ones in use: the uplink keeps its (tuned) options, the TLS config stays nil (system roots)
	if gotUp.TLSConfig != nil || gotDial.TLSConfig != nil {
		t.Error("TLS must stay at the system defaults: Tune is not given a TLS override by Build")
	}
}

func TestBuild_WithoutTuneKeepsTheProductionDefaults(t *testing.T) {
	t.Setenv("RELAY_HOOKS_CONFIG", t.TempDir()+"/absent.json")
	n, err := Build(Config{JWTSecret: "s", AdminToken: "a", NATSURL: "nats://127.0.0.1:1", DatabaseURL: ":memory:"})
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	if repeater.DefaultMinBackoff != 5*time.Second || repeater.DefaultMaxBackoff != 60*time.Second ||
		repeater.DefaultAgentListInterval != 30*time.Second || repeater.DefaultPingInterval != 30*time.Second {
		t.Error("production defaults changed")
	}
}
