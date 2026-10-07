package repeater

import (
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

func TestDialPolicy_LoopbackOptInReachesTheListener(t *testing.T) {
	withGuard(t)
	port, accepts := tcpCounter(t)

	// default: refused before any connection
	if _, err := dialCtx(t, "127.0.0.1:"+port); !errors.Is(err, ErrForbiddenTarget) || !strings.Contains(err.Error(), "category=loopback") {
		t.Fatalf("default must refuse loopback with its category: %v", err)
	}
	// opt-in: connects, by literal and by the name "localhost"
	p, err := ParseDialPolicy(true, "", "")
	if err != nil {
		t.Fatal(err)
	}
	defer SetDialPolicy(p)()
	for _, addr := range []string{"127.0.0.1:" + port, "localhost:" + port} {
		c, err := dialCtx(t, addr)
		if err != nil {
			t.Fatalf("%s with the opt-in: %v", addr, err)
		}
		_ = c.Close()
	}
	deadline := time.Now().Add(3 * time.Second)
	for accepts.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if accepts.Load() < 2 {
		t.Fatalf("accepts = %d", accepts.Load())
	}
	// the opt-in lifts loopback ONLY
	if _, err := dialCtx(t, "169.254.169.254:80"); !errors.Is(err, ErrForbiddenTarget) || !strings.Contains(err.Error(), "category=builtin") {
		t.Fatalf("metadata must stay refused: %v", err)
	}
}

func TestDialPolicy_ErrorsNeverEchoTheAddress(t *testing.T) {
	withGuard(t)
	p, _ := ParseDialPolicy(false, "10.0.0.0/8", "")
	defer SetDialPolicy(p)()
	_, err := ParseTargetURLs([]string{"wss://10.1.2.3:7772"})
	if err == nil || strings.Contains(err.Error(), "10.1.2.3") || !strings.Contains(err.Error(), "category=deny") {
		t.Fatalf("err = %v", err)
	}
	_, err = dialCtx(t, "10.1.2.3:1")
	if err == nil || strings.Contains(err.Error(), "10.1.2.3") || !errors.Is(err, ErrForbiddenTarget) {
		t.Fatalf("dial err = %v", err)
	}
}

func TestDialPolicy_ConfigureFromEnv(t *testing.T) {
	restore := SetDialPolicy(currentPolicy())
	defer restore()
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

	if err := ConfigureDialPolicyFromEnv(env(map[string]string{EnvDialDenyCIDRs: "10.0.0.0/8", EnvDialAllowLoopback: "true"})); err != nil {
		t.Fatal(err)
	}
	if currentPolicy().Category(net.ParseIP("10.1.2.3")) != CategoryDeny || currentPolicy().Category(net.ParseIP("127.0.0.1")) != "" {
		t.Fatal("policy not installed from the environment")
	}
	for _, bad := range []map[string]string{
		{EnvDialAllowLoopback: "1"}, {EnvDialAllowLoopback: "TRUE"},
		{EnvDialDenyCIDRs: "0.0.0.0/0"}, {EnvDialAllowCIDRs: "10.0.0.1/8"}, {EnvDialDenyCIDRs: "10.0.0.0/8,,"},
	} {
		before := currentPolicy()
		err := ConfigureDialPolicyFromEnv(env(bad))
		if !errors.Is(err, ErrDialPolicy) {
			t.Fatalf("%v: got %v", bad, err)
		}
		if currentPolicy() != before {
			t.Fatalf("%v: an invalid configuration changed the active policy", bad)
		}
	}
}
