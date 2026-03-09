package facts

import (
	"encoding/json"
	"runtime"
	"strings"
	"testing"
)

// ========================================================================
// Collect — smoke test
// ========================================================================

func TestCollectReturnsNonEmpty(t *testing.T) {
	f := Collect()

	if f.Hostname == "" {
		t.Error("Hostname is empty")
	}
	if f.OS.System == "" {
		t.Error("OS.System is empty")
	}
	if f.PythonVersion != "N/A" {
		t.Errorf("PythonVersion: got %q, want 'N/A'", f.PythonVersion)
	}
	if f.Packages == nil {
		t.Error("Packages is nil, expected empty map")
	}
}

func TestCollectOSSystem(t *testing.T) {
	f := Collect()
	if f.OS.System != runtime.GOOS {
		t.Errorf("OS.System: got %q, want %q", f.OS.System, runtime.GOOS)
	}
}

func TestCollectCPUCount(t *testing.T) {
	f := Collect()
	if f.CPUCount <= 0 {
		t.Errorf("CPUCount: got %d, want > 0", f.CPUCount)
	}
}

func TestCollectIPAddresses(t *testing.T) {
	f := Collect()
	// May be empty in CI (no network), just check no panic
	_ = f.IPAddresses
}

func TestCollectNetworkInterfaces(t *testing.T) {
	f := Collect()
	// May be empty in CI, just check no panic
	_ = f.NetworkInterfaces
}

func TestCollectDiskTotalGB(t *testing.T) {
	f := Collect()
	// On most systems, disk > 0
	if f.DiskTotalGB < 0 {
		t.Errorf("DiskTotalGB: got negative value %f", f.DiskTotalGB)
	}
}

// ========================================================================
// JSON marshaling
// ========================================================================

func TestFactsMarshalJSON(t *testing.T) {
	f := Collect()
	data, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if len(data) == 0 {
		t.Error("marshaled JSON is empty")
	}

	// Verify key fields are present
	str := string(data)
	for _, key := range []string{"hostname", "os", "cpu_count", "python_version"} {
		if !strings.Contains(str, `"`+key+`"`) {
			t.Errorf("JSON missing field: %q", key)
		}
	}
}

func TestFactsUnmarshalJSON(t *testing.T) {
	original := Collect()
	data, _ := json.Marshal(original)

	var restored Facts
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	if restored.Hostname != original.Hostname {
		t.Errorf("Hostname: got %q, want %q", restored.Hostname, original.Hostname)
	}
	if restored.OS.System != original.OS.System {
		t.Errorf("OS.System: got %q, want %q", restored.OS.System, original.OS.System)
	}
	if restored.CPUCount != original.CPUCount {
		t.Errorf("CPUCount: got %d, want %d", restored.CPUCount, original.CPUCount)
	}
	if restored.PythonVersion != "N/A" {
		t.Errorf("PythonVersion: got %q, want 'N/A'", restored.PythonVersion)
	}
}

// ========================================================================
// getHostname
// ========================================================================

func TestGetHostname(t *testing.T) {
	h := getHostname()
	if h == "" {
		t.Error("getHostname returned empty string")
	}
}

// ========================================================================
// getCPUCount
// ========================================================================

func TestGetCPUCount(t *testing.T) {
	n := getCPUCount()
	if n <= 0 {
		t.Errorf("getCPUCount: got %d, want > 0", n)
	}
}

// ========================================================================
// getOSInfo
// ========================================================================

func TestGetOSInfo(t *testing.T) {
	info := getOSInfo()
	if info.System == "" {
		t.Error("OSInfo.System is empty")
	}
	if info.System != runtime.GOOS {
		t.Errorf("OSInfo.System: got %q, want %q", info.System, runtime.GOOS)
	}
}

// ========================================================================
// getOSFamily
// ========================================================================

func TestGetOSFamily(t *testing.T) {
	family := getOSFamily()
	if family == "" {
		t.Error("getOSFamily returned empty string")
	}
	if runtime.GOOS == "windows" && family != "Windows" {
		t.Errorf("getOSFamily on windows: got %q, want Windows", family)
	}
}

// ========================================================================
// getNonLoopbackIPs
// ========================================================================

func TestGetNonLoopbackIPsNoLoopback(t *testing.T) {
	ips := getNonLoopbackIPs()
	for _, ip := range ips {
		if ip == "127.0.0.1" || ip == "::1" {
			t.Errorf("loopback address found: %q", ip)
		}
	}
}

// ========================================================================
// getNetworkInterfaces
// ========================================================================

func TestGetNetworkInterfacesNoLoopback(t *testing.T) {
	ifaces := getNetworkInterfaces()
	for _, iface := range ifaces {
		if iface.Name == "lo" {
			t.Error("loopback interface 'lo' should be excluded")
		}
	}
}

// ========================================================================
// getMemoryTotalMB
// ========================================================================

func TestGetMemoryTotalMB(t *testing.T) {
	mb := getMemoryTotalMB()
	if runtime.GOOS == "linux" && mb <= 0 {
		t.Logf("getMemoryTotalMB on Linux: got %d (may be 0 in containers)", mb)
	}
	if mb < 0 {
		t.Errorf("getMemoryTotalMB: got negative value %d", mb)
	}
}

// ========================================================================
// parseKeyValue helper
// ========================================================================

func TestParseKeyValue(t *testing.T) {
	lines := []string{
		`NAME="Ubuntu"`,
		`VERSION_ID="22.04"`,
		`ID=ubuntu`,
		`ID_LIKE=debian`,
		`# comment`,
		`NO_EQUALS`,
	}
	kv := parseKeyValue(lines)

	if kv["NAME"] != `"Ubuntu"` {
		t.Errorf("NAME: got %q, want %q", kv["NAME"], `"Ubuntu"`)
	}
	if kv["ID"] != "ubuntu" {
		t.Errorf("ID: got %q, want ubuntu", kv["ID"])
	}
	if _, ok := kv["# comment"]; ok {
		t.Error("comment line should not be parsed as key")
	}
	if _, ok := kv["NO_EQUALS"]; ok {
		t.Error("line without = should not be parsed")
	}
}

// ========================================================================
// roundFloat helper
// ========================================================================

func TestRoundFloat(t *testing.T) {
	tests := []struct {
		input    float64
		decimals int
		want     float64
	}{
		{1.234, 2, 1.23},
		{1.235, 2, 1.24},
		{1.0, 0, 1.0},
		{0.0, 2, 0.0},
		{100.999, 1, 101.0},
	}
	for _, tt := range tests {
		got := roundFloat(tt.input, tt.decimals)
		if got != tt.want {
			t.Errorf("roundFloat(%f, %d) = %f, want %f", tt.input, tt.decimals, got, tt.want)
		}
	}
}

// ========================================================================
// Facts struct — types
// ========================================================================

func TestFactsStruct(t *testing.T) {
	f := Facts{
		Hostname:      "test-host",
		OS:            OSInfo{System: "linux", Release: "22.04", Version: "22.04.1"},
		OSFamily:      "Debian",
		KernelVersion: "5.15.0",
		CPUCount:      4,
		MemoryTotalMB: 8192,
		DiskTotalGB:   100.5,
		IPAddresses:   []string{"192.168.1.1"},
		NetworkInterfaces: []NetworkIface{
			{Name: "eth0", MAC: "aa:bb:cc:dd:ee:ff", IPv4: []string{"192.168.1.1"}},
		},
		PythonVersion: "N/A",
		Packages:      map[string]string{},
	}

	if f.Hostname != "test-host" {
		t.Error("Hostname not preserved")
	}
	if f.CPUCount != 4 {
		t.Error("CPUCount not preserved")
	}
	if f.OSFamily != "Debian" {
		t.Error("OSFamily not preserved")
	}
}

func TestNetworkIfaceStruct(t *testing.T) {
	iface := NetworkIface{
		Name: "eth0",
		MAC:  "aa:bb:cc:dd:ee:ff",
		IPv4: []string{"192.168.1.1", "10.0.0.1"},
		IPv6: []string{"fe80::1"},
	}
	if iface.Name != "eth0" {
		t.Error("Name not preserved")
	}
	if len(iface.IPv4) != 2 {
		t.Errorf("IPv4: got %d addresses, want 2", len(iface.IPv4))
	}
}
