package ws

import "testing"

// Invalid values of the limit variables must never disable or zero a bound: they fall back to
// the default, exactly like MAX_SNAPSHOT_HOSTS (same validation, envInt).
func TestLimitsEnv_InvalidValuesFallBackToDefault(t *testing.T) {
	const def = 10000
	tests := []struct {
		name, value string
		want        int
	}{
		{"unset", "", def},
		{"not a number", "abc", def},
		{"zero (would reject every list, or mean unlimited)", "0", def},
		{"negative", "-5", def},
		{"huge, overflows int", "99999999999999999999", def},
		{"float", "3.5", def},
		{"padded with spaces", " 7 ", def},
		{"valid", "7", 7},
		{"huge but valid", "2147483647", 2147483647},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("MAX_AGENT_LIST_HOSTS", tt.value)
			t.Setenv("MAX_SNAPSHOT_HOSTS", tt.value)
			if got := maxAgentListHosts(); got != tt.want {
				t.Errorf("MAX_AGENT_LIST_HOSTS=%q → %d, want %d", tt.value, got, tt.want)
			}
			if got := maxSnapshotHosts(); got != tt.want {
				t.Errorf("MAX_SNAPSHOT_HOSTS=%q → %d, want %d", tt.value, got, tt.want)
			}
			if maxAgentListHosts() != maxSnapshotHosts() {
				t.Error("MAX_AGENT_LIST_HOSTS and MAX_SNAPSHOT_HOSTS must be validated identically")
			}
		})
	}
}
