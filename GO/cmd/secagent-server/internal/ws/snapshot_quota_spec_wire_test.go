package ws

// Wiring of the #156 quota table into the spec tests (snapshot_quota_spec_test.go). The table is
// process-global like the connection registry; resetRelayState (the cleanup of setupRelayTestServer)
// clears it between tests.

func init() {
	specSnapshotQuotaEntries = snapshotQuotaEntries
}
