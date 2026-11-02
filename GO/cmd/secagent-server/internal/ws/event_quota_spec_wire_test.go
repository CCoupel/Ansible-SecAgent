package ws

// Wiring of the #216 quota table into the spec tests (event_quota_spec_test.go).

func init() {
	specEventQuotaEntries = eventQuotaEntries
}
