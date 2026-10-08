package ws

// Wiring of the #179 admission counters into the purge-path spec tests (task_purge_spec_test.go):
// every test then asserts the counters as well as the maps, which catches a forgotten decrement.

func init() {
	specCounters = &specCountersImpl{InFlight: inFlightOf, InFlightAll: inFlightAll, StdoutBytes: stdoutHeldBytes}
	specAdmit = func(taskID, host string) error {
		_, err := RegisterFuture(taskID, host)
		return err
	}
}
