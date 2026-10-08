package ws

func mustFuture(ch chan Message, err error) chan Message {
	if err != nil {
		panic(err)
	}
	return ch
}

func mustRelayFuture(ch chan RelayTaskResult, err error) chan RelayTaskResult {
	if err != nil {
		panic(err)
	}
	return ch
}

// resetAdmission forgets every admitted task and restores the default limits (tests).
func resetAdmission() {
	admMu.Lock()
	admitted = map[string]*admission{}
	perHostCount = map[string]int{}
	inflightTotal, stdoutHeld = 0, 0
	admMu.Unlock()
	SetTaskLimits(0, 0, 0)
}

// stdoutString returns the stdout accumulated for a task ("" when none).
func stdoutString(id string) string {
	buffersMu.RLock()
	defer buffersMu.RUnlock()
	if b := stdoutBuffers[id]; b != nil {
		return b.String()
	}
	return ""
}
