// SPDX-FileCopyrightText: 2025-2026 Cyril Coupel
// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"log"
	"os"
	"strings"
	"testing"
)

// #220: the [INIT] line carries the injected version, not the hard-coded "v1.0".
func TestInitLineCarriesTheInjectedVersion(t *testing.T) {
	buf := &lockedBuf{}
	log.SetOutput(buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	prev := Version
	Version = "9.9.9-test"
	t.Cleanup(func() { Version = prev })
	startNode(t, nil)
	out := buf.String()
	if !strings.Contains(out, "[INIT] Ansible-SecAgent GO Server 9.9.9-test") {
		t.Errorf("the [INIT] line must carry the version:\n%s", out)
	}
	if strings.Contains(out, "Server v1.0") {
		t.Errorf("the hard-coded v1.0 is back:\n%s", out)
	}
}
