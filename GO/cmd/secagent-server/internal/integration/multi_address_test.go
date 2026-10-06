package integration

import (
	"net/http"
	"testing"

	"secagent-server/internal/testnet"
)

// closedWSSAddress is the wss address of a port nobody listens on.
func closedWSSAddress(t *testing.T) string {
	t.Helper()
	return "wss://" + testnet.ClosedAddr(t)
}

// A child declared with TWO parent addresses (REPEATER_UPSTREAM_URL list): the first one is down, the
// link comes up on the second and the chain works end to end (host routable, exec through the link).
func TestMultiAddress_ChildFallsBackToTheSecondParentAddress(t *testing.T) {
	parallel(t)
	root := startNode(t, nodeSpec{ID: "root", Hooks: standardHooks})
	token := root.registerChild("relay1")
	relay1 := startNode(t, nodeSpec{ID: "relay1", ParentURL: closedWSSAddress(t) + "," + root.wssURL(), ParentToken: token, Hooks: standardHooks})
	waitFor(t, "relay1 linked to the root through its second address", func() bool { return relay1.upstreamState() == "connected" })

	connectMinion(t, relay1, "multi-host")
	waitFor(t, "the root routes the host behind the child", func() bool { return root.hasHost("multi-host") })
	if r := root.exec("multi-host", execBody("whoami")); r.Code != http.StatusOK {
		t.Errorf("exec through the chain = %d %v", r.Code, r.Body)
	}
	assertNoSecrets(t, allLogs(root, relay1), nodeSecrets(root, relay1)...)
}
