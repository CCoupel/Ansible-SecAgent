package proxy

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"strings"
	"testing"
	"time"

	"secagent-server/cmd/secagent-server/internal/storage"
	"secagent-server/cmd/secagent-server/internal/ws"
)

// ── Helpers ───────────────────────────────────────────────────────────────────

func newRouterTestStore(t *testing.T) *storage.Store {
	t.Helper()
	s, err := storage.OpenTemp()
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// seedRelayNode inserts a relay node (any mode) and routing entries.
// Push-mode nodes are accepted and stored but are inert for routing until #140.
func seedRelayNode(t *testing.T, s *storage.Store, relayID, url, mode string, hostnames []string) {
	t.Helper()
	node := storage.RelayNode{
		ID:        "uuid-" + relayID,
		RelayID:   relayID,
		URLs:      splitURLs(url),
		Mode:      mode,
		Status:    "connected",
		CreatedAt: time.Now().Unix(),
	}
	if mode == "push" {
		node.TokenSecret = "enc:test-token-" + relayID // the state only holds sealed push tokens
	} else {
		node.TokenHash = "test-token-" + relayID
	}
	if err := s.UpsertRelayNode(node); err != nil {
		t.Fatalf("UpsertRelayNode: %v", err)
	}
	if err := s.BulkUpsertRelayRouting(relayID, hostnames); err != nil {
		t.Fatalf("BulkUpsertRelayRouting: %v", err)
	}
}

// seedPushRelay inserts a push-mode relay node and routing entry.
// Push-mode is stored but inert for routing (reserved for #140).
func seedPushRelay(t *testing.T, s *storage.Store, relayID, url string, hostnames []string) {
	t.Helper()
	seedRelayNode(t, s, relayID, url, "push", hostnames)
}

// ── GetRelayForHostname ────────────────────────────────────────────────────────

func TestProxyRouter_GetRelayForHostname_Found(t *testing.T) {
	s := newRouterTestStore(t)
	seedPushRelay(t, s, "dmz1", "http://dmz1:7770", []string{"host-a", "host-b"})

	r := NewProxyRouter(s)
	relayID, err := r.GetRelayForHostname("host-a")
	if err != nil {
		t.Fatalf("GetRelayForHostname: %v", err)
	}
	if relayID != "dmz1" {
		t.Errorf("expected dmz1, got %q", relayID)
	}
}

func TestProxyRouter_GetRelayForHostname_NotFound(t *testing.T) {
	s := newRouterTestStore(t)
	r := NewProxyRouter(s)

	_, err := r.GetRelayForHostname("unknown-host")
	if err == nil {
		t.Fatal("expected ErrHostNotFound")
	}
	if err != ErrHostNotFound {
		t.Errorf("expected ErrHostNotFound, got %v", err)
	}
}

func TestProxyRouter_GetRelayForHostname_MultipleRelays(t *testing.T) {
	s := newRouterTestStore(t)
	seedPushRelay(t, s, "dmz1", "http://dmz1:7770", []string{"host-a", "host-b"})
	seedPushRelay(t, s, "dmz2", "http://dmz2:7770", []string{"host-c", "host-d"})

	r := NewProxyRouter(s)

	for _, tc := range []struct{ host, want string }{
		{"host-a", "dmz1"},
		{"host-b", "dmz1"},
		{"host-c", "dmz2"},
		{"host-d", "dmz2"},
	} {
		rid, err := r.GetRelayForHostname(tc.host)
		if err != nil {
			t.Errorf("GetRelayForHostname(%q): %v", tc.host, err)
			continue
		}
		if rid != tc.want {
			t.Errorf("host %q → relay %q, want %q", tc.host, rid, tc.want)
		}
	}
}

// ── RouteExec ─────────────────────────────────────────────────────────────────

func TestProxyRouter_RouteExec_HostNotFound(t *testing.T) {
	s := newRouterTestStore(t)
	r := NewProxyRouter(s)

	_, err := r.RouteExec(context.Background(), "no-such-host", "task-x", ExecRequest{Cmd: "ls"})
	if err != ErrHostNotFound {
		t.Errorf("expected ErrHostNotFound, got %v", err)
	}
}

func TestProxyRouter_RouteExec_RelayOffline(t *testing.T) {
	s := newRouterTestStore(t)
	// Register pull relay in DB but no WS connection
	node := storage.RelayNode{
		ID: "uuid-offline", RelayID: "offline-relay",
		Mode: "pull", Status: "disconnected", CreatedAt: time.Now().Unix(),
	}
	_ = s.UpsertRelayNode(node)
	_ = s.BulkUpsertRelayRouting("offline-relay", []string{"host-offline"})

	r := NewProxyRouter(s)
	r.isRelayConnected = func(string) bool { return false }

	_, err := r.RouteExec(context.Background(), "host-offline", "task-y", ExecRequest{Cmd: "ls"})
	if err == nil {
		t.Fatal("expected error for offline relay")
	}
	if !containsStr(err.Error(), "relay_offline") {
		t.Errorf("expected relay_offline error, got %v", err)
	}
}

// TestProxyRouter_RouteExec_PushModeOffline verifies that a push-mode relay node
// that is not WS-connected returns relay_offline (not routed via HTTP — push is inert until #140).
func TestProxyRouter_RouteExec_PushModeOffline(t *testing.T) {
	s := newRouterTestStore(t)
	seedPushRelay(t, s, "push-relay", "http://push-relay:7770", []string{"push-host"})

	r := NewProxyRouter(s)
	r.isRelayConnected = func(string) bool { return false } // push relay not WS-connected

	_, err := r.RouteExec(context.Background(), "push-host", "task-push-offline", ExecRequest{Cmd: "ls"})
	if err == nil {
		t.Fatal("expected relay_offline for push relay without WS connection")
	}
	if !containsStr(err.Error(), "relay_offline") {
		t.Errorf("expected relay_offline, got %v", err)
	}
}

func TestProxyRouter_RouteExec_PullMode_Success(t *testing.T) {
	s := newRouterTestStore(t)
	node := storage.RelayNode{
		ID: "uuid-pull", RelayID: "dmz-pull",
		Mode: "pull", Status: "connected", CreatedAt: time.Now().Unix(),
	}
	_ = s.UpsertRelayNode(node)
	_ = s.BulkUpsertRelayRouting("dmz-pull", []string{"pull-host"})

	r := NewProxyRouter(s)
	r.isRelayConnected = func(id string) bool { return id == "dmz-pull" }

	// Mock dispatch: immediately returns success result
	r.dispatchToRelay = func(relayID string, msg ws.RelayMessage) (chan ws.RelayTaskResult, error) {
		ch := make(chan ws.RelayTaskResult, 1)
		ch <- ws.RelayTaskResult{TaskID: msg.TaskID, RC: 0, Stdout: "pull output"}
		return ch, nil
	}
	r.unregisterRelayFuture = func(string) {} // no-op

	resp, err := r.RouteExec(context.Background(), "pull-host", "task-pull-1", ExecRequest{
		Cmd: "echo hi", Timeout: 5,
	})
	if err != nil {
		t.Fatalf("RouteExec pull: %v", err)
	}
	if resp.Stdout != "pull output" {
		t.Errorf("unexpected stdout: %q", resp.Stdout)
	}
}

func TestProxyRouter_RouteExec_PullMode_RelayDisconnect(t *testing.T) {
	s := newRouterTestStore(t)
	node := storage.RelayNode{
		ID: "uuid-pull-dc", RelayID: "dmz-pull-dc",
		Mode: "pull", Status: "connected", CreatedAt: time.Now().Unix(),
	}
	_ = s.UpsertRelayNode(node)
	_ = s.BulkUpsertRelayRouting("dmz-pull-dc", []string{"host-dc"})

	r := NewProxyRouter(s)
	r.isRelayConnected = func(id string) bool { return id == "dmz-pull-dc" }

	// Mock dispatch: returns relay_disconnected error
	r.dispatchToRelay = func(relayID string, msg ws.RelayMessage) (chan ws.RelayTaskResult, error) {
		ch := make(chan ws.RelayTaskResult, 1)
		ch <- ws.RelayTaskResult{TaskID: msg.TaskID, Error: "relay_disconnected"}
		return ch, nil
	}
	r.unregisterRelayFuture = func(string) {}

	_, err := r.RouteExec(context.Background(), "host-dc", "task-dc", ExecRequest{Cmd: "ls", Timeout: 5})
	if err == nil {
		t.Fatal("expected error for relay_disconnected")
	}
	if !containsStr(err.Error(), "relay_disconnected") {
		t.Errorf("expected relay_disconnected error, got %v", err)
	}
}

// ── RouteUpload ───────────────────────────────────────────────────────────────

func TestProxyRouter_RouteUpload_HostNotFound(t *testing.T) {
	s := newRouterTestStore(t)
	r := NewProxyRouter(s)

	err := r.RouteUpload(context.Background(), "no-host", "t-up", UploadRequest{Dest: "/x"})
	if err != ErrHostNotFound {
		t.Errorf("expected ErrHostNotFound, got %v", err)
	}
}

func TestProxyRouter_RouteUpload_RelayOffline(t *testing.T) {
	s := newRouterTestStore(t)
	seedRelayNode(t, s, "offline-up", "", "pull", []string{"up-host"})

	r := NewProxyRouter(s)
	r.isRelayConnected = func(string) bool { return false }

	err := r.RouteUpload(context.Background(), "up-host", "t-up-offline", UploadRequest{
		Dest: "/tmp/f.txt", Data: "aGVsbG8=", Mode: "0644",
	})
	if err == nil {
		t.Fatal("expected relay_offline error for upload")
	}
	if !containsStr(err.Error(), "relay_offline") {
		t.Errorf("expected relay_offline, got %v", err)
	}
}

// ── RouteFetch ────────────────────────────────────────────────────────────────

func TestProxyRouter_RouteFetch_HostNotFound(t *testing.T) {
	s := newRouterTestStore(t)
	r := NewProxyRouter(s)

	_, err := r.RouteFetch(context.Background(), "no-host", "t-ft", FetchRequest{Src: "/x"})
	if err != ErrHostNotFound {
		t.Errorf("expected ErrHostNotFound, got %v", err)
	}
}

func TestProxyRouter_RouteFetch_RelayOffline(t *testing.T) {
	s := newRouterTestStore(t)
	seedRelayNode(t, s, "offline-ft", "", "pull", []string{"ft-host"})

	r := NewProxyRouter(s)
	r.isRelayConnected = func(string) bool { return false }

	_, err := r.RouteFetch(context.Background(), "ft-host", "t-ft-offline", FetchRequest{Src: "/etc/h"})
	if err == nil {
		t.Fatal("expected relay_offline error for fetch")
	}
	if !containsStr(err.Error(), "relay_offline") {
		t.Errorf("expected relay_offline, got %v", err)
	}
}

// ── AggregateRelayInventory ───────────────────────────────────────────────────

func TestProxyRouter_AggregateRelayInventory_Empty(t *testing.T) {
	s := newRouterTestStore(t)
	r := NewProxyRouter(s)
	r.isRelayConnected = func(string) bool { return false }

	entries, err := r.AggregateRelayInventory()
	if err != nil {
		t.Fatalf("AggregateRelayInventory: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(entries))
	}
}

func TestProxyRouter_AggregateRelayInventory_TwoRelays(t *testing.T) {
	s := newRouterTestStore(t)
	seedPushRelay(t, s, "dmz1", "http://dmz1:7770", []string{"h1", "h2", "h3"})
	seedPushRelay(t, s, "dmz2", "http://dmz2:7770", []string{"h4", "h5", "h6"})

	r := NewProxyRouter(s)
	r.isRelayConnected = func(id string) bool { return id == "dmz1" } // dmz1 live

	entries, err := r.AggregateRelayInventory()
	if err != nil {
		t.Fatalf("AggregateRelayInventory: %v", err)
	}
	if len(entries) != 6 {
		t.Fatalf("expected 6 entries, got %d", len(entries))
	}

	// Count by relay
	cnt := make(map[string]int)
	for _, e := range entries {
		cnt[e.RelayID]++
	}
	if cnt["dmz1"] != 3 {
		t.Errorf("expected 3 from dmz1, got %d", cnt["dmz1"])
	}
	if cnt["dmz2"] != 3 {
		t.Errorf("expected 3 from dmz2, got %d", cnt["dmz2"])
	}

	// dmz1 should be "connected" (live WS override)
	for _, e := range entries {
		if e.RelayID == "dmz1" && e.RelayStatus != "connected" {
			t.Errorf("dmz1 agent %q: expected connected, got %q", e.Hostname, e.RelayStatus)
		}
	}
}

func TestProxyRouter_AggregateRelayInventory_DisconnectedRelay(t *testing.T) {
	s := newRouterTestStore(t)
	node := storage.RelayNode{
		ID: "uuid-dc", RelayID: "dmz-dc",
		Mode: "pull", Status: "disconnected", CreatedAt: time.Now().Unix(),
	}
	_ = s.UpsertRelayNode(node)
	_ = s.BulkUpsertRelayRouting("dmz-dc", []string{"dc-host-1", "dc-host-2"})

	r := NewProxyRouter(s)
	r.isRelayConnected = func(string) bool { return false }

	entries, err := r.AggregateRelayInventory()
	if err != nil {
		t.Fatalf("AggregateRelayInventory: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	for _, e := range entries {
		if e.RelayStatus != "disconnected" {
			t.Errorf("expected disconnected for dc relay agent %q, got %q", e.Hostname, e.RelayStatus)
		}
		if e.RelayID != "dmz-dc" {
			t.Errorf("expected RelayID=dmz-dc, got %q", e.RelayID)
		}
	}
}

// ── pullExec additional coverage ──────────────────────────────────────────────

func TestProxyRouter_RouteExec_PullMode_DispatchError(t *testing.T) {
	s := newRouterTestStore(t)
	node := storage.RelayNode{
		ID: "uuid-de", RelayID: "de-relay", Mode: "pull", Status: "connected", CreatedAt: time.Now().Unix(),
	}
	_ = s.UpsertRelayNode(node)
	_ = s.BulkUpsertRelayRouting("de-relay", []string{"de-host"})

	r := NewProxyRouter(s)
	r.isRelayConnected = func(id string) bool { return id == "de-relay" }
	r.dispatchToRelay = func(relayID string, msg ws.RelayMessage) (chan ws.RelayTaskResult, error) {
		return nil, fmt.Errorf("relay_unreachable")
	}
	r.unregisterRelayFuture = func(string) {}

	_, err := r.RouteExec(context.Background(), "de-host", "task-de", ExecRequest{Cmd: "ls", Timeout: 5})
	if err == nil {
		t.Fatal("expected error for dispatch failure")
	}
	if !containsStr(err.Error(), "dispatch_failed") {
		t.Errorf("expected dispatch_failed error, got %v", err)
	}
}

func TestProxyRouter_RouteExec_PullMode_ContextCancel(t *testing.T) {
	s := newRouterTestStore(t)
	node := storage.RelayNode{
		ID: "uuid-cc", RelayID: "cc-relay", Mode: "pull", Status: "connected", CreatedAt: time.Now().Unix(),
	}
	_ = s.UpsertRelayNode(node)
	_ = s.BulkUpsertRelayRouting("cc-relay", []string{"cc-host"})

	r := NewProxyRouter(s)
	r.isRelayConnected = func(id string) bool { return id == "cc-relay" }
	r.dispatchToRelay = func(relayID string, msg ws.RelayMessage) (chan ws.RelayTaskResult, error) {
		return make(chan ws.RelayTaskResult), nil // never sends
	}
	r.unregisterRelayFuture = func(string) {}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled

	_, err := r.RouteExec(ctx, "cc-host", "task-cc", ExecRequest{Cmd: "ls", Timeout: 30})
	if err == nil {
		t.Fatal("expected error for cancelled context")
	}
	if !containsStr(err.Error(), "context_cancelled") {
		t.Errorf("expected context_cancelled error, got %v", err)
	}
}

// ── pullUpload success path ───────────────────────────────────────────────────

func TestProxyRouter_RouteUpload_PullMode_Success(t *testing.T) {
	s := newRouterTestStore(t)
	node := storage.RelayNode{
		ID: "uuid-ups", RelayID: "ups-relay", Mode: "pull", Status: "connected", CreatedAt: time.Now().Unix(),
	}
	_ = s.UpsertRelayNode(node)
	_ = s.BulkUpsertRelayRouting("ups-relay", []string{"ups-host"})

	r := NewProxyRouter(s)
	r.isRelayConnected = func(id string) bool { return id == "ups-relay" }
	r.dispatchToRelay = func(relayID string, msg ws.RelayMessage) (chan ws.RelayTaskResult, error) {
		ch := make(chan ws.RelayTaskResult, 1)
		ch <- ws.RelayTaskResult{TaskID: msg.TaskID, RC: 0}
		return ch, nil
	}
	r.unregisterRelayFuture = func(string) {}

	err := r.RouteUpload(context.Background(), "ups-host", "task-ups-1", UploadRequest{
		Dest: "/tmp/f.txt", Data: "aGVsbG8=", Mode: "0644",
	})
	if err != nil {
		t.Fatalf("RouteUpload pull success: %v", err)
	}
}

func TestProxyRouter_RouteUpload_PullMode_ResultRC(t *testing.T) {
	// Relay returns non-zero RC → upload_failed error
	s := newRouterTestStore(t)
	node := storage.RelayNode{
		ID: "uuid-urc", RelayID: "urc-relay", Mode: "pull", Status: "connected", CreatedAt: time.Now().Unix(),
	}
	_ = s.UpsertRelayNode(node)
	_ = s.BulkUpsertRelayRouting("urc-relay", []string{"urc-host"})

	r := NewProxyRouter(s)
	r.isRelayConnected = func(id string) bool { return id == "urc-relay" }
	r.dispatchToRelay = func(relayID string, msg ws.RelayMessage) (chan ws.RelayTaskResult, error) {
		ch := make(chan ws.RelayTaskResult, 1)
		ch <- ws.RelayTaskResult{TaskID: msg.TaskID, RC: 1} // non-zero RC
		return ch, nil
	}
	r.unregisterRelayFuture = func(string) {}

	err := r.RouteUpload(context.Background(), "urc-host", "task-urc", UploadRequest{
		Dest: "/tmp/f.txt", Data: "aGVsbG8=",
	})
	if err == nil {
		t.Fatal("expected upload_failed for RC != 0")
	}
	if !containsStr(err.Error(), "upload_failed") {
		t.Errorf("expected upload_failed error, got %v", err)
	}
}

func TestProxyRouter_RouteUpload_PullMode_ResultError(t *testing.T) {
	s := newRouterTestStore(t)
	node := storage.RelayNode{
		ID: "uuid-ure", RelayID: "ure-relay", Mode: "pull", Status: "connected", CreatedAt: time.Now().Unix(),
	}
	_ = s.UpsertRelayNode(node)
	_ = s.BulkUpsertRelayRouting("ure-relay", []string{"ure-host"})

	r := NewProxyRouter(s)
	r.isRelayConnected = func(id string) bool { return id == "ure-relay" }
	r.dispatchToRelay = func(relayID string, msg ws.RelayMessage) (chan ws.RelayTaskResult, error) {
		ch := make(chan ws.RelayTaskResult, 1)
		ch <- ws.RelayTaskResult{TaskID: msg.TaskID, Error: "relay_disconnected"}
		return ch, nil
	}
	r.unregisterRelayFuture = func(string) {}

	err := r.RouteUpload(context.Background(), "ure-host", "task-ure", UploadRequest{
		Dest: "/tmp/f.txt", Data: "aGVsbG8=",
	})
	if err == nil {
		t.Fatal("expected error from result.Error")
	}
	if !containsStr(err.Error(), "relay_disconnected") {
		t.Errorf("expected relay_disconnected in error, got %v", err)
	}
}

func TestProxyRouter_RouteUpload_PullMode_DispatchError(t *testing.T) {
	s := newRouterTestStore(t)
	node := storage.RelayNode{
		ID: "uuid-ude", RelayID: "ude-relay", Mode: "pull", Status: "connected", CreatedAt: time.Now().Unix(),
	}
	_ = s.UpsertRelayNode(node)
	_ = s.BulkUpsertRelayRouting("ude-relay", []string{"ude-host"})

	r := NewProxyRouter(s)
	r.isRelayConnected = func(id string) bool { return id == "ude-relay" }
	r.dispatchToRelay = func(relayID string, msg ws.RelayMessage) (chan ws.RelayTaskResult, error) {
		return nil, fmt.Errorf("relay_unavailable")
	}
	r.unregisterRelayFuture = func(string) {}

	err := r.RouteUpload(context.Background(), "ude-host", "task-ude", UploadRequest{
		Dest: "/tmp/f.txt", Data: "dA==",
	})
	if err == nil {
		t.Fatal("expected error for dispatch failure")
	}
	if !containsStr(err.Error(), "dispatch_failed") {
		t.Errorf("expected dispatch_failed error, got %v", err)
	}
}

func TestProxyRouter_RouteUpload_PullMode_ContextCancel(t *testing.T) {
	s := newRouterTestStore(t)
	node := storage.RelayNode{
		ID: "uuid-ucc", RelayID: "ucc-relay", Mode: "pull", Status: "connected", CreatedAt: time.Now().Unix(),
	}
	_ = s.UpsertRelayNode(node)
	_ = s.BulkUpsertRelayRouting("ucc-relay", []string{"ucc-host"})

	r := NewProxyRouter(s)
	r.isRelayConnected = func(id string) bool { return id == "ucc-relay" }
	r.dispatchToRelay = func(relayID string, msg ws.RelayMessage) (chan ws.RelayTaskResult, error) {
		return make(chan ws.RelayTaskResult), nil // never sends
	}
	r.unregisterRelayFuture = func(string) {}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := r.RouteUpload(ctx, "ucc-host", "task-ucc", UploadRequest{Dest: "/tmp/f", Data: "dA=="})
	if err == nil {
		t.Fatal("expected error for cancelled context")
	}
	if !containsStr(err.Error(), "context_cancelled") {
		t.Errorf("expected context_cancelled error, got %v", err)
	}
}

// ── pullFetch success path ────────────────────────────────────────────────────

func TestProxyRouter_RouteFetch_PullMode_Success(t *testing.T) {
	s := newRouterTestStore(t)
	node := storage.RelayNode{
		ID: "uuid-fps", RelayID: "fps-relay", Mode: "pull", Status: "connected", CreatedAt: time.Now().Unix(),
	}
	_ = s.UpsertRelayNode(node)
	_ = s.BulkUpsertRelayRouting("fps-relay", []string{"fps-host"})

	r := NewProxyRouter(s)
	r.isRelayConnected = func(id string) bool { return id == "fps-relay" }
	r.dispatchToRelay = func(relayID string, msg ws.RelayMessage) (chan ws.RelayTaskResult, error) {
		ch := make(chan ws.RelayTaskResult, 1)
		ch <- ws.RelayTaskResult{TaskID: msg.TaskID, RC: 0, Data: "cmVsYXktZmV0Y2g="}
		return ch, nil
	}
	r.unregisterRelayFuture = func(string) {}

	resp, err := r.RouteFetch(context.Background(), "fps-host", "task-fps-1", FetchRequest{Src: "/etc/hosts"})
	if err != nil {
		t.Fatalf("RouteFetch pull success: %v", err)
	}
	if resp.Data != "cmVsYXktZmV0Y2g=" {
		t.Errorf("expected base64 data, got %q", resp.Data)
	}
	if resp.RC != 0 {
		t.Errorf("expected RC=0, got %d", resp.RC)
	}
}

func TestProxyRouter_RouteFetch_PullMode_ResultError(t *testing.T) {
	s := newRouterTestStore(t)
	node := storage.RelayNode{
		ID: "uuid-fre", RelayID: "fre-relay", Mode: "pull", Status: "connected", CreatedAt: time.Now().Unix(),
	}
	_ = s.UpsertRelayNode(node)
	_ = s.BulkUpsertRelayRouting("fre-relay", []string{"fre-host"})

	r := NewProxyRouter(s)
	r.isRelayConnected = func(id string) bool { return id == "fre-relay" }
	r.dispatchToRelay = func(relayID string, msg ws.RelayMessage) (chan ws.RelayTaskResult, error) {
		ch := make(chan ws.RelayTaskResult, 1)
		ch <- ws.RelayTaskResult{TaskID: msg.TaskID, Error: "file_not_found"}
		return ch, nil
	}
	r.unregisterRelayFuture = func(string) {}

	_, err := r.RouteFetch(context.Background(), "fre-host", "task-fre", FetchRequest{Src: "/no/such/file"})
	if err == nil {
		t.Fatal("expected error from result.Error")
	}
	if !containsStr(err.Error(), "file_not_found") {
		t.Errorf("expected file_not_found in error, got %v", err)
	}
}

func TestProxyRouter_RouteFetch_PullMode_DispatchError(t *testing.T) {
	s := newRouterTestStore(t)
	node := storage.RelayNode{
		ID: "uuid-fde", RelayID: "fde-relay", Mode: "pull", Status: "connected", CreatedAt: time.Now().Unix(),
	}
	_ = s.UpsertRelayNode(node)
	_ = s.BulkUpsertRelayRouting("fde-relay", []string{"fde-host"})

	r := NewProxyRouter(s)
	r.isRelayConnected = func(id string) bool { return id == "fde-relay" }
	r.dispatchToRelay = func(relayID string, msg ws.RelayMessage) (chan ws.RelayTaskResult, error) {
		return nil, fmt.Errorf("relay_unavailable")
	}
	r.unregisterRelayFuture = func(string) {}

	_, err := r.RouteFetch(context.Background(), "fde-host", "task-fde", FetchRequest{Src: "/etc/hosts"})
	if err == nil {
		t.Fatal("expected error for dispatch failure")
	}
	if !containsStr(err.Error(), "dispatch_failed") {
		t.Errorf("expected dispatch_failed error, got %v", err)
	}
}

func TestProxyRouter_RouteFetch_PullMode_ContextCancel(t *testing.T) {
	s := newRouterTestStore(t)
	node := storage.RelayNode{
		ID: "uuid-fcc", RelayID: "fcc-relay", Mode: "pull", Status: "connected", CreatedAt: time.Now().Unix(),
	}
	_ = s.UpsertRelayNode(node)
	_ = s.BulkUpsertRelayRouting("fcc-relay", []string{"fcc-host"})

	r := NewProxyRouter(s)
	r.isRelayConnected = func(id string) bool { return id == "fcc-relay" }
	r.dispatchToRelay = func(relayID string, msg ws.RelayMessage) (chan ws.RelayTaskResult, error) {
		return make(chan ws.RelayTaskResult), nil // never sends
	}
	r.unregisterRelayFuture = func(string) {}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := r.RouteFetch(ctx, "fcc-host", "task-fcc", FetchRequest{Src: "/etc/hosts"})
	if err == nil {
		t.Fatal("expected error for cancelled context")
	}
	if !containsStr(err.Error(), "context_cancelled") {
		t.Errorf("expected context_cancelled error, got %v", err)
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

func containsStr(s, sub string) bool {
	return strings.Contains(s, sub)
}

// A task_id coming from a plugin request is logged with %q: no forged log line.
func TestProxyRouter_RouteExec_LogQuotesCallerIdentifiers(t *testing.T) {
	s := newRouterTestStore(t)
	evilHost := "h1"
	_ = s.UpsertRelayNode(storage.RelayNode{ID: "uuid-q", RelayID: "dmz-q", Mode: "pull", Status: "connected", CreatedAt: time.Now().Unix()})
	_ = s.BulkUpsertRelayRouting("dmz-q", []string{evilHost})
	r := NewProxyRouter(s)
	r.isRelayConnected = func(string) bool { return true }
	r.dispatchToRelay = func(_ string, msg ws.RelayMessage) (chan ws.RelayTaskResult, error) {
		ch := make(chan ws.RelayTaskResult, 1)
		ch <- ws.RelayTaskResult{TaskID: msg.TaskID}
		return ch, nil
	}
	r.unregisterRelayFuture = func(string) {}

	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(prev)
	if _, err := r.RouteExec(context.Background(), evilHost, "t\nFAKE task", ExecRequest{Cmd: "ls", Timeout: 5}); err != nil {
		t.Fatal(err)
	}
	for _, l := range strings.Split(buf.String(), "\n") {
		if strings.HasPrefix(l, "FAKE") {
			t.Errorf("forged log line: %q", l)
		}
	}
	if !strings.Contains(buf.String(), `task_id="t\nFAKE task"`) {
		t.Errorf("task_id must be quoted: %q", buf.String())
	}
}

// splitURLs turns a comma list ("" = none) into the RelayNode.URLs form.
func splitURLs(u string) []string {
	if u == "" {
		return nil
	}
	return strings.Split(u, ",")
}
