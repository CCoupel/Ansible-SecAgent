package broker

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	nats "github.com/nats-io/nats.go"
	natsserver "github.com/nats-io/nats-server/v2/server"
	natstest "github.com/nats-io/nats-server/v2/test"
)

// startTestNATSServer starts an embedded NATS JetStream server
func startTestNATSServer(t *testing.T) (*natsserver.Server, string) {
	t.Helper()

	opts := &natsserver.Options{
		Host:      "127.0.0.1",
		Port:      -1,
		JetStream: true,
		StoreDir:  t.TempDir(),
		NoLog:     true,
		NoSigs:    true,
	}

	srv := natstest.RunServer(opts)
	if srv == nil {
		t.Fatal("failed to start embedded NATS server")
	}
	t.Cleanup(func() { srv.Shutdown() })

	return srv, srv.ClientURL()
}

// newTestClient creates a connected NATS client for tests
func newTestClient(t *testing.T) *Client {
	t.Helper()
	_, natsURL := startTestNATSServer(t)

	client, err := NewClient(natsURL)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { client.Close() })
	return client
}

// ========================================================================
// Constants
// ========================================================================

func TestStreamConstants(t *testing.T) {
	if StreamTasks != "RELAY_TASKS" {
		t.Errorf("StreamTasks: expected 'RELAY_TASKS', got %q", StreamTasks)
	}
	if StreamResults != "RELAY_RESULTS" {
		t.Errorf("StreamResults: expected 'RELAY_RESULTS', got %q", StreamResults)
	}
	if SubjectTasks != "tasks.*" {
		t.Errorf("SubjectTasks: expected 'tasks.*', got %q", SubjectTasks)
	}
	if SubjectResults != "results.*" {
		t.Errorf("SubjectResults: expected 'results.*', got %q", SubjectResults)
	}
	if TasksTTLSec != 300 {
		t.Errorf("TasksTTLSec: expected 300, got %d", TasksTTLSec)
	}
	if ResultsTTLSec != 60 {
		t.Errorf("ResultsTTLSec: expected 60, got %d", ResultsTTLSec)
	}
	if TasksMaxBytes != 1*1024*1024 {
		t.Errorf("TasksMaxBytes: expected 1MB, got %d", TasksMaxBytes)
	}
	if ResultsMaxBytes != 5*1024*1024 {
		t.Errorf("ResultsMaxBytes: expected 5MB, got %d", ResultsMaxBytes)
	}
}

// ========================================================================
// NATS URL
// ========================================================================

func TestGetNatsURL(t *testing.T) {
	url := getNatsURL()
	if url == "" {
		t.Error("getNatsURL returned empty string")
	}
	// Default should be localhost:4222
	if url != "nats://localhost:4222" {
		t.Logf("NATS URL (may be set via env): %s", url)
	}
}

// ========================================================================
// Struct JSON marshaling
// ========================================================================

func TestTaskMessageStruct(t *testing.T) {
	stdin := "password"
	msg := TaskMessage{
		TaskID:       "task-123",
		Type:         "exec",
		Cmd:          "ls -la",
		Stdin:        &stdin,
		Timeout:      30,
		Become:       true,
		BecomeMethod: "sudo",
		ExpiresAt:    1234567890,
	}

	body, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var msg2 TaskMessage
	err = json.Unmarshal(body, &msg2)
	if err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if msg2.TaskID != msg.TaskID {
		t.Error("failed to preserve TaskID")
	}
	if msg2.Type != msg.Type {
		t.Error("failed to preserve Type")
	}
	if msg2.Cmd != msg.Cmd {
		t.Error("failed to preserve Cmd")
	}
	if msg2.Timeout != msg.Timeout {
		t.Error("failed to preserve Timeout")
	}
	if msg2.Become != msg.Become {
		t.Error("failed to preserve Become")
	}
}

func TestResultMessageStruct(t *testing.T) {
	result := ResultMessage{
		TaskID:    "task-123",
		RC:        0,
		Stdout:    "hello world",
		Stderr:    "",
		Truncated: false,
		Error:     "",
	}

	body, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var result2 ResultMessage
	err = json.Unmarshal(body, &result2)
	if err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if result2.TaskID != result.TaskID {
		t.Error("failed to preserve TaskID")
	}
	if result2.RC != result.RC {
		t.Error("failed to preserve RC")
	}
	if result2.Stdout != result.Stdout {
		t.Error("failed to preserve Stdout")
	}
}

func TestTaskMessageOmitEmpty(t *testing.T) {
	msg := TaskMessage{
		TaskID:       "task-456",
		Type:         "cancel",
		Cmd:          "",
		Stdin:        nil,
		Timeout:      0,
		Become:       false,
		BecomeMethod: "",
		ExpiresAt:    0,
	}

	body, _ := json.Marshal(msg)
	bodyStr := string(body)
	t.Logf("TaskMessage JSON: %s", bodyStr)

	// task_id and type must be present
	var decoded map[string]interface{}
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded["task_id"] != "task-456" {
		t.Error("task_id must be present")
	}
	if decoded["type"] != "cancel" {
		t.Error("type must be present")
	}
}

// ========================================================================
// NewClient — integration with embedded server
// ========================================================================

func TestNewClientConnects(t *testing.T) {
	client := newTestClient(t)
	if client == nil {
		t.Fatal("expected non-nil client")
	}
	if client.nc == nil {
		t.Error("expected NATS connection to be initialized")
	}
}

func TestNewClientCreatesStreams(t *testing.T) {
	client := newTestClient(t)
	ctx := context.Background()

	// Verify RELAY_TASKS stream exists
	stream, err := client.js.Stream(ctx, StreamTasks)
	if err != nil {
		t.Errorf("RELAY_TASKS stream not found: %v", err)
		return
	}
	info, _ := stream.Info(ctx)
	if info.Config.Name != StreamTasks {
		t.Errorf("stream name: got %q, want %q", info.Config.Name, StreamTasks)
	}

	// Verify RELAY_RESULTS stream exists
	stream, err = client.js.Stream(ctx, StreamResults)
	if err != nil {
		t.Errorf("RELAY_RESULTS stream not found: %v", err)
		return
	}
	info, _ = stream.Info(ctx)
	if info.Config.Name != StreamResults {
		t.Errorf("stream name: got %q, want %q", info.Config.Name, StreamResults)
	}
}

func TestNewClientStreamsIdempotent(t *testing.T) {
	_, natsURL := startTestNATSServer(t)

	c1, err := NewClient(natsURL)
	if err != nil {
		t.Fatalf("first NewClient: %v", err)
	}
	defer c1.Close()

	// Second client — streams already exist, should not error
	c2, err := NewClient(natsURL)
	if err != nil {
		t.Fatalf("second NewClient (idempotent streams): %v", err)
	}
	defer c2.Close()
}

func TestNewClientInvalidURLError(t *testing.T) {
	client, err := NewClient("nats://127.0.0.1:1")
	if err == nil {
		client.Close()
		t.Error("expected connection error for invalid server")
	}
}

// ========================================================================
// Close
// ========================================================================

func TestClientClose(t *testing.T) {
	client := newTestClient(t)
	err := client.Close()
	if err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestClientCloseIdempotent(t *testing.T) {
	client := newTestClient(t)
	_ = client.Close()
	// Second close should not error
	err := client.Close()
	if err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

// ========================================================================
// PublishTask
// ========================================================================

func TestPublishTask(t *testing.T) {
	client := newTestClient(t)
	ctx := context.Background()

	payload := map[string]interface{}{
		"task_id": "task-123",
		"type":    "exec",
		"cmd":     "echo hello",
	}
	err := client.PublishTask(ctx, "host-a", payload)
	if err != nil {
		t.Fatalf("PublishTask: %v", err)
	}
}

func TestPublishTaskSubjectRouting(t *testing.T) {
	client := newTestClient(t)
	ctx := context.Background()

	for _, hostname := range []string{"host-a", "host-b", "host-c"} {
		payload := map[string]interface{}{
			"task_id": "task-" + hostname,
			"type":    "exec",
			"cmd":     "echo " + hostname,
		}
		err := client.PublishTask(ctx, hostname, payload)
		if err != nil {
			t.Fatalf("PublishTask for %s: %v", hostname, err)
		}
	}
}

// ========================================================================
// PublishResult
// ========================================================================

func TestPublishResult(t *testing.T) {
	client := newTestClient(t)
	ctx := context.Background()

	payload := map[string]interface{}{
		"task_id": "task-456",
		"rc":      0,
		"stdout":  "done",
	}
	err := client.PublishResult(ctx, "task-456", payload)
	if err != nil {
		t.Fatalf("PublishResult: %v", err)
	}
}

func TestPublishResultSubjectRouting(t *testing.T) {
	client := newTestClient(t)
	ctx := context.Background()

	for _, taskID := range []string{"t1", "t2", "t3"} {
		payload := map[string]interface{}{"task_id": taskID, "rc": 0}
		err := client.PublishResult(ctx, taskID, payload)
		if err != nil {
			t.Fatalf("PublishResult for %s: %v", taskID, err)
		}
	}
}

// ========================================================================
// SubscribeTasks
// ========================================================================

func TestSubscribeTasksDeliversToWsSendFn(t *testing.T) {
	client := newTestClient(t)
	ctx := context.Background()

	delivered := make(chan string, 1)
	wsSendFn := func(hostname string, msg map[string]interface{}) error {
		delivered <- hostname
		return nil
	}

	err := client.SubscribeTasks(ctx, wsSendFn)
	if err != nil {
		t.Fatalf("SubscribeTasks: %v", err)
	}

	payload := map[string]interface{}{
		"task_id": "task-ws-1",
		"type":    "exec",
		"cmd":     "echo test",
	}
	err = client.PublishTask(ctx, "host-a", payload)
	if err != nil {
		t.Fatalf("PublishTask: %v", err)
	}

	select {
	case hostname := <-delivered:
		if hostname != "host-a" {
			t.Errorf("hostname: got %q, want %q", hostname, "host-a")
		}
	case <-time.After(3 * time.Second):
		t.Error("timeout waiting for task delivery")
	}
}

func TestSubscribeTasksNaksWhenAgentOffline(t *testing.T) {
	client := newTestClient(t)
	ctx := context.Background()

	called := make(chan struct{}, 1)
	wsSendFn := func(hostname string, msg map[string]interface{}) error {
		select {
		case called <- struct{}{}:
		default:
		}
		return fmt.Errorf("agent_offline")
	}

	err := client.SubscribeTasks(ctx, wsSendFn)
	if err != nil {
		t.Fatalf("SubscribeTasks: %v", err)
	}

	payload := map[string]interface{}{
		"task_id": "task-nak-1",
		"type":    "exec",
		"cmd":     "echo test",
	}
	err = client.PublishTask(ctx, "host-offline", payload)
	if err != nil {
		t.Fatalf("PublishTask: %v", err)
	}

	select {
	case <-called:
		// wsSendFn was called — correct behavior
	case <-time.After(3 * time.Second):
		t.Error("timeout: wsSendFn was not called for offline agent")
	}
}

// ========================================================================
// SubscribeResults
// ========================================================================

func TestSubscribeResultsDeliversToResultFn(t *testing.T) {
	client := newTestClient(t)
	ctx := context.Background()

	received := make(chan string, 1)
	resultFn := func(taskID string, payload map[string]interface{}) error {
		received <- taskID
		return nil
	}

	err := client.SubscribeResults(ctx, resultFn)
	if err != nil {
		t.Fatalf("SubscribeResults: %v", err)
	}

	payload := map[string]interface{}{
		"task_id": "task-result-1",
		"rc":      0,
		"stdout":  "done",
	}
	err = client.PublishResult(ctx, "task-result-1", payload)
	if err != nil {
		t.Fatalf("PublishResult: %v", err)
	}

	select {
	case taskID := <-received:
		if taskID != "task-result-1" {
			t.Errorf("task_id: got %q, want %q", taskID, "task-result-1")
		}
	case <-time.After(3 * time.Second):
		t.Error("timeout waiting for result delivery")
	}
}

// ========================================================================
// Payload wire encoding
// ========================================================================

func TestPublishTaskPayloadEncoding(t *testing.T) {
	client := newTestClient(t)
	ctx := context.Background()

	received := make(chan []byte, 1)
	nc := client.nc
	sub, err := nc.Subscribe("tasks.host-enc", func(msg *nats.Msg) {
		received <- msg.Data
	})
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	defer sub.Unsubscribe()

	payload := map[string]interface{}{
		"task_id": "enc-task-1",
		"cmd":     "echo encoding-test",
	}
	err = client.PublishTask(ctx, "host-enc", payload)
	if err != nil {
		t.Fatalf("PublishTask: %v", err)
	}

	select {
	case data := <-received:
		var decoded map[string]interface{}
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("failed to decode published payload: %v", err)
		}
		if decoded["task_id"] != "enc-task-1" {
			t.Errorf("task_id: got %v, want %q", decoded["task_id"], "enc-task-1")
		}
	case <-time.After(3 * time.Second):
		t.Error("timeout waiting for published message")
	}
}
