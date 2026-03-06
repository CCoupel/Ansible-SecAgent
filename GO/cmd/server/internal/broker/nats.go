package broker

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// Stream configuration constants — ARCHITECTURE.md §5
const (
	StreamTasks    = "RELAY_TASKS"
	StreamResults  = "RELAY_RESULTS"
	SubjectTasks   = "tasks.*"         // wildcard — subscribe to all hostnames
	SubjectResults = "results.*"       // wildcard — subscribe to all task results
	TasksTTLSec    = 300               // 5 minutes
	ResultsTTLSec  = 60               // 60 seconds
	TasksMaxBytes  = 1 * 1024 * 1024   // 1 MB
	ResultsMaxBytes = 5 * 1024 * 1024  // 5 MB
)

// Client represents a NATS JetStream client for the relay server
// Handles task publishing and result subscriptions for HA deployment
type Client struct {
	natsURL       string
	nc            *nats.Conn
	js            jetstream.JetStream
	nodeID        string
	wsSendFn      func(hostname string, message map[string]interface{}) error
	resultFn      func(taskID string, payload map[string]interface{}) error
	consumers     []jetstream.ConsumeContext
}

// TaskMessage represents a message being published to NATS
type TaskMessage struct {
	TaskID       string  `json:"task_id"`
	Type         string  `json:"type"`
	Cmd          string  `json:"cmd,omitempty"`
	Stdin        *string `json:"stdin,omitempty"`
	Timeout      int     `json:"timeout,omitempty"`
	Become       bool    `json:"become,omitempty"`
	BecomeMethod string  `json:"become_method,omitempty"`
	ExpiresAt    int64   `json:"expires_at,omitempty"`
}

// ResultMessage represents a result message from an agent
type ResultMessage struct {
	TaskID    string `json:"task_id"`
	RC        int    `json:"rc"`
	Stdout    string `json:"stdout"`
	Stderr    string `json:"stderr"`
	Truncated bool   `json:"truncated"`
	Error     string `json:"error,omitempty"`
}

// getNatsURL returns the NATS URL from environment or default
func getNatsURL() string {
	if url := os.Getenv("NATS_URL"); url != "" {
		return url
	}
	return "nats://localhost:4222"
}

// NewClient creates and connects a new NATS JetStream client
func NewClient(natsURL string) (*Client, error) {
	if natsURL == "" {
		natsURL = getNatsURL()
	}

	nc, err := nats.Connect(natsURL,
		nats.Name("relay-server"),
		nats.ReconnectWait(2*time.Second),
		nats.MaxReconnects(-1), // Reconnect forever
		nats.DisconnectErrHandler(func(nc *nats.Conn, err error) {
			if err != nil {
				log.Printf("NATS disconnected: %v", err)
			}
		}),
		nats.ReconnectHandler(func(nc *nats.Conn) {
			log.Printf("NATS reconnected [%s]", nc.ConnectedUrl())
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to NATS: %w", err)
	}

	js, err := jetstream.New(nc)
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("failed to create JetStream context: %w", err)
	}

	client := &Client{
		natsURL:   natsURL,
		nc:        nc,
		js:        js,
		nodeID:    "relay-server",
		consumers: []jetstream.ConsumeContext{},
	}

	// Ensure streams exist
	if err := client.ensureStreams(context.Background()); err != nil {
		client.Close()
		return nil, err
	}

	log.Printf("NATS client ready: url=%s", natsURL)
	return client, nil
}

// IsConnected returns true if the underlying NATS connection is open.
func (c *Client) IsConnected() bool {
	return c.nc != nil && c.nc.IsConnected()
}

// Close closes the NATS connection gracefully
func (c *Client) Close() error {
	// Stop all consumers
	for _, cc := range c.consumers {
		cc.Stop()
	}
	if c.nc != nil && !c.nc.IsClosed() {
		c.nc.Drain()
		log.Printf("NATS connection closed")
	}
	return nil
}

// ensureStreams creates RELAY_TASKS and RELAY_RESULTS streams if they don't exist
func (c *Client) ensureStreams(ctx context.Context) error {
	if err := c.ensureStream(ctx, StreamTasks, []string{"tasks.*"},
		jetstream.WorkQueuePolicy, TasksTTLSec, TasksMaxBytes); err != nil {
		return err
	}

	if err := c.ensureStream(ctx, StreamResults, []string{"results.*"},
		jetstream.LimitsPolicy, ResultsTTLSec, ResultsMaxBytes); err != nil {
		return err
	}

	return nil
}

// ensureStream creates a JetStream stream if it doesn't already exist
func (c *Client) ensureStream(ctx context.Context, name string, subjects []string,
	retention jetstream.RetentionPolicy, maxAge int, maxMsgSize int) error {

	cfg := jetstream.StreamConfig{
		Name:        name,
		Subjects:    subjects,
		Retention:   retention,
		MaxAge:      time.Duration(maxAge) * time.Second,
		MaxBytes:    int64(maxMsgSize),
		Storage:     jetstream.FileStorage,
		Replicas:    1,
	}

	_, err := c.js.CreateOrUpdateStream(ctx, cfg)
	if err != nil {
		return fmt.Errorf("failed to create/update stream %s: %w", name, err)
	}

	log.Printf("NATS stream ready: stream=%s", name)
	return nil
}

// PublishTask publishes a task to RELAY_TASKS for a specific agent
func (c *Client) PublishTask(ctx context.Context, hostname string, payload map[string]interface{}) error {
	subject := fmt.Sprintf("tasks.%s", hostname)
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal task: %w", err)
	}

	info, err := c.js.Publish(ctx, subject, data)
	if err != nil {
		return fmt.Errorf("failed to publish task to %s: %w", subject, err)
	}

	log.Printf("Task published to NATS: subject=%s seq=%d task_id=%v",
		subject, info.Sequence, payload["task_id"])
	return nil
}

// PublishResult publishes a task result to RELAY_RESULTS
func (c *Client) PublishResult(ctx context.Context, taskID string, payload map[string]interface{}) error {
	subject := fmt.Sprintf("results.%s", taskID)
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal result: %w", err)
	}

	info, err := c.js.Publish(ctx, subject, data)
	if err != nil {
		return fmt.Errorf("failed to publish result to %s: %w", subject, err)
	}

	log.Printf("Result published to NATS: subject=%s seq=%d task_id=%s",
		subject, info.Sequence, taskID)
	return nil
}

// SubscribeTasks subscribes to tasks.* and forwards them to agents via WebSocket
// This is for HA routing: each relay node subscribes and delivers tasks to local agents
// If an agent is not on this node, the message is NAK'd for another node to handle
func (c *Client) SubscribeTasks(ctx context.Context, wsSendFn func(hostname string, msg map[string]interface{}) error) error {
	c.wsSendFn = wsSendFn

	consumerName := fmt.Sprintf("relay-server-%s-tasks", c.nodeID)
	stream, err := c.js.Stream(ctx, StreamTasks)
	if err != nil {
		return fmt.Errorf("failed to get tasks stream: %w", err)
	}

	consumer, err := stream.CreateOrUpdateConsumer(ctx, jetstream.ConsumerConfig{
		Durable:       consumerName,
		AckPolicy:     jetstream.AckExplicitPolicy,
		MaxDeliver:    1, // No silent retry
		FilterSubject: SubjectTasks,
	})
	if err != nil {
		return fmt.Errorf("failed to create tasks consumer: %w", err)
	}

	cc, err := consumer.Consume(c.onTaskMessage)
	if err != nil {
		return fmt.Errorf("failed to subscribe to tasks: %w", err)
	}

	c.consumers = append(c.consumers, cc)
	log.Printf("Subscribed to NATS tasks.*: consumer=%s", consumerName)
	return nil
}

// onTaskMessage handles incoming task messages from NATS
func (c *Client) onTaskMessage(msg jetstream.Msg) {
	var payload map[string]interface{}
	if err := json.Unmarshal(msg.Data(), &payload); err != nil {
		log.Printf("Failed to decode NATS task message: %v", err)
		msg.Ack()
		return
	}

	// Extract hostname from subject: tasks.{hostname}
	hostname := ""
	if len(msg.Subject()) > 6 {
		hostname = msg.Subject()[6:] // Strip "tasks."
	}

	if hostname == "" {
		log.Printf("Malformed task subject: subject=%s", msg.Subject())
		msg.Ack()
		return
	}

	if c.wsSendFn == nil {
		msg.Nak()
		return
	}

	// Try to deliver via WebSocket
	if err := c.wsSendFn(hostname, payload); err != nil {
		log.Printf("Agent not on this node, NAK task: hostname=%s error=%v", hostname, err)
		msg.Nak()
		return
	}

	msg.Ack()
	log.Printf("Task delivered to agent: hostname=%s task_id=%v", hostname, payload["task_id"])
}

// SubscribeResults subscribes to results.* and delivers them to pending futures
// Used in HA deployment where the result is published by the node holding the agent WS
// and consumed by the node that received the original POST /api/exec request
func (c *Client) SubscribeResults(ctx context.Context, resultFn func(taskID string, payload map[string]interface{}) error) error {
	c.resultFn = resultFn

	consumerName := fmt.Sprintf("relay-server-%s-results", c.nodeID)
	stream, err := c.js.Stream(ctx, StreamResults)
	if err != nil {
		return fmt.Errorf("failed to get results stream: %w", err)
	}

	consumer, err := stream.CreateOrUpdateConsumer(ctx, jetstream.ConsumerConfig{
		Durable:       consumerName,
		AckPolicy:     jetstream.AckExplicitPolicy,
		MaxDeliver:    1,
		FilterSubject: SubjectResults,
	})
	if err != nil {
		return fmt.Errorf("failed to create results consumer: %w", err)
	}

	cc, err := consumer.Consume(c.onResultMessage)
	if err != nil {
		return fmt.Errorf("failed to subscribe to results: %w", err)
	}

	c.consumers = append(c.consumers, cc)
	log.Printf("Subscribed to NATS results.*: consumer=%s", consumerName)
	return nil
}

// onResultMessage handles incoming result messages from NATS
func (c *Client) onResultMessage(msg jetstream.Msg) {
	var payload map[string]interface{}
	if err := json.Unmarshal(msg.Data(), &payload); err != nil {
		log.Printf("Failed to decode NATS result message: %v", err)
		msg.Ack()
		return
	}

	// Extract task_id from subject: results.{task_id}
	taskID := ""
	if len(msg.Subject()) > 8 {
		taskID = msg.Subject()[8:] // Strip "results."
	}

	msg.Ack()

	if c.resultFn != nil && taskID != "" {
		if err := c.resultFn(taskID, payload); err != nil {
			log.Printf("resultFn raised for task: task_id=%s error=%v", taskID, err)
		}
	}
}
