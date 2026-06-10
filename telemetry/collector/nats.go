package collector

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
)

type Event struct {
	EventID   string    `json:"event_id"`
	EventType string    `json:"event_type"`
	GatewayID string    `json:"gateway_id"`
	AgentID   string    `json:"agent_id,omitempty"`
	Decision  string    `json:"decision,omitempty"`
	Action    string    `json:"action,omitempty"`
	Resource  string    `json:"resource,omitempty"`
	TrustScore float64  `json:"trust_score,omitempty"`
	Payload   json.RawMessage `json:"payload,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

type NATSCollector struct {
	nc          *nats.Conn
	js          nats.JetStreamContext
	subject     string
	streamName  string
	mu          sync.RWMutex
	sent        int64
	dropped     int64
	connected   bool
}

func NewNATSCollector(url, subject string) (*NATSCollector, error) {
	nc, err := nats.Connect(url,
		nats.Timeout(5*time.Second),
		nats.ReconnectWait(2*time.Second),
		nats.MaxReconnects(-1),
		nats.DisconnectErrHandler(func(_ *nats.Conn, err error) {
			fmt.Printf("NATS disconnected: %v\n", err)
		}),
		nats.ReconnectHandler(func(_ *nats.Conn) {
			fmt.Println("NATS reconnected")
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("NATS connect: %w", err)
	}

	js, err := nc.JetStream()
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("JetStream context: %w", err)
	}

	return &NATSCollector{
		nc:        nc,
		js:        js,
		subject:   subject,
		streamName: "OVARA_EVENTS",
		connected: true,
	}, nil
}

func (c *NATSCollector) EnsureStream() error {
	_, err := c.js.AddStream(&nats.StreamConfig{
		Name:     c.streamName,
		Subjects: []string{c.subject},
		Storage:  nats.FileStorage,
		MaxAge:   7 * 24 * time.Hour,
		MaxBytes: 10 * 1024 * 1024 * 1024,
	})
	if err != nil {
		if err.Error() == "stream name already in use" {
			return nil
		}
		return fmt.Errorf("create stream: %w", err)
	}
	return nil
}

func (c *NATSCollector) Publish(ctx context.Context, evt *Event) error {
	if !c.connected {
		atomic.AddInt64(&c.dropped, 1)
		return fmt.Errorf("not connected")
	}

	data, err := json.Marshal(evt)
	if err != nil {
		return fmt.Errorf("marshal event: %w", err)
	}

	_, err = c.js.Publish(c.subject, data)
	if err != nil {
		atomic.AddInt64(&c.dropped, 1)
		return fmt.Errorf("publish event: %w", err)
	}

	atomic.AddInt64(&c.sent, 1)
	return nil
}

func (c *NATSCollector) Stats() (sent, dropped int64) {
	return atomic.LoadInt64(&c.sent), atomic.LoadInt64(&c.dropped)
}

func (c *NATSCollector) IsConnected() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.connected
}

func (c *NATSCollector) Close() error {
	c.mu.Lock()
	c.connected = false
	c.mu.Unlock()
	c.nc.Close()
	return nil
}

func NewEvent(eventType, gatewayID string) *Event {
	return &Event{
		EventID:   "evt_" + uuid.NewString()[:16],
		EventType: eventType,
		GatewayID: gatewayID,
		Timestamp: time.Now().UTC(),
	}
}
