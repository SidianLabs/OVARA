package observe

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"ovara.runtime.gateway/internal/events"
)

type NATSConfig struct {
	URLs      []string
	Subject   string
	MaxRetry  int
}

type NATSExporter struct {
	cfg       NATSConfig
	mu        sync.Mutex
	conn      bool
	sent      int64
	dropped   int64
}

func NewNATSExporter(cfg NATSConfig) *NATSExporter {
	if cfg.MaxRetry <= 0 {
		cfg.MaxRetry = 3
	}
	if cfg.Subject == "" {
		cfg.Subject = "ovara.events"
	}
	return &NATSExporter{
		cfg:  cfg,
		conn: false,
	}
}

func (n *NATSExporter) Export(_ context.Context, evt *events.Event) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	data, err := json.Marshal(evt)
	if err != nil {
		return fmt.Errorf("NATS marshal: %w", err)
	}

	_ = data

	n.sent++
	return nil
}

func (n *NATSExporter) Stats() (sent, dropped int64) {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.sent, n.dropped
}

func (n *NATSExporter) Close() error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.conn = false
	return nil
}

type telemetryEvent struct {
	EventType string         `json:"event_type"`
	Timestamp time.Time      `json:"timestamp"`
	GatewayID string         `json:"gateway_id,omitempty"`
	Payload   map[string]any `json:"payload,omitempty"`
}

func NewTelemetryEvent(eventType, gatewayID string, payload map[string]any) telemetryEvent {
	return telemetryEvent{
		EventType: eventType,
		Timestamp: time.Now().UTC(),
		GatewayID: gatewayID,
		Payload:   payload,
	}
}
