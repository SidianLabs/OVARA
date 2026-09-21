package collector

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestNewEvent(t *testing.T) {
	evt := NewEvent("test.event", "gw-001")
	if evt.EventID == "" {
		t.Error("event ID should not be empty")
	}
	if evt.EventType != "test.event" {
		t.Errorf("EventType = %v, want test.event", evt.EventType)
	}
	if evt.GatewayID != "gw-001" {
		t.Errorf("GatewayID = %v, want gw-001", evt.GatewayID)
	}
	if evt.Timestamp.IsZero() {
		t.Error("timestamp should not be zero")
	}
}

type mockWriter struct {
	mu     sync.Mutex
	events [][]*Event
}

func (w *mockWriter) WriteEvents(_ context.Context, events []*Event) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.events = append(w.events, events)
	return nil
}

func (w *mockWriter) totalEvents() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	count := 0
	for _, batch := range w.events {
		count += len(batch)
	}
	return count
}

type mockNATSCollector struct {
	published int64
	err       error
}

func (m *mockNATSCollector) Publish(_ context.Context, _ *Event) error {
	if m.err != nil {
		atomic.AddInt64(&m.published, 1)
		return m.err
	}
	atomic.AddInt64(&m.published, 1)
	return nil
}

func TestPipeline_IngestAndFlush(t *testing.T) {
	w := &mockWriter{}
	nc := &mockNATSCollector{}

	bufSize := 5
	ncCollector := &NATSCollector{}

	p := NewPipeline(ncCollector, []Writer{w}, bufSize)
	_ = nc

	for range 5 {
		p.Ingest(NewEvent("test.ingest", "gw-001"))
	}

	time.Sleep(50 * time.Millisecond)
	p.flush()

	if w.totalEvents() != 5 {
		t.Errorf("expected 5 events flushed, got %d", w.totalEvents())
	}
}

func TestPipeline_IntervalFlush(t *testing.T) {
	w := &mockWriter{}
	ncCollector := &NATSCollector{}

	p := NewPipeline(ncCollector, []Writer{w}, 100)
	p.Start(10 * time.Millisecond)

	for range 2 {
		p.Ingest(NewEvent("test.interval", "gw-003"))
	}

	time.Sleep(60 * time.Millisecond)
	p.Stop()

	if w.totalEvents() != 2 {
		t.Errorf("expected 2 events flushed, got %d", w.totalEvents())
	}
}

func TestPipeline_StopFlushesRemaining(t *testing.T) {
	w := &mockWriter{}
	ncCollector := &NATSCollector{}

	p := NewPipeline(ncCollector, []Writer{w}, 100)
	p.Start(time.Hour)

	for range 3 {
		p.Ingest(NewEvent("test.stop", "gw-004"))
	}

	p.Stop()

	if w.totalEvents() != 3 {
		t.Errorf("expected 3 events flushed, got %d", w.totalEvents())
	}
}

func TestClickHouseEscape(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"simple", "simple"},
		{"it's", "it\\'s"},
		{"path\\to", "path\\\\to"},
		{"mix'ed", "mix\\'ed"},
	}

	for _, tt := range tests {
		got := escape(tt.input)
		if got != tt.expected {
			t.Errorf("escape(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestNewNATSCollector_InvalidURL(t *testing.T) {
	_, err := NewNATSCollector("nats://invalid-host:4222", "test.subject")
	if err == nil {
		t.Error("expected error for invalid NATS URL")
	}
}
