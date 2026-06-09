package observe

import (
	"context"
	"sync"
	"testing"
	"time"

	"ovara.runtime.gateway/internal/events"
)

type testExporter struct {
	mu       sync.Mutex
	exported []*events.Event
}

func (t *testExporter) Export(_ context.Context, evt *events.Event) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.exported = append(t.exported, evt)
	return nil
}

func (t *testExporter) Close() error { return nil }

func (t *testExporter) Count() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.exported)
}

func TestPipeline_Send(t *testing.T) {
	exp := &testExporter{}
	pipe := NewPipeline(exp)
	pipe.Start(context.Background())

	evt := events.NewEvent(events.EventTypeDecisionEvaluated).
		WithGatewayID("gw-test").
		WithDecisionID("dec-001")

	pipe.Send(context.Background(), evt)

	if exp.Count() != 1 {
		t.Errorf("expected 1 event, got %d", exp.Count())
	}

	if exp.exported[0].EventType != events.EventTypeDecisionEvaluated {
		t.Errorf("event type = %v, want %v", exp.exported[0].EventType, events.EventTypeDecisionEvaluated)
	}
}

func TestPipeline_MultipleExporters(t *testing.T) {
	e1 := &testExporter{}
	e2 := &testExporter{}
	pipe := NewPipeline(e1, e2)
	pipe.Start(context.Background())

	evt := events.NewEvent("test.event")
	pipe.Send(context.Background(), evt)

	if e1.Count() != 1 || e2.Count() != 1 {
		t.Errorf("both exporters should receive event: e1=%d, e2=%d", e1.Count(), e2.Count())
	}
}

func TestPipeline_Shutdown(t *testing.T) {
	exp := &testExporter{}
	pipe := NewPipeline(exp)
	pipe.Start(context.Background())
	pipe.Shutdown()

	evt := events.NewEvent("test.event")
	pipe.Send(context.Background(), evt)

	if exp.Count() != 0 {
		t.Errorf("event sent after shutdown should not be exported")
	}
}

func TestOTLPExporter_AddSpan(t *testing.T) {
	e := NewOTLPExporter(10, time.Hour)
	span := OTLPSpan{
		TraceID:    "trace-1",
		SpanID:     "span-1",
		Name:       "policy.evaluate",
		StartTime:  time.Now(),
		EndTime:    time.Now().Add(time.Microsecond * 5),
		StatusCode: "OK",
	}

	e.AddSpan(span)

	spans := e.Spans()
	if len(spans) != 1 {
		t.Fatalf("expected 1 span, got %d", len(spans))
	}
	if spans[0].TraceID != "trace-1" {
		t.Errorf("TraceID = %v, want trace-1", spans[0].TraceID)
	}
}

func TestOTLPExporter_MaxSpans(t *testing.T) {
	maxSpans := 5
	e := NewOTLPExporter(maxSpans, time.Hour)

	for i := range maxSpans + 3 {
		e.AddSpan(OTLPSpan{TraceID: "overflow", SpanID: "s"})
		_ = i
	}

	spans := e.Spans()
	if len(spans) != maxSpans {
		t.Errorf("expected %d spans after overflow, got %d", maxSpans, len(spans))
	}
}

func TestNATSExporter_Config(t *testing.T) {
	cfg := NATSConfig{
		URLs:    []string{"nats://localhost:4222"},
		Subject: "ovara.test",
	}
	exp := NewNATSExporter(cfg)
	if exp.cfg.Subject != "ovara.test" {
		t.Errorf("Subject = %v, want ovara.test", exp.cfg.Subject)
	}

	cfg2 := NATSConfig{}
	exp2 := NewNATSExporter(cfg2)
	if exp2.cfg.Subject != "ovara.events" {
		t.Errorf("Subject = %v, want ovara.events (default)", exp2.cfg.Subject)
	}
	if exp2.cfg.MaxRetry != 3 {
		t.Errorf("MaxRetry = %v, want 3 (default)", exp2.cfg.MaxRetry)
	}
}

func TestNATSExporter_Send(t *testing.T) {
	exp := NewNATSExporter(NATSConfig{URLs: []string{"nats://localhost:4222"}})
	evt := events.NewEvent("test.event").WithGatewayID("gw-nats")
	err := exp.Export(context.Background(), evt)
	if err != nil {
		t.Errorf("Export failed: %v", err)
	}
	sent, dropped := exp.Stats()
	if sent != 1 {
		t.Errorf("sent = %d, want 1", sent)
	}
	if dropped != 0 {
		t.Errorf("dropped = %d, want 0", dropped)
	}
}

func TestNATSExporter_Close(t *testing.T) {
	exp := NewNATSExporter(NATSConfig{})
	err := exp.Close()
	if err != nil {
		t.Errorf("Close failed: %v", err)
	}
}

func TestMetricsBridge_EmitSnapshot(t *testing.T) {
	exp := &testExporter{}
	pipe := NewPipeline(exp)
	pipe.Start(context.Background())

	m := newMockMetrics()
	bridge := NewMetricsBridge(m, pipe, "gw-bridge", 10*time.Millisecond)
	bridge.Start()

	time.Sleep(30 * time.Millisecond)
	bridge.Stop()

	if exp.Count() < 1 {
		t.Error("expected at least 1 metrics snapshot event")
	}
	if exp.exported[0].EventType != "telemetry.metrics_snapshot" {
		t.Errorf("event type = %v, want telemetry.metrics_snapshot", exp.exported[0].EventType)
	}
	if exp.exported[0].GatewayID != "gw-bridge" {
		t.Errorf("gatewayID = %v, want gw-bridge", exp.exported[0].GatewayID)
	}
}

func TestConsoleExporter(t *testing.T) {
	exp := NewConsoleExporter()
	evt := events.NewEvent("test.console")
	err := exp.Export(context.Background(), evt)
	if err != nil {
		t.Errorf("ConsoleExporter.Export failed: %v", err)
	}
	if err := exp.Close(); err != nil {
		t.Errorf("ConsoleExporter.Close failed: %v", err)
	}
}

func TestNoopExporter(t *testing.T) {
	exp := &NoopExporter{}
	if err := exp.Export(context.Background(), nil); err != nil {
		t.Errorf("NoopExporter.Export failed: %v", err)
	}
	if err := exp.Close(); err != nil {
		t.Errorf("NoopExporter.Close failed: %v", err)
	}
}

type mockMetrics struct {
	totalDecisions int
	avgLatencyMs   int64
	approvalCount  int
	heartbeatCount int
	reloadStatus   string
}

func newMockMetrics() *mockMetrics {
	return &mockMetrics{
		totalDecisions: 150,
		avgLatencyMs:   5,
		approvalCount:  10,
		heartbeatCount: 300,
		reloadStatus:   "ok",
	}
}

func (m *mockMetrics) Snapshot() MetricsSnapshot {
	return MetricsSnapshot{
		TotalDecisions:     m.totalDecisions,
		AvgLatencyMs:       m.avgLatencyMs,
		ApprovalCounts:     m.approvalCount,
		HeartbeatCount:     m.heartbeatCount,
		PolicyReloadStatus: m.reloadStatus,
	}
}
