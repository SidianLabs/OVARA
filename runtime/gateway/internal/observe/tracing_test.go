package observe

import (
	"context"
	"testing"
	"time"

	"ovara.runtime.gateway/internal/models"
)

func TestInitTracer(t *testing.T) {
	config := DefaultTracerConfig()
	tp := InitTracer(config)

	if tp == nil {
		t.Fatal("InitTracer returned nil")
	}

	if !tp.IsRunning() {
		t.Fatal("tracer provider should be running after init")
	}

	cfg := tp.Config()
	if cfg.ServiceName != "ovara-gateway" {
		t.Errorf("expected service name 'ovara-gateway', got %q", cfg.ServiceName)
	}
	if cfg.Endpoint != "localhost:4317" {
		t.Errorf("expected endpoint 'localhost:4317', got %q", cfg.Endpoint)
	}
	if cfg.SampleRate != 1.0 {
		t.Errorf("expected sample rate 1.0, got %f", cfg.SampleRate)
	}

	ctx := context.Background()
	if err := tp.Shutdown(ctx); err != nil {
		t.Fatalf("shutdown failed: %v", err)
	}

	if tp.IsRunning() {
		t.Fatal("tracer provider should not be running after shutdown")
	}
}

func TestInitTracerDefaults(t *testing.T) {
	tp := InitTracer(TracerConfig{})

	cfg := tp.Config()
	if cfg.ServiceName != "ovara-gateway" {
		t.Errorf("expected default service name, got %q", cfg.ServiceName)
	}
	if cfg.Endpoint != "localhost:4317" {
		t.Errorf("expected default endpoint, got %q", cfg.Endpoint)
	}
	if cfg.SampleRate != 1.0 {
		t.Errorf("expected default sample rate 1.0, got %f", cfg.SampleRate)
	}
}

func TestStartDecisionSpan(t *testing.T) {
	req := &models.ActionRequest{
		ActionType:  models.ActionTypeShell,
		Resource:    "/bin/bash",
		Environment: models.EnvironmentLocal,
		AgentIdentity: &models.AgentIdentity{
			SubjectID: "agent-123",
		},
	}

	ctx := context.Background()
	ctx, span := StartDecisionSpan(ctx, req)

	if span == nil {
		t.Fatal("StartDecisionSpan returned nil span")
	}

	if span.Name != "decision.evaluate" {
		t.Errorf("expected span name 'decision.evaluate', got %q", span.Name)
	}

	if span.Attributes["action_type"] != "shell" {
		t.Errorf("expected action_type 'shell', got %q", span.Attributes["action_type"])
	}
	if span.Attributes["resource"] != "/bin/bash" {
		t.Errorf("expected resource '/bin/bash', got %q", span.Attributes["resource"])
	}
	if span.Attributes["environment"] != "local" {
		t.Errorf("expected environment 'local', got %q", span.Attributes["environment"])
	}
	if span.Attributes["agent_id"] != "agent-123" {
		t.Errorf("expected agent_id 'agent-123', got %q", span.Attributes["agent_id"])
	}

	if span.TraceID == "" {
		t.Error("trace ID should not be empty")
	}
	if span.SpanID == "" {
		t.Error("span ID should not be empty")
	}
	if span.Status != "OK" {
		t.Errorf("expected status 'OK', got %q", span.Status)
	}

	got := SpanFromContext(ctx)
	if got != span {
		t.Error("span not found in context")
	}
}

func TestStartExecutionSpan(t *testing.T) {
	ctx := context.Background()
	ctx, span := StartExecutionSpan(ctx, "cont-456")

	if span == nil {
		t.Fatal("StartExecutionSpan returned nil span")
	}

	if span.Name != "execution.run" {
		t.Errorf("expected span name 'execution.run', got %q", span.Name)
	}
	if span.Attributes["continuation_id"] != "cont-456" {
		t.Errorf("expected continuation_id 'cont-456', got %q", span.Attributes["continuation_id"])
	}

	got := SpanFromContext(ctx)
	if got != span {
		t.Error("span not found in context")
	}
}

func TestStartApprovalSpan(t *testing.T) {
	ctx := context.Background()
	ctx, span := StartApprovalSpan(ctx, "apr-789")

	if span == nil {
		t.Fatal("StartApprovalSpan returned nil span")
	}

	if span.Name != "approval.process" {
		t.Errorf("expected span name 'approval.process', got %q", span.Name)
	}
	if span.Attributes["approval_id"] != "apr-789" {
		t.Errorf("expected approval_id 'apr-789', got %q", span.Attributes["approval_id"])
	}

	got := SpanFromContext(ctx)
	if got != span {
		t.Error("span not found in context")
	}
}

func TestSpanAttributes(t *testing.T) {
	span := &Span{
		TraceID:   generateTraceID(),
		SpanID:    generateSpanID(),
		Name:      "test-span",
		StartTime: time.Now().UTC(),
		Attributes: make(map[string]string),
	}

	AddSpanAttribute(span, "custom_key", "custom_value")
	if span.Attributes["custom_key"] != "custom_value" {
		t.Errorf("expected custom_key 'custom_value', got %q", span.Attributes["custom_key"])
	}

	AddSpanEvent(span, "test.event", map[string]string{"key": "val"})
	if len(span.Events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(span.Events))
	}
	if span.Events[0].Name != "test.event" {
		t.Errorf("expected event name 'test.event', got %q", span.Events[0].Name)
	}
}

func TestSpanAttributesNilSpan(t *testing.T) {
	AddSpanAttribute(nil, "key", "val")
	AddSpanEvent(nil, "event", nil)
}

func TestEndSpan(t *testing.T) {
	span := &Span{
		TraceID:   generateTraceID(),
		SpanID:    generateSpanID(),
		Name:      "test",
		StartTime: time.Now().UTC(),
		Attributes: make(map[string]string),
	}

	EndSpan(span, models.DecisionAllow)
	if span.EndTime.IsZero() {
		t.Error("end time should be set")
	}
	if span.Attributes["decision"] != "allow" {
		t.Errorf("expected decision 'allow', got %q", span.Attributes["decision"])
	}
	if span.Status != "OK" {
		t.Errorf("expected status 'OK' for allow, got %q", span.Status)
	}

	EndSpan(span, models.DecisionDeny)
	if span.Status != "ERROR" {
		t.Errorf("expected status 'ERROR' for deny, got %q", span.Status)
	}

	EndSpan(span, models.DecisionEscalate)
	if span.Status != "UNSET" {
		t.Errorf("expected status 'UNSET' for escalate, got %q", span.Status)
	}

	EndSpan(nil, models.DecisionAllow)
}

func TestSpanParentChild(t *testing.T) {
	ctx := context.Background()
	ctx, parent := StartDecisionSpan(ctx, &models.ActionRequest{
		ActionType:  models.ActionTypeShell,
		Resource:    "/bin/bash",
		Environment: models.EnvironmentLocal,
	})

	_, child := StartExecutionSpan(ctx, "cont-1")

	if child.ParentID != parent.SpanID {
		t.Errorf("child parent ID %q != parent span ID %q", child.ParentID, parent.SpanID)
	}
	if child.TraceID != parent.TraceID {
		t.Errorf("child trace ID %q != parent trace ID %q", child.TraceID, parent.TraceID)
	}
}

func TestSpanFromContextEmpty(t *testing.T) {
	span := SpanFromContext(context.Background())
	if span != nil {
		t.Error("expected nil span from empty context")
	}
}

func TestToOTLPSpan(t *testing.T) {
	span := &Span{
		TraceID:   "trace-1",
		SpanID:    "span-1",
		Name:      "test",
		StartTime: time.Now().UTC(),
		EndTime:   time.Now().UTC(),
		Attributes: map[string]string{"k": "v"},
		Status:    "OK",
	}

	otlp := ToOTLPSpan(span)
	if otlp.TraceID != "trace-1" {
		t.Errorf("expected trace ID 'trace-1', got %q", otlp.TraceID)
	}
	if otlp.Name != "test" {
		t.Errorf("expected name 'test', got %q", otlp.Name)
	}

	empty := ToOTLPSpan(nil)
	if empty.TraceID != "" {
		t.Error("expected empty trace ID for nil span")
	}
}

func TestShutdownTracer(t *testing.T) {
	tp := InitTracer(DefaultTracerConfig())

	if !tp.IsRunning() {
		t.Fatal("tracer should be running")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := tp.Shutdown(ctx); err != nil {
		t.Fatalf("shutdown failed: %v", err)
	}

	if tp.IsRunning() {
		t.Fatal("tracer should not be running after shutdown")
	}

	if err := tp.Shutdown(ctx); err != nil {
		t.Fatalf("double shutdown should not fail: %v", err)
	}
}
