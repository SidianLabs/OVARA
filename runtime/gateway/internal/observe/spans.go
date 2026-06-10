package observe

import (
	"context"
	"time"

	"ovara.runtime.gateway/internal/models"
)

type Span struct {
	TraceID    string
	SpanID     string
	Name       string
	StartTime  time.Time
	EndTime    time.Time
	Attributes map[string]string
	Events     []SpanEvent
	Status     string
	ParentID   string
}

type SpanEvent struct {
	Name       string
	Timestamp  time.Time
	Attributes map[string]string
}

type SpanKey struct{}

func StartDecisionSpan(ctx context.Context, req *models.ActionRequest) (context.Context, *Span) {
	span := &Span{
		TraceID:   generateTraceID(),
		SpanID:    generateSpanID(),
		Name:      "decision.evaluate",
		StartTime: time.Now().UTC(),
		Attributes: make(map[string]string),
		Status:    "OK",
	}

	if req != nil {
		span.Attributes["action_type"] = string(req.ActionType)
		span.Attributes["resource"] = req.Resource
		span.Attributes["environment"] = string(req.Environment)
		if req.AgentIdentity != nil {
			span.Attributes["agent_id"] = req.AgentIdentity.SubjectID
		}
	}

	if parentSpan := SpanFromContext(ctx); parentSpan != nil {
		span.ParentID = parentSpan.SpanID
		span.TraceID = parentSpan.TraceID
	}

	ctx = context.WithValue(ctx, SpanKey{}, span)
	return ctx, span
}

func StartExecutionSpan(ctx context.Context, continuationID string) (context.Context, *Span) {
	span := &Span{
		TraceID:   generateTraceID(),
		SpanID:    generateSpanID(),
		Name:      "execution.run",
		StartTime: time.Now().UTC(),
		Attributes: map[string]string{
			"continuation_id": continuationID,
		},
		Status: "OK",
	}

	if parentSpan := SpanFromContext(ctx); parentSpan != nil {
		span.ParentID = parentSpan.SpanID
		span.TraceID = parentSpan.TraceID
	}

	ctx = context.WithValue(ctx, SpanKey{}, span)
	return ctx, span
}

func StartApprovalSpan(ctx context.Context, approvalID string) (context.Context, *Span) {
	span := &Span{
		TraceID:   generateTraceID(),
		SpanID:    generateSpanID(),
		Name:      "approval.process",
		StartTime: time.Now().UTC(),
		Attributes: map[string]string{
			"approval_id": approvalID,
		},
		Status: "OK",
	}

	if parentSpan := SpanFromContext(ctx); parentSpan != nil {
		span.ParentID = parentSpan.SpanID
		span.TraceID = parentSpan.TraceID
	}

	ctx = context.WithValue(ctx, SpanKey{}, span)
	return ctx, span
}

func EndSpan(span *Span, decision models.Decision) {
	if span == nil {
		return
	}
	span.EndTime = time.Now().UTC()
	span.Attributes["decision"] = string(decision)

	switch decision {
	case models.DecisionDeny:
		span.Status = "ERROR"
	case models.DecisionEscalate:
		span.Status = "UNSET"
	default:
		span.Status = "OK"
	}
}

func SpanFromContext(ctx context.Context) *Span {
	if span, ok := ctx.Value(SpanKey{}).(*Span); ok {
		return span
	}
	return nil
}

func AddSpanAttribute(span *Span, key, value string) {
	if span == nil {
		return
	}
	if span.Attributes == nil {
		span.Attributes = make(map[string]string)
	}
	span.Attributes[key] = value
}

func AddSpanEvent(span *Span, name string, attrs map[string]string) {
	if span == nil {
		return
	}
	span.Events = append(span.Events, SpanEvent{
		Name:       name,
		Timestamp:  time.Now().UTC(),
		Attributes: attrs,
	})
}

func ToOTLPSpan(span *Span) OTLPSpan {
	if span == nil {
		return OTLPSpan{}
	}
	return OTLPSpan{
		TraceID:    span.TraceID,
		SpanID:     span.SpanID,
		Name:       span.Name,
		StartTime:  span.StartTime,
		EndTime:    span.EndTime,
		Attributes: span.Attributes,
		StatusCode: span.Status,
	}
}
