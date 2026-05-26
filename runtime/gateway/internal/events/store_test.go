package events

import (
	"testing"
	"time"
)

func TestNewEvent(t *testing.T) {
	e := NewEvent(EventTypeDecisionEvaluated)
	if e.EventID == "" {
		t.Error("event_id should not be empty")
	}
	if e.EventType != EventTypeDecisionEvaluated {
		t.Errorf("event_type = %s, want %s", e.EventType, EventTypeDecisionEvaluated)
	}
	if e.Timestamp.IsZero() {
		t.Error("timestamp should not be zero")
	}
}

func TestEvent_BuilderChaining(t *testing.T) {
	e := NewEvent(EventTypeApprovalCreated).
		WithGatewayID("gw_abc").
		WithAgentID("agt_123").
		WithDecisionID("dec_xyz").
		WithApprovalID("apr_789")

	if e.GatewayID != "gw_abc" {
		t.Errorf("gateway_id = %s, want gw_abc", e.GatewayID)
	}
	if e.AgentID != "agt_123" {
		t.Errorf("agent_id = %s, want agt_123", e.AgentID)
	}
	if e.DecisionID != "dec_xyz" {
		t.Errorf("decision_id = %s, want dec_xyz", e.DecisionID)
	}
	if e.ApprovalID != "apr_789" {
		t.Errorf("approval_id = %s, want apr_789", e.ApprovalID)
	}
}

func TestInMemoryStore_AppendAndList(t *testing.T) {
	store := NewInMemoryStore(100)

	e1 := NewEvent(EventTypeDecisionEvaluated).WithDecisionID("dec_1")
	e2 := NewEvent(EventTypeReceiptIssued).WithReceiptID("rcpt_1")

	store.Append(e1)
	store.Append(e2)

	if store.Count() != 2 {
		t.Errorf("count = %d, want 2", store.Count())
	}

	events := store.List(10)
	if len(events) != 2 {
		t.Errorf("list length = %d, want 2", len(events))
	}
}

func TestInMemoryStore_Get(t *testing.T) {
	store := NewInMemoryStore(100)

	e := NewEvent(EventTypeApprovalCreated).WithApprovalID("apr_test")
	store.Append(e)

	found, ok := store.Get(e.EventID)
	if !ok {
		t.Error("expected to find event by id")
	}
	if found.ApprovalID != "apr_test" {
		t.Errorf("approval_id = %s, want apr_test", found.ApprovalID)
	}
}

func TestInMemoryStore_NotFound(t *testing.T) {
	store := NewInMemoryStore(100)
	_, ok := store.Get("evt_nonexistent")
	if ok {
		t.Error("expected not found for nonexistent event id")
	}
}

func TestInMemoryStore_CountZero(t *testing.T) {
	store := NewInMemoryStore(100)
	if store.Count() != 0 {
		t.Errorf("count = %d, want 0", store.Count())
	}
}

func TestInMemoryStore_ListLimit(t *testing.T) {
	store := NewInMemoryStore(100)
	for i := 0; i < 5; i++ {
		e := NewEvent(EventTypeDecisionEvaluated).WithDecisionID("dec_" + string(rune('a'+i)))
		store.Append(e)
	}

	events := store.List(2)
	if len(events) != 2 {
		t.Errorf("list length = %d, want 2", len(events))
	}
}

func TestInMemoryStore_Latest(t *testing.T) {
	store := NewInMemoryStore(100)

	latest := NewEvent(EventTypePolicyReloaded).WithDecisionID("dec_latest")
	store.Append(NewEvent(EventTypeDecisionEvaluated))
	store.Append(latest)

	l := store.Latest()
	if l != latest {
		t.Error("Latest() should return the most recently appended event")
	}
}

func TestInMemoryStore_LatestNil(t *testing.T) {
	store := NewInMemoryStore(100)
	if store.Latest() != nil {
		t.Error("Latest() on empty store should return nil")
	}
}

func TestInMemoryStore_MaxLenEviction(t *testing.T) {
	maxEvents := 5
	store := NewInMemoryStore(maxEvents)

	for i := 0; i < maxEvents+3; i++ {
		e := NewEvent(EventTypeDecisionEvaluated).WithDecisionID("dec_" + string(rune('0'+i)))
		store.Append(e)
	}

	if store.Count() != maxEvents {
		t.Errorf("count = %d, want %d (should evict oldest)", store.Count(), maxEvents)
	}
}

func TestEvent_TimestampIsUTC(t *testing.T) {
	e := NewEvent(EventTypeDecisionEvaluated)
	if e.Timestamp.Location() != time.UTC {
		t.Error("timestamp should be UTC")
	}
}