package events

import (
	"sync"
	"time"

	"github.com/google/uuid"
)

const (
	EventTypeDecisionEvaluated   = "runtime.decision_evaluated"
	EventTypeApprovalCreated     = "approval.created"
	EventTypeApprovalResolved    = "approval.resolved"
	EventTypeReceiptIssued       = "receipt.issued"
	EventTypePolicyReloaded      = "policy.reloaded"
	EventTypeShieldRestrictionChanged = "shield.restriction_changed"
	EventTypeEnrollmentHeartbeat = "enrollment.heartbeat"
)

type Event struct {
	EventID    string         `json:"event_id"`
	EventType  string         `json:"event_type"`
	Timestamp  time.Time      `json:"timestamp"`
	GatewayID  string         `json:"gateway_id,omitempty"`
	AgentID    string         `json:"agent_id,omitempty"`
	TraceID    string         `json:"trace_id,omitempty"`
	DecisionID string         `json:"decision_id,omitempty"`
	ReceiptID  string         `json:"receipt_id,omitempty"`
	ApprovalID string         `json:"approval_id,omitempty"`
	Payload    map[string]any `json:"payload,omitempty"`
}

func NewEvent(eventType string) *Event {
	return &Event{
		EventID:   "evt_" + uuid.New().String()[:16],
		EventType: eventType,
		Timestamp: time.Now().UTC(),
	}
}

func (e *Event) WithGatewayID(id string) *Event {
	e.GatewayID = id
	return e
}

func (e *Event) WithAgentID(id string) *Event {
	e.AgentID = id
	return e
}

func (e *Event) WithTraceID(id string) *Event {
	e.TraceID = id
	return e
}

func (e *Event) WithDecisionID(id string) *Event {
	e.DecisionID = id
	return e
}

func (e *Event) WithReceiptID(id string) *Event {
	e.ReceiptID = id
	return e
}

func (e *Event) WithApprovalID(id string) *Event {
	e.ApprovalID = id
	return e
}

func (e *Event) WithPayload(payload map[string]any) *Event {
	e.Payload = payload
	return e
}

type Store interface {
	Append(event *Event)
	List(limit int) []*Event
	Get(eventID string) (*Event, bool)
	Count() int
}

type InMemoryStore struct {
	mu     sync.RWMutex
	events []*Event
	maxLen int
}

func NewInMemoryStore(maxEvents int) *InMemoryStore {
	if maxEvents <= 0 {
		maxEvents = 10000
	}
	return &InMemoryStore{
		events: make([]*Event, 0, maxEvents),
		maxLen: maxEvents,
	}
}

func (s *InMemoryStore) Append(event *Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, event)
	if len(s.events) > s.maxLen {
		s.events = s.events[len(s.events)-s.maxLen:]
	}
}

func (s *InMemoryStore) List(limit int) []*Event {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if limit <= 0 || limit > len(s.events) {
		limit = len(s.events)
	}
	result := make([]*Event, limit)
	copy(result, s.events[len(s.events)-limit:])
	return result
}

func (s *InMemoryStore) Get(eventID string) (*Event, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for i := len(s.events) - 1; i >= 0; i-- {
		if s.events[i].EventID == eventID {
			return s.events[i], true
		}
	}
	return nil, false
}

func (s *InMemoryStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.events)
}

func (s *InMemoryStore) Latest() *Event {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.events) == 0 {
		return nil
	}
	return s.events[len(s.events)-1]
}