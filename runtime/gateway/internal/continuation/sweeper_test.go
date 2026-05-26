package continuation

import (
	"sync"
	"testing"
	"time"

	"ovara.runtime.gateway/internal/events"
)

type mockEventStore struct {
	mu     sync.Mutex
	events []*events.Event
}

func (m *mockEventStore) Append(evt *events.Event) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, evt)
}

func (m *mockEventStore) List(limit int) []*events.Event {
	m.mu.Lock()
	defer m.mu.Unlock()
	if limit <= 0 || limit > len(m.events) {
		limit = len(m.events)
	}
	return m.events[len(m.events)-limit:]
}

func (m *mockEventStore) Get(eventID string) (*events.Event, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := len(m.events) - 1; i >= 0; i-- {
		if m.events[i].EventID == eventID {
			return m.events[i], true
		}
	}
	return nil, false
}

func (m *mockEventStore) Count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.events)
}

func TestSweeper_SweepNow_ExpiresStale(t *testing.T) {
	store := NewInMemoryStore()
	mes := &mockEventStore{}
	sweeper := NewSweeper(store)
	sweeper.SetEventStore(mes)
	sweeper.SetGatewayID("gw_test")

	past := time.Now().UTC().Add(-2 * time.Hour)
	c1 := &Continuation{
		ContinuationID: "cnt_expire_1",
		DecisionID:     "dec_1",
		ActionType:     "shell",
		Resource:       "shell:ls",
		State:          StateApproved,
		CreatedAt:      time.Now().UTC().Add(-3 * time.Hour),
		ExpiresAt:      &past,
	}
	store.Create(c1)

	c2 := &Continuation{
		ContinuationID: "cnt_expire_2",
		DecisionID:     "dec_2",
		ActionType:     "shell",
		Resource:       "shell:ls",
		State:          StateEscalated,
		CreatedAt:      time.Now().UTC().Add(-5 * time.Hour),
		ExpiresAt:      &past,
	}
	store.Create(c2)

	future := time.Now().UTC().Add(1 * time.Hour)
	c3 := &Continuation{
		ContinuationID: "cnt_fresh",
		DecisionID:     "dec_3",
		ActionType:     "shell",
		Resource:       "shell:ls",
		State:          StateApproved,
		CreatedAt:      time.Now().UTC(),
		ExpiresAt:      &future,
	}
	store.Create(c3)

	count := sweeper.SweepNow()

	if count != 2 {
		t.Errorf("expected 2 expired, got %d", count)
	}

	got1, _ := store.Get("cnt_expire_1")
	if got1.State != StateExpired {
		t.Errorf("cnt_expire_1 state = %s, want expired", got1.State)
	}

	got2, _ := store.Get("cnt_expire_2")
	if got2.State != StateExpired {
		t.Errorf("cnt_expire_2 state = %s, want expired", got2.State)
	}

	got3, _ := store.Get("cnt_fresh")
	if got3.State != StateApproved {
		t.Errorf("cnt_fresh state = %s, want approved", got3.State)
	}

	if len(mes.events) != 2 {
		t.Errorf("expected 2 events emitted, got %d", len(mes.events))
	}
}

func TestSweeper_SweepNow_DoesNotExpireTerminal(t *testing.T) {
	store := NewInMemoryStore()
	mes := &mockEventStore{}
	sweeper := NewSweeper(store)
	sweeper.SetEventStore(mes)
	sweeper.SetGatewayID("gw_test")

	past := time.Now().UTC().Add(-2 * time.Hour)
	c := &Continuation{
		ContinuationID: "cnt_terminal",
		DecisionID:     "dec_1",
		ActionType:     "shell",
		Resource:       "shell:ls",
		State:          StateResumed,
		CreatedAt:      time.Now().UTC().Add(-3 * time.Hour),
		ExpiresAt:      &past,
	}
	store.Create(c)

	count := sweeper.SweepNow()

	if count != 0 {
		t.Errorf("expected 0 expired (terminal should not be expired), got %d", count)
	}

	got, _ := store.Get("cnt_terminal")
	if got.State != StateResumed {
		t.Errorf("cnt_terminal state = %s, want resumed", got.State)
	}
}

func TestSweeper_SweepNow_DoesNotExpireNoExpiry(t *testing.T) {
	store := NewInMemoryStore()
	mes := &mockEventStore{}
	sweeper := NewSweeper(store)
	sweeper.SetEventStore(mes)
	sweeper.SetGatewayID("gw_test")

	c := &Continuation{
		ContinuationID: "cnt_no_expiry",
		DecisionID:     "dec_1",
		ActionType:     "shell",
		Resource:       "shell:ls",
		State:          StateApproved,
		CreatedAt:      time.Now().UTC().Add(-5 * time.Hour),
		ExpiresAt:      nil,
	}
	store.Create(c)

	count := sweeper.SweepNow()

	if count != 0 {
		t.Errorf("expected 0 expired (no expiry set), got %d", count)
	}

	got, _ := store.Get("cnt_no_expiry")
	if got.State != StateApproved {
		t.Errorf("cnt_no_expiry state = %s, want approved", got.State)
	}
}

func TestSweeper_ReconcileOnStartup(t *testing.T) {
	store := NewInMemoryStore()
	mes := &mockEventStore{}
	sweeper := NewSweeper(store)
	sweeper.SetEventStore(mes)
	sweeper.SetGatewayID("gw_test")

	past := time.Now().UTC().Add(-1 * time.Hour)
	c1 := &Continuation{
		ContinuationID: "cnt_startup_expire",
		DecisionID:     "dec_1",
		ActionType:     "shell",
		Resource:       "shell:ls",
		State:          StateEscalated,
		CreatedAt:      time.Now().UTC().Add(-2 * time.Hour),
		ExpiresAt:      &past,
	}
	store.Create(c1)

	count := sweeper.ReconcileOnStartup()

	if count != 1 {
		t.Errorf("expected 1 expired on startup, got %d", count)
	}

	got, _ := store.Get("cnt_startup_expire")
	if got.State != StateExpired {
		t.Errorf("state = %s, want expired", got.State)
	}
	if got.ExpiredAt == nil {
		t.Error("expired_at should be set")
	}

	if len(mes.events) != 1 {
		t.Errorf("expected 1 expiration event, got %d", len(mes.events))
	}
	if mes.events[0].EventType != events.EventTypeContinuationExpired {
		t.Errorf("event type = %s, want %s", mes.events[0].EventType, events.EventTypeContinuationExpired)
	}
}

func TestSweeper_StartStop(t *testing.T) {
	store := NewInMemoryStore()
	mes := &mockEventStore{}
	sweeper := NewSweeper(store)
	sweeper.SetEventStore(mes)
	sweeper.SetGatewayID("gw_test")

	sweeper.Start(1)
	time.Sleep(100 * time.Millisecond)

	sweeper.Stop()

	sweeper.mu.Lock()
	running := sweeper.running
	sweeper.mu.Unlock()

	if running {
		t.Error("sweeper should not be running after Stop")
	}
}

func TestSweeper_StartTwiceNoOp(t *testing.T) {
	store := NewInMemoryStore()
	mes := &mockEventStore{}
	sweeper := NewSweeper(store)
	sweeper.SetEventStore(mes)
	sweeper.SetGatewayID("gw_test")

	sweeper.Start(1)
	time.Sleep(50 * time.Millisecond)
	sweeper.Start(1)
	time.Sleep(50 * time.Millisecond)

	sweeper.Stop()
}

func TestSweeper_SweepNow_ReturnsCount(t *testing.T) {
	store := NewInMemoryStore()
	mes := &mockEventStore{}
	sweeper := NewSweeper(store)
	sweeper.SetEventStore(mes)
	sweeper.SetGatewayID("gw_test")

	past := time.Now().UTC().Add(-1 * time.Hour)
	for i := 0; i < 5; i++ {
		c := &Continuation{
			ContinuationID: "cnt_multi_" + string(rune('0'+i)),
			DecisionID:     "dec_" + string(rune('0'+i)),
			ActionType:     "shell",
			Resource:       "shell:ls",
			State:          StateApproved,
			CreatedAt:      time.Now().UTC().Add(-2 * time.Hour),
			ExpiresAt:      &past,
		}
		store.Create(c)
	}

	count := sweeper.SweepNow()

	if count != 5 {
		t.Errorf("expected 5, got %d", count)
	}
}

func TestSweeper_SweepNow_EmitsExpiredEvent(t *testing.T) {
	store := NewInMemoryStore()
	mes := &mockEventStore{}
	sweeper := NewSweeper(store)
	sweeper.SetEventStore(mes)
	sweeper.SetGatewayID("gw_test_expire")

	past := time.Now().UTC().Add(-1 * time.Hour)
	c := &Continuation{
		ContinuationID: "cnt_event_test",
		DecisionID:     "dec_event",
		ApprovalID:     "apr_event",
		AgentID:        "agt_event",
		ActionType:     "shell",
		Resource:       "shell:ls",
		State:          StateApproved,
		CreatedAt:      time.Now().UTC().Add(-2 * time.Hour),
		ExpiresAt:      &past,
	}
	store.Create(c)

	sweeper.SweepNow()

	if len(mes.events) != 1 {
		t.Fatalf("expected 1 continuation.expired event, got %d", len(mes.events))
	}

	expiredEvt := mes.events[0]
	if expiredEvt.EventType != events.EventTypeContinuationExpired {
		t.Errorf("event[0] type = %s, want %s", expiredEvt.EventType, events.EventTypeContinuationExpired)
	}
	if expiredEvt.GatewayID != "gw_test_expire" {
		t.Errorf("gateway_id = %s, want gw_test_expire", expiredEvt.GatewayID)
	}
	if expiredEvt.ApprovalID != "apr_event" {
		t.Errorf("approval_id = %s, want apr_event", expiredEvt.ApprovalID)
	}
}