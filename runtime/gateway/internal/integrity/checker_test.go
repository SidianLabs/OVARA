package integrity

import (
	"errors"
	"testing"
	"time"

	"ovara.runtime.gateway/internal/approval"
	"ovara.runtime.gateway/internal/continuation"
	"ovara.runtime.gateway/internal/events"
	"ovara.runtime.gateway/internal/execution"
	"ovara.runtime.gateway/internal/models"
)

type mockEventStore struct {
	events []*events.Event
	count  int
}

func (m *mockEventStore) Append(e *events.Event) {}
func (m *mockEventStore) List(limit int) []*events.Event {
	if limit <= 0 || limit > len(m.events) {
		return m.events
	}
	return m.events[len(m.events)-limit:]
}
func (m *mockEventStore) Get(id string) (*events.Event, bool) {
	for _, e := range m.events {
		if e.EventID == id {
			return e, true
		}
	}
	return nil, false
}
func (m *mockEventStore) Count() int {
	if m.count > 0 {
		return m.count
	}
	return len(m.events)
}

type mockContinuationStore struct {
	continuations []*continuation.Continuation
}

func (m *mockContinuationStore) Create(c *continuation.Continuation) error {
	return nil
}
func (m *mockContinuationStore) Get(id string) (*continuation.Continuation, bool) {
	for _, c := range m.continuations {
		if c.ContinuationID == id {
			return c, true
		}
	}
	return nil, false
}
func (m *mockContinuationStore) Update(c *continuation.Continuation) error {
	return nil
}
func (m *mockContinuationStore) ListByState(state continuation.State) []*continuation.Continuation {
	var result []*continuation.Continuation
	for _, c := range m.continuations {
		if c.State == state {
			result = append(result, c)
		}
	}
	return result
}
func (m *mockContinuationStore) ListByDecision(decisionID string) []*continuation.Continuation {
	return nil
}
func (m *mockContinuationStore) ListByAgent(agentID string) []*continuation.Continuation {
	return nil
}
func (m *mockContinuationStore) ListByApprovalID(approvalID string) []*continuation.Continuation {
	return nil
}
func (m *mockContinuationStore) ListAll() []*continuation.Continuation {
	return m.continuations
}
func (m *mockContinuationStore) ListNonTerminal() []*continuation.Continuation {
	var result []*continuation.Continuation
	for _, c := range m.continuations {
		if !c.IsTerminal() {
			result = append(result, c)
		}
	}
	return result
}

func (m *mockContinuationStore) ClaimForExecution(id string) (*continuation.Continuation, bool) {
	return nil, false
}

func (m *mockContinuationStore) ClaimForRetry(id string) (*continuation.Continuation, bool) {
	return nil, false
}

func (m *mockContinuationStore) RetryForExecution(id string) (*continuation.Continuation, bool) {
	return nil, false
}

func (m *mockContinuationStore) CancelForOperation(id string) (*continuation.Continuation, bool) {
	return nil, false
}

type mockExecutionStore struct {
	executions []*execution.Execution
	stats     (func() (total, succeeded, failed, running, timedOut int))
}

func (m *mockExecutionStore) Create(e *execution.Execution) error {
	return nil
}
func (m *mockExecutionStore) Get(id string) (*execution.Execution, bool) {
	for _, e := range m.executions {
		if e.ExecutionID == id {
			return e, true
		}
	}
	return nil, false
}
func (m *mockExecutionStore) Update(e *execution.Execution) error {
	return nil
}
func (m *mockExecutionStore) ListByContinuation(continuationID string) []*execution.Execution {
	var result []*execution.Execution
	for _, e := range m.executions {
		if e.ContinuationID == continuationID {
			result = append(result, e)
		}
	}
	return result
}
func (m *mockExecutionStore) ListByDecision(decisionID string) []*execution.Execution {
	var result []*execution.Execution
	for _, e := range m.executions {
		if e.DecisionID == decisionID {
			result = append(result, e)
		}
	}
	return result
}
func (m *mockExecutionStore) ListAll() []*execution.Execution {
	return m.executions
}
func (m *mockExecutionStore) ListByState(state execution.State) []*execution.Execution {
	var result []*execution.Execution
	for _, e := range m.executions {
		if e.State == state {
			result = append(result, e)
		}
	}
	return result
}
func (m *mockExecutionStore) Stats() (total, succeeded, failed, running, timedOut int) {
	if m.stats != nil {
		return m.stats()
	}
	return len(m.executions), 0, 0, 0, 0
}

type mockReceiptStore struct {
	receipts []*models.Receipt
}

func (m *mockReceiptStore) Put(r *models.Receipt) error {
	return nil
}
func (m *mockReceiptStore) Get(id string) (*models.Receipt, error) {
	for _, r := range m.receipts {
		if r.ReceiptID == id {
			return r, nil
		}
	}
	return nil, errors.New("not found")
}
func (m *mockReceiptStore) ListByDecision(decisionID string) []*models.Receipt {
	return nil
}
func (m *mockReceiptStore) ListByAgent(agentID string) []*models.Receipt {
	return nil
}
func (m *mockReceiptStore) ListAll() []*models.Receipt {
	return m.receipts
}

type mockApprovalStore struct {
	pending []*approval.ApprovalRequest
}

func (m *mockApprovalStore) Create(req *approval.ApprovalRequest) error {
	return nil
}
func (m *mockApprovalStore) Get(id string) (*approval.ApprovalRequest, error) {
	for _, a := range m.pending {
		if a.ApprovalID == id {
			return a, nil
		}
	}
	return nil, errors.New("not found")
}
func (m *mockApprovalStore) Update(req *approval.ApprovalRequest) error {
	return nil
}
func (m *mockApprovalStore) ListAll() []*approval.ApprovalRequest {
	return m.pending
}
func (m *mockApprovalStore) ListByStatus(status approval.Status) []*approval.ApprovalRequest {
	if status == approval.StatusPending {
		return m.pending
	}
	return nil
}
func (m *mockApprovalStore) ListByDecision(decisionID string) []*approval.ApprovalRequest {
	var result []*approval.ApprovalRequest
	for _, a := range m.pending {
		if a.DecisionID == decisionID {
			result = append(result, a)
		}
	}
	return result
}

func TestChecker_CleanState(t *testing.T) {
	ck := NewChecker()
	ck.SetEventStore(&mockEventStore{events: []*events.Event{
		{EventID: "evt_1", EventType: "test", Timestamp: time.Now().UTC()},
	}})
	ck.SetContinuationStore(&mockContinuationStore{continuations: []*continuation.Continuation{
		{ContinuationID: "cnt_1", State: continuation.StateApproved, CreatedAt: time.Now().UTC()},
	}})
	ck.SetExecutionStore(&mockExecutionStore{
		executions: []*execution.Execution{},
		stats:      func() (int, int, int, int, int) { return 0, 0, 0, 0, 0 },
	})
	ck.SetReceiptStore(&mockReceiptStore{receipts: []*models.Receipt{}})
	ck.SetApprovalStore(&mockApprovalStore{pending: []*approval.ApprovalRequest{}})
	ck.SetGatewayInfo("gw_test", "0.8.0")

	result := ck.Check()

	if !result.Passed {
		t.Errorf("expected Passed=true for clean state, got false")
	}
	if len(result.Issues) != 0 {
		t.Errorf("expected 0 issues for clean state, got %d: %+v", len(result.Issues), result.Issues)
	}
	if result.Summary.TotalIssues != 0 {
		t.Errorf("expected Summary.TotalIssues=0, got %d", result.Summary.TotalIssues)
	}
	if result.Summary.TotalWarnings != 0 {
		t.Errorf("expected Summary.TotalWarnings=0, got %d", result.Summary.TotalWarnings)
	}
	if result.VersionInfo["gateway_id"] != "gw_test" {
		t.Errorf("expected gateway_id=gw_test, got %s", result.VersionInfo["gateway_id"])
	}
}

func TestChecker_NoStoresConfigured(t *testing.T) {
	ck := NewChecker()
	result := ck.Check()

	if !result.Passed {
		t.Errorf("expected Passed=true with warnings-only (low severity), got false")
	}
	if len(result.Warnings) == 0 {
		t.Errorf("expected warnings when no stores configured, got none")
	}
	if result.Summary.TotalIssues != 0 {
		t.Errorf("expected 0 issues, got %d", result.Summary.TotalIssues)
	}
	if result.Summary.TotalWarnings != len(result.Warnings) {
		t.Errorf("expected Summary.TotalWarnings=%d, got %d", len(result.Warnings), result.Summary.TotalWarnings)
	}
}

func TestChecker_DuplicateEventIDs(t *testing.T) {
	store := &mockEventStore{events: []*events.Event{
		{EventID: "evt_dup", EventType: "test", Timestamp: time.Now().UTC()},
		{EventID: "evt_dup", EventType: "test", Timestamp: time.Now().UTC()},
		{EventID: "evt_unique", EventType: "test", Timestamp: time.Now().UTC()},
	}}
	ck := NewChecker()
	ck.SetEventStore(store)

	result := ck.Check()

	if result.Passed {
		t.Errorf("expected Passed=false with duplicate event IDs, got true")
	}
	if len(result.Issues) != 1 {
		t.Errorf("expected 1 issue, got %d", len(result.Issues))
	}
	if result.Issues[0].Severity != "high" {
		t.Errorf("expected severity=high, got %s", result.Issues[0].Severity)
	}
	if result.Issues[0].Category != "event_store" {
		t.Errorf("expected category=event_store, got %s", result.Issues[0].Category)
	}
	if result.Summary.High != 1 {
		t.Errorf("expected Summary.High=1, got %d", result.Summary.High)
	}
}

func TestChecker_ZeroTimestampEvents(t *testing.T) {
	store := &mockEventStore{events: []*events.Event{
		{EventID: "evt_1", EventType: "test", Timestamp: time.Time{}},
		{EventID: "evt_2", EventType: "test", Timestamp: time.Time{}},
	}}
	ck := NewChecker()
	ck.SetEventStore(store)

	result := ck.Check()

	if !result.Passed {
		t.Errorf("expected Passed=true with medium-only issues, got false")
	}
	if len(result.Issues) != 1 {
		t.Errorf("expected 1 issue, got %d", len(result.Issues))
	}
	if result.Issues[0].Severity != "medium" {
		t.Errorf("expected severity=medium, got %s", result.Issues[0].Severity)
	}
	if result.Summary.Medium != 1 {
		t.Errorf("expected Summary.Medium=1, got %d", result.Summary.Medium)
	}
}

func TestChecker_ExecutionOrphanedContinuation(t *testing.T) {
	execStore := &mockExecutionStore{
		executions: []*execution.Execution{
			{ExecutionID: "exe_1", ContinuationID: "cnt_nonexistent", State: execution.StateSucceeded},
		},
		stats: func() (int, int, int, int, int) { return 1, 1, 0, 0, 0 },
	}
	contStore := &mockContinuationStore{continuations: []*continuation.Continuation{}}
	ck := NewChecker()
	ck.SetExecutionStore(execStore)
	ck.SetContinuationStore(contStore)

	result := ck.Check()

	if result.Passed {
		t.Errorf("expected Passed=false with orphaned execution reference, got true")
	}
	found := false
	for _, issue := range result.Issues {
		if (issue.Category == "execution_store" || issue.Category == "cross_store") && issue.EntityID == "exe_1" {
			found = true
			if issue.Severity != "high" {
				t.Errorf("expected severity=high, got %s", issue.Severity)
			}
			if issue.Code != "EXEC_ORPHAN_CNT" {
				t.Errorf("expected code=EXEC_ORPHAN_CNT, got %s", issue.Code)
			}
		}
	}
	if !found {
		t.Errorf("expected issue for exe_1 with orphaned continuation reference, not found in %+v", result.Issues)
	}
	if result.Summary.High != 1 {
		t.Errorf("expected Summary.High=1, got %d", result.Summary.High)
	}
}

func TestChecker_ExpiredButNotMarkedContinuation(t *testing.T) {
	now := time.Now().UTC()
	past := now.Add(-1 * time.Hour)
	contStore := &mockContinuationStore{continuations: []*continuation.Continuation{
		{
			ContinuationID: "cnt_expired",
			State:          continuation.StateApproved,
			CreatedAt:      now.Add(-2 * time.Hour),
			ExpiresAt:      &past,
		},
	}}
	ck := NewChecker()
	ck.SetContinuationStore(contStore)

	result := ck.Check()

	if !result.Passed {
		t.Errorf("expected Passed=true with medium-only issues, got false")
	}
	found := false
	for _, issue := range result.Issues {
		if issue.EntityID == "cnt_expired" && issue.Severity == "medium" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected medium issue for cnt_expired, got %+v", result.Issues)
	}
	if result.Summary.Medium != 1 {
		t.Errorf("expected Summary.Medium=1, got %d", result.Summary.Medium)
	}
}

func TestChecker_ZeroCreatedAtContinuation(t *testing.T) {
	contStore := &mockContinuationStore{continuations: []*continuation.Continuation{
		{ContinuationID: "cnt_bad", State: continuation.StateApproved, CreatedAt: time.Time{}},
	}}
	ck := NewChecker()
	ck.SetContinuationStore(contStore)

	result := ck.Check()

	if !result.Passed {
		t.Errorf("expected Passed=true with medium-only issues, got false")
	}
	if result.Summary.Medium != 1 {
		t.Errorf("expected Summary.Medium=1, got %d", result.Summary.Medium)
	}
}

func TestChecker_DuplicateExecutionIDs(t *testing.T) {
	execStore := &mockExecutionStore{
		executions: []*execution.Execution{
			{ExecutionID: "exe_dup", ContinuationID: "cnt_1", State: execution.StateSucceeded, StartedAt: time.Now().UTC()},
			{ExecutionID: "exe_dup", ContinuationID: "cnt_1", State: execution.StateSucceeded, StartedAt: time.Now().UTC()},
		},
		stats: func() (int, int, int, int, int) { return 2, 2, 0, 0, 0 },
	}
	ck := NewChecker()
	ck.SetExecutionStore(execStore)

	result := ck.Check()

	if result.Passed {
		t.Errorf("expected Passed=false with duplicate execution IDs, got true")
	}
	if result.Summary.High != 1 {
		t.Errorf("expected Summary.High=1, got %d", result.Summary.High)
	}
}

func TestChecker_DuplicateReceiptIDs(t *testing.T) {
	recStore := &mockReceiptStore{receipts: []*models.Receipt{
		{ReceiptID: "rec_dup", DecisionID: "dec_1"},
		{ReceiptID: "rec_dup", DecisionID: "dec_1"},
	}}
	ck := NewChecker()
	ck.SetReceiptStore(recStore)

	result := ck.Check()

	if result.Passed {
		t.Errorf("expected Passed=false with duplicate receipt IDs, got true")
	}
	if result.Summary.High != 1 {
		t.Errorf("expected Summary.High=1, got %d", result.Summary.High)
	}
}

func TestChecker_EmptyApprovalID(t *testing.T) {
	apprStore := &mockApprovalStore{pending: []*approval.ApprovalRequest{
		{ApprovalID: "", DecisionID: "dec_1", Status: approval.StatusPending},
	}}
	ck := NewChecker()
	ck.SetApprovalStore(apprStore)

	result := ck.Check()

	if !result.Passed {
		t.Errorf("expected Passed=true with medium-only issues, got false")
	}
	if result.Summary.Medium != 1 {
		t.Errorf("expected Summary.Medium=1, got %d", result.Summary.Medium)
	}
}

func TestChecker_StoreStatsPopulated(t *testing.T) {
	execStore := &mockExecutionStore{
		executions: []*execution.Execution{},
		stats:      func() (int, int, int, int, int) { return 10, 5, 3, 2, 0 },
	}
	eventStore := &mockEventStore{
		events: []*events.Event{
			{EventID: "evt_1", EventType: "type_a", Timestamp: time.Now().UTC()},
			{EventID: "evt_2", EventType: "type_b", Timestamp: time.Now().UTC()},
			{EventID: "evt_3", EventType: "type_a", Timestamp: time.Now().UTC()},
		},
	}
	contStore := &mockContinuationStore{continuations: []*continuation.Continuation{
		{ContinuationID: "cnt_1", State: continuation.StateApproved, CreatedAt: time.Now().UTC()},
	}}
	recStore := &mockReceiptStore{receipts: []*models.Receipt{
		{ReceiptID: "rec_1", DecisionID: "dec_1"},
	}}
	apprStore := &mockApprovalStore{pending: []*approval.ApprovalRequest{
		{ApprovalID: "apr_1", DecisionID: "dec_1", Status: approval.StatusPending},
	}}

	ck := NewChecker()
	ck.SetExecutionStore(execStore)
	ck.SetEventStore(eventStore)
	ck.SetContinuationStore(contStore)
	ck.SetReceiptStore(recStore)
	ck.SetApprovalStore(apprStore)

	result := ck.Check()

	if result.StoreStats["executions_total"] != 10 {
		t.Errorf("expected executions_total=10, got %d", result.StoreStats["executions_total"])
	}
	if result.StoreStats["executions_succeeded"] != 5 {
		t.Errorf("expected executions_succeeded=5, got %d", result.StoreStats["executions_succeeded"])
	}
	if result.StoreStats["executions_running"] != 2 {
		t.Errorf("expected executions_running=2, got %d", result.StoreStats["executions_running"])
	}
	if result.StoreStats["events"] != 3 {
		t.Errorf("expected events=3, got %d", result.StoreStats["events"])
	}
	if result.StoreStats["event_types"] != 2 {
		t.Errorf("expected event_types=2, got %d", result.StoreStats["event_types"])
	}
	if result.StoreStats["continuations"] != 1 {
		t.Errorf("expected continuations=1, got %d", result.StoreStats["continuations"])
	}
	if result.StoreStats["receipts"] != 1 {
		t.Errorf("expected receipts=1, got %d", result.StoreStats["receipts"])
	}
	if result.StoreStats["approvals_pending"] != 1 {
		t.Errorf("expected approvals_pending=1, got %d", result.StoreStats["approvals_pending"])
	}
}

func TestChecker_SummaryClassifiesAllSeverities(t *testing.T) {
	execStore := &mockExecutionStore{
		executions: []*execution.Execution{
			{ExecutionID: "exe_dup", ContinuationID: "cnt_1", State: execution.StateSucceeded, StartedAt: time.Now().UTC()},
			{ExecutionID: "exe_dup", ContinuationID: "cnt_1", State: execution.StateSucceeded, StartedAt: time.Now().UTC()},
		},
		stats: func() (int, int, int, int, int) { return 2, 2, 0, 0, 0 },
	}
	eventStore := &mockEventStore{
		events: []*events.Event{
			{EventID: "evt_dup", EventType: "test", Timestamp: time.Time{}},
		},
	}
	ck := NewChecker()
	ck.SetExecutionStore(execStore)
	ck.SetEventStore(eventStore)

	result := ck.Check()

	if result.Summary.TotalIssues != 2 {
		t.Errorf("expected TotalIssues=2, got %d", result.Summary.TotalIssues)
	}
	if result.Summary.High != 1 {
		t.Errorf("expected High=1, got %d", result.Summary.High)
	}
	if result.Summary.Medium != 1 {
		t.Errorf("expected Medium=1, got %d", result.Summary.Medium)
	}
	if result.Summary.Critical != 0 {
		t.Errorf("expected Critical=0, got %d", result.Summary.Critical)
	}
}

func TestChecker_CrossStoreExecutionContinuationReference(t *testing.T) {
	contStore := &mockContinuationStore{continuations: []*continuation.Continuation{
		{ContinuationID: "cnt_exists", State: continuation.StateApproved, CreatedAt: time.Now().UTC()},
	}}
	execStore := &mockExecutionStore{
		executions: []*execution.Execution{
			{ExecutionID: "exe_orphan", ContinuationID: "cnt_missing", State: execution.StateSucceeded, StartedAt: time.Now().UTC()},
			{ExecutionID: "exe_ok", ContinuationID: "cnt_exists", State: execution.StateSucceeded, StartedAt: time.Now().UTC()},
		},
		stats: func() (int, int, int, int, int) { return 2, 1, 0, 1, 0 },
	}
	ck := NewChecker()
	ck.SetContinuationStore(contStore)
	ck.SetExecutionStore(execStore)

	result := ck.Check()

	found := false
	for _, issue := range result.Issues {
		if issue.EntityID == "exe_orphan" && (issue.Category == "execution_store" || issue.Category == "cross_store") {
			found = true
			if issue.Severity != "high" {
				t.Errorf("expected severity=high, got %s", issue.Severity)
			}
		}
	}
	if !found {
		t.Errorf("expected execution_store/cross_store issue for exe_orphan, got %+v", result.Issues)
	}
	if result.Passed {
		t.Errorf("expected Passed=false (has high issue), got true")
	}
}

func TestChecker_WarningsOnlyDoNotFail(t *testing.T) {
	contStore := &mockContinuationStore{continuations: []*continuation.Continuation{
		{ContinuationID: "cnt_stuck", State: continuation.StateEscalated, CreatedAt: time.Now().UTC()},
	}}
	ck := NewChecker()
	ck.SetContinuationStore(contStore)

	result := ck.Check()

	if !result.Passed {
		t.Errorf("expected Passed=true with only warnings (stuck in escalated), got false")
	}
	if len(result.Issues) != 0 {
		t.Errorf("expected 0 issues, got %d", len(result.Issues))
	}
	if len(result.Warnings) == 0 {
		t.Errorf("expected warnings for escalated state, got none")
	}
}
