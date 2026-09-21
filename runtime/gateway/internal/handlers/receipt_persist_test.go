package handlers

// F-01 regression: a failed receiptsStore.Put must never be reported as
// a durable receipt. The receipt is post-decision evidence, not an
// authorization prerequisite — Put failure must not change the
// decision, but must emit receipt.persist_failed, not receipt.issued.

import (
	"errors"
	"testing"

	"ovara.runtime.gateway/internal/events"
	"ovara.runtime.gateway/internal/models"
	"ovara.runtime.gateway/internal/receipts"
)

type failingReceiptStore struct {
	inner *receipts.InMemoryStore
	err   error
}

func (f *failingReceiptStore) Put(r *models.Receipt) error {
	if f.err != nil {
		return f.err
	}
	return f.inner.Put(r)
}
func (f *failingReceiptStore) Get(id string) (*models.Receipt, error) {
	return f.inner.Get(id)
}
func (f *failingReceiptStore) ListByDecision(d string) []*models.Receipt {
	return f.inner.ListByDecision(d)
}
func (f *failingReceiptStore) ListByAgent(a string) []*models.Receipt {
	return f.inner.ListByAgent(a)
}
func (f *failingReceiptStore) ListAll() []*models.Receipt { return f.inner.ListAll() }

func receiptTestReqResp() (*models.ActionRequest, *models.DecisionResponse) {
	req := &models.ActionRequest{
		ActionType: "shell",
		Resource:   "shell:echo hi",
		AgentIdentity: &models.AgentIdentity{
			SubjectID: "agent-1",
		},
	}
	resp := &models.DecisionResponse{
		DecisionID: "dec-1",
		Decision:   models.DecisionAllow,
		ReceiptStub: &models.ReceiptStub{
			ReceiptID:     "rcpt-1",
			ActionDigest:  "digest",
			ActionType:    "shell",
			Resource:      "shell:echo hi",
			PolicyVersion: "v1",
		},
	}
	return req, resp
}

func eventTypes(es events.Store) map[string]int {
	out := map[string]int{}
	for _, e := range es.List(0) {
		out[e.EventType]++
	}
	return out
}

func TestReceiptPersistSuccess_EmitsIssued(t *testing.T) {
	rs := &failingReceiptStore{inner: receipts.NewInMemoryStore()}
	es := events.NewInMemoryStore(0)
	h := New(nil, nil, nil, rs)
	h.SetEventStore(es)

	req, resp := receiptTestReqResp()
	h.recordDecision(req, resp, 1)

	if got := rs.inner.ListAll(); len(got) != 1 {
		t.Fatalf("receipt not persisted: %d records", len(got))
	}
	types := eventTypes(es)
	if types[events.EventTypeReceiptIssued] != 1 {
		t.Fatalf("expected receipt.issued, got %v", types)
	}
	if types[events.EventTypeReceiptPersistFailed] != 0 {
		t.Fatalf("unexpected persist_failed on success: %v", types)
	}
}

func TestReceiptPersistFailure_NoFalseIssued(t *testing.T) {
	rs := &failingReceiptStore{inner: receipts.NewInMemoryStore(), err: errors.New("disk full")}
	es := events.NewInMemoryStore(0)
	h := New(nil, nil, nil, rs)
	h.SetEventStore(es)

	req, resp := receiptTestReqResp()
	h.recordDecision(req, resp, 1) // must not panic

	if got := rs.inner.ListAll(); len(got) != 0 {
		t.Fatalf("failed write must not leave a receipt: %d", len(got))
	}
	types := eventTypes(es)
	if types[events.EventTypeReceiptIssued] != 0 {
		t.Fatalf("receipt.issued emitted despite failed Put: %v", types)
	}
	if types[events.EventTypeReceiptPersistFailed] != 1 {
		t.Fatalf("expected receipt.persist_failed, got %v", types)
	}
	// The decision itself was still recorded — evidence failure is not
	// an authorization gate.
	if types[events.EventTypeDecisionEvaluated] != 1 {
		t.Fatalf("decision_evaluated missing: %v", types)
	}
}
