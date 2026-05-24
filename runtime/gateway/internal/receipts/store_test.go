package receipts

import (
	"testing"

	"ovara.runtime.gateway/internal/models"
)

func TestInMemoryStore_Put(t *testing.T) {
	store := NewInMemoryStore()
	receipt := &models.Receipt{
		ReceiptID:  "rcpt_test123",
		DecisionID: "dec_456",
		ActionType: "shell",
		Resource:   "shell:echo test",
		Decision:   "allow",
	}

	err := store.Put(receipt)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	err = store.Put(&models.Receipt{})
	if err == nil {
		t.Error("expected error for empty receipt_id")
	}
}

func TestInMemoryStore_Get(t *testing.T) {
	store := NewInMemoryStore()
	receipt := &models.Receipt{
		ReceiptID:  "rcpt_get456",
		DecisionID: "dec_789",
		ActionType: "shell",
		Decision:   "allow",
	}
	store.Put(receipt)

	got, err := store.Get("rcpt_get456")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.ReceiptID != "rcpt_get456" {
		t.Errorf("receipt_id = %v, want rcpt_get456", got.ReceiptID)
	}

	_, err = store.Get("rcpt_notfound")
	if err == nil {
		t.Error("expected error for not found")
	}
}

func TestInMemoryStore_ListByDecision(t *testing.T) {
	store := NewInMemoryStore()
	store.Put(&models.Receipt{ReceiptID: "rcpt_1", DecisionID: "dec_a", ActionType: "shell", Decision: "allow"})
	store.Put(&models.Receipt{ReceiptID: "rcpt_2", DecisionID: "dec_b", ActionType: "shell", Decision: "deny"})
	store.Put(&models.Receipt{ReceiptID: "rcpt_3", DecisionID: "dec_a", ActionType: "git.push", Decision: "escalate"})

	byDecision := store.ListByDecision("dec_a")
	if len(byDecision) != 2 {
		t.Errorf("len(byDecision) = %d, want 2", len(byDecision))
	}

	empty := store.ListByDecision("dec_notfound")
	if len(empty) != 0 {
		t.Errorf("len(empty) = %d, want 0", len(empty))
	}
}

func TestInMemoryStore_ListByAgent(t *testing.T) {
	store := NewInMemoryStore()
	store.Put(&models.Receipt{ReceiptID: "rcpt_1", DecisionID: "dec_1", AgentID: "agent_001", Decision: "allow"})
	store.Put(&models.Receipt{ReceiptID: "rcpt_2", DecisionID: "dec_2", AgentID: "agent_002", Decision: "allow"})
	store.Put(&models.Receipt{ReceiptID: "rcpt_3", DecisionID: "dec_3", AgentID: "agent_001", Decision: "deny"})

	byAgent := store.ListByAgent("agent_001")
	if len(byAgent) != 2 {
		t.Errorf("len(byAgent) = %d, want 2", len(byAgent))
	}

	none := store.ListByAgent("agent_notfound")
	if len(none) != 0 {
		t.Errorf("len(none) = %d, want 0", len(none))
	}
}

func TestInMemoryStore_ListAll(t *testing.T) {
	store := NewInMemoryStore()
	store.Put(&models.Receipt{ReceiptID: "rcpt_1", DecisionID: "dec_1", Decision: "allow"})
	store.Put(&models.Receipt{ReceiptID: "rcpt_2", DecisionID: "dec_2", Decision: "deny"})

	all := store.ListAll()
	if len(all) != 2 {
		t.Errorf("len(all) = %d, want 2", len(all))
	}
}