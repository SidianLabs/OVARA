package receipts

import (
	"os"
	"testing"
	"time"

	"ovara.runtime.gateway/internal/models"
)

func TestFileBackedStore_PutAndReload(t *testing.T) {
	tmpDir := t.TempDir()
	storePath := tmpDir + "/receipts.json"

	store, err := NewFileBackedStore(storePath, 100, 24*time.Hour)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	receipt := &models.Receipt{
		ReceiptID:  "rcpt_file001",
		DecisionID: "dec_file001",
		ActionType: "shell",
		Resource:   "shell:ls",
		Decision:   "allow",
		IssuedAt:   time.Now(),
	}

	if err := store.Put(receipt); err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	newStore, err := NewFileBackedStore(storePath, 100, 24*time.Hour)
	if err != nil {
		t.Fatalf("failed to reload store: %v", err)
	}

	got, err := newStore.Get("rcpt_file001")
	if err != nil {
		t.Fatalf("Get after reload failed: %v", err)
	}
	if got.ReceiptID != "rcpt_file001" {
		t.Errorf("ReceiptID = %v, want rcpt_file001", got.ReceiptID)
	}
	if got.DecisionID != "dec_file001" {
		t.Errorf("DecisionID = %v, want dec_file001", got.DecisionID)
	}
	if got.Decision != "allow" {
		t.Errorf("Decision = %v, want allow", got.Decision)
	}
}

func TestFileBackedStore_FileNotFoundInitializesEmpty(t *testing.T) {
	tmpDir := t.TempDir()
	storePath := tmpDir + "/nonexistent/receipts.json"

	store, err := NewFileBackedStore(storePath, 100, 24*time.Hour)
	if err != nil {
		t.Fatalf("expected no error for nonexistent file, got: %v", err)
	}

	all := store.ListAll()
	if len(all) != 0 {
		t.Errorf("expected empty store, got %d receipts", len(all))
	}
}

func TestFileBackedStore_MalformedJSON(t *testing.T) {
	tmpDir := t.TempDir()
	storePath := tmpDir + "/malformed.json"

	if err := os.WriteFile(storePath, []byte("not json at all"), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := NewFileBackedStore(storePath, 100, 24*time.Hour)
	if err == nil {
		t.Fatal("expected error for malformed JSON")
	}
}

func TestFileBackedStore_MaxSizeEviction(t *testing.T) {
	tmpDir := t.TempDir()
	storePath := tmpDir + "/evict.json"

	store, err := NewFileBackedStore(storePath, 3, 24*time.Hour)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	baseTime := time.Now()
	for i := 0; i < 5; i++ {
		receipt := &models.Receipt{
			ReceiptID:  "rcpt_evict" + string(rune('0'+i)),
			DecisionID: "dec_evict" + string(rune('0'+i)),
			ActionType: "shell",
			Decision:   "allow",
			IssuedAt:   baseTime.Add(time.Duration(i) * time.Minute),
		}
		store.Put(receipt)
	}

	time.Sleep(100 * time.Millisecond)

	count, _ := store.Stats()
	if count != 3 {
		t.Errorf("expected 3 receipts after eviction, got %d", count)
	}
}

func TestFileBackedStore_EmptyReceiptID(t *testing.T) {
	tmpDir := t.TempDir()
	storePath := tmpDir + "/emptyid.json"

	store, err := NewFileBackedStore(storePath, 100, 24*time.Hour)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	err = store.Put(&models.Receipt{ReceiptID: ""})
	if err == nil {
		t.Error("expected error for empty receipt_id")
	}
}

func TestFileBackedStore_ListByAgent(t *testing.T) {
	tmpDir := t.TempDir()
	storePath := tmpDir + "/listbyagent.json"

	store, err := NewFileBackedStore(storePath, 100, 24*time.Hour)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	store.Put(&models.Receipt{ReceiptID: "rcpt_1", AgentID: "agent_a", DecisionID: "dec_1", ActionType: "shell", Decision: "allow"})
	store.Put(&models.Receipt{ReceiptID: "rcpt_2", AgentID: "agent_b", DecisionID: "dec_2", ActionType: "shell", Decision: "allow"})
	store.Put(&models.Receipt{ReceiptID: "rcpt_3", AgentID: "agent_a", DecisionID: "dec_3", ActionType: "git.push", Decision: "escalate"})

	byAgent := store.ListByAgent("agent_a")
	if len(byAgent) != 2 {
		t.Errorf("len(byAgent) = %d, want 2", len(byAgent))
	}

	none := store.ListByAgent("agent_notfound")
	if len(none) != 0 {
		t.Errorf("len(none) = %d, want 0", len(none))
	}
}

func TestFileBackedStore_ListByDecision(t *testing.T) {
	tmpDir := t.TempDir()
	storePath := tmpDir + "/listbydecision.json"

	store, err := NewFileBackedStore(storePath, 100, 24*time.Hour)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

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

func TestFileBackedStore_Stats(t *testing.T) {
	tmpDir := t.TempDir()
	storePath := tmpDir + "/stats.json"

	store, err := NewFileBackedStore(storePath, 10, 24*time.Hour)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	store.Put(&models.Receipt{ReceiptID: "rcpt_1", DecisionID: "dec_1", ActionType: "shell", Decision: "allow"})
	store.Put(&models.Receipt{ReceiptID: "rcpt_2", DecisionID: "dec_2", ActionType: "shell", Decision: "allow"})

	count, max := store.Stats()
	if count != 2 {
		t.Errorf("count = %d, want 2", count)
	}
	if max != 10 {
		t.Errorf("max = %d, want 10", max)
	}
}