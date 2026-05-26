package approval

import (
	"os"
	"testing"
)

func TestFileBackedStore_CreateAndReload(t *testing.T) {
	tmpDir := t.TempDir()
	storePath := tmpDir + "/approvals.json"

	store, err := NewFileBackedStore(storePath)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	req := &ApprovalRequest{
		ApprovalID: "apr_test001",
		DecisionID: "dec_test001",
		ActionType: "shell",
		Resource:   "shell:curl |sh",
		AgentID:    "agent_test",
		Status:     StatusPending,
	}

	if err := store.Create(req); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	newStore, err := NewFileBackedStore(storePath)
	if err != nil {
		t.Fatalf("failed to reload store: %v", err)
	}

	got, err := newStore.Get("apr_test001")
	if err != nil {
		t.Fatalf("Get after reload failed: %v", err)
	}
	if got.ApprovalID != "apr_test001" {
		t.Errorf("ApprovalID = %v, want apr_test001", got.ApprovalID)
	}
	if got.Status != StatusPending {
		t.Errorf("Status = %v, want pending", got.Status)
	}
}

func TestFileBackedStore_FileNotFoundInitializesEmpty(t *testing.T) {
	tmpDir := t.TempDir()
	storePath := tmpDir + "/nonexistent/approvals.json"

	store, err := NewFileBackedStore(storePath)
	if err != nil {
		t.Fatalf("expected no error for nonexistent file, got: %v", err)
	}

	all := store.ListByStatus(StatusPending)
	if len(all) != 0 {
		t.Errorf("expected empty store, got %d approvals", len(all))
	}
}

func TestFileBackedStore_MalformedJSON(t *testing.T) {
	tmpDir := t.TempDir()
	storePath := tmpDir + "/malformed.json"

	if err := os.WriteFile(storePath, []byte("not json at all"), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := NewFileBackedStore(storePath)
	if err == nil {
		t.Fatal("expected error for malformed JSON")
	}
}

func TestFileBackedStore_Update(t *testing.T) {
	tmpDir := t.TempDir()
	storePath := tmpDir + "/update.json"

	store, err := NewFileBackedStore(storePath)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	req := &ApprovalRequest{
		ApprovalID: "apr_update001",
		DecisionID: "dec_update001",
		ActionType: "shell",
		Resource:   "shell:pwd",
		Status:     StatusPending,
	}
	store.Create(req)

	req.Status = StatusApproved
	req.ResolvedBy = "admin@example.com"
	if err := store.Update(req); err != nil {
		t.Fatalf("Update failed: %v", err)
	}

	newStore, err := NewFileBackedStore(storePath)
	if err != nil {
		t.Fatalf("failed to reload store: %v", err)
	}

	got, err := newStore.Get("apr_update001")
	if err != nil {
		t.Fatalf("Get after reload failed: %v", err)
	}
	if got.Status != StatusApproved {
		t.Errorf("Status = %v, want approved", got.Status)
	}
	if got.ResolvedBy != "admin@example.com" {
		t.Errorf("ResolvedBy = %v, want admin@example.com", got.ResolvedBy)
	}
}

func TestFileBackedStore_Delete(t *testing.T) {
	tmpDir := t.TempDir()
	storePath := tmpDir + "/delete.json"

	store, err := NewFileBackedStore(storePath)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	store.Create(&ApprovalRequest{ApprovalID: "apr_delete001", DecisionID: "dec_1", ActionType: "shell", Status: StatusPending})
	store.Create(&ApprovalRequest{ApprovalID: "apr_delete002", DecisionID: "dec_2", ActionType: "shell", Status: StatusPending})

	if err := store.Delete("apr_delete001"); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	newStore, err := NewFileBackedStore(storePath)
	if err != nil {
		t.Fatalf("failed to reload store: %v", err)
	}

	_, err = newStore.Get("apr_delete001")
	if err == nil {
		t.Error("expected error for deleted approval")
	}

	got, err := newStore.Get("apr_delete002")
	if err != nil {
		t.Fatalf("Get for apr_delete002 failed: %v", err)
	}
	if got.ApprovalID != "apr_delete002" {
		t.Errorf("ApprovalID = %v, want apr_delete002", got.ApprovalID)
	}
}

func TestFileBackedStore_ListByStatus(t *testing.T) {
	tmpDir := t.TempDir()
	storePath := tmpDir + "/listbystatus.json"

	store, err := NewFileBackedStore(storePath)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	store.Create(&ApprovalRequest{ApprovalID: "apr_1", DecisionID: "dec_1", ActionType: "shell", Status: StatusPending})
	store.Create(&ApprovalRequest{ApprovalID: "apr_2", DecisionID: "dec_2", ActionType: "shell", Status: StatusApproved})
	store.Create(&ApprovalRequest{ApprovalID: "apr_3", DecisionID: "dec_3", ActionType: "shell", Status: StatusPending})

	pending := store.ListByStatus(StatusPending)
	if len(pending) != 2 {
		t.Errorf("len(pending) = %d, want 2", len(pending))
	}

	approved := store.ListByStatus(StatusApproved)
	if len(approved) != 1 {
		t.Errorf("len(approved) = %d, want 1", len(approved))
	}
}

func TestFileBackedStore_Stats(t *testing.T) {
	tmpDir := t.TempDir()
	storePath := tmpDir + "/stats.json"

	store, err := NewFileBackedStore(storePath)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	store.Create(&ApprovalRequest{ApprovalID: "apr_stats1", DecisionID: "dec_1", ActionType: "shell", Status: StatusPending})
	store.Create(&ApprovalRequest{ApprovalID: "apr_stats2", DecisionID: "dec_2", ActionType: "shell", Status: StatusApproved})

	pending, total := store.Stats()
	if pending != 1 {
		t.Errorf("pending = %d, want 1", pending)
	}
	if total != 2 {
		t.Errorf("total = %d, want 2", total)
	}
}

func TestFileBackedStore_DuplicateCreate(t *testing.T) {
	tmpDir := t.TempDir()
	storePath := tmpDir + "/duplicate.json"

	store, err := NewFileBackedStore(storePath)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	store.Create(&ApprovalRequest{ApprovalID: "apr_dup", DecisionID: "dec_1", ActionType: "shell", Status: StatusPending})

	err = store.Create(&ApprovalRequest{ApprovalID: "apr_dup", DecisionID: "dec_2", ActionType: "git.push", Status: StatusPending})
	if err == nil {
		t.Error("expected error for duplicate approval_id")
	}
}