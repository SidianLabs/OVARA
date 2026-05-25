package continuation

import (
	"testing"
	"time"
)

func TestNewContinuation(t *testing.T) {
	c := NewContinuation("dec_123", "shell", "shell:echo test")
	if c.ContinuationID == "" {
		t.Error("continuation_id should not be empty")
	}
	if c.DecisionID != "dec_123" {
		t.Errorf("decision_id = %s, want dec_123", c.DecisionID)
	}
	if c.State != StateEscalated {
		t.Errorf("state = %s, want escalated", c.State)
	}
	if c.CreatedAt.IsZero() {
		t.Error("created_at should not be zero")
	}
}

func TestContinuation_CanResume(t *testing.T) {
	c := NewContinuation("dec_1", "shell", "shell:ls")
	if c.CanResume() {
		t.Error("escalated continuation should not be directly resumable - must be approved first")
	}

	c.MarkApproved("resolver1")
	if !c.CanResume() {
		t.Error("approved continuation should be resumable")
	}

	c2 := NewContinuation("dec_2", "shell", "shell:ls")
	c2.MarkDenied("resolver2", "too risky")
	if c2.CanResume() {
		t.Error("denied continuation should not be resumable")
	}
}

func TestContinuation_IsTerminal(t *testing.T) {
	c := NewContinuation("dec_1", "shell", "shell:ls")
	if c.IsTerminal() {
		t.Error("escalated should not be terminal")
	}

	c.MarkDenied("r", "test")
	if !c.IsTerminal() {
		t.Error("denied should be terminal")
	}
}

func TestContinuation_MarkApproved(t *testing.T) {
	c := NewContinuation("dec_1", "shell", "shell:ls")
	c.MarkApproved("admin")

	if c.State != StateApproved {
		t.Errorf("state = %s, want approved", c.State)
	}
	if c.ResolvedBy != "admin" {
		t.Errorf("resolved_by = %s, want admin", c.ResolvedBy)
	}
	if c.ApprovedAt == nil {
		t.Error("approved_at should be set")
	}
	if c.ApprovedAt.Location() != time.UTC {
		t.Error("approved_at should be UTC")
	}
}

func TestContinuation_MarkResumed(t *testing.T) {
	c := NewContinuation("dec_1", "shell", "shell:ls")
	c.MarkApproved("admin")
	c.MarkResumed()

	if c.State != StateResumed {
		t.Errorf("state = %s, want resumed", c.State)
	}
	if c.ResumedAt == nil {
		t.Error("resumed_at should be set")
	}
}

func TestContinuation_BuilderChaining(t *testing.T) {
	c := NewContinuation("dec_1", "shell", "shell:ls").
		WithAgentID("agt_123").
		WithEnvironment("production").
		WithTrustContext(0.75, "medium", []string{"risky_shell_pattern"}, true, false).
		WithPolicyVersion("v1-prod")

	if c.AgentID != "agt_123" {
		t.Errorf("agent_id = %s, want agt_123", c.AgentID)
	}
	if c.Environment != "production" {
		t.Errorf("environment = %s, want production", c.Environment)
	}
	if c.TrustScore != 0.75 {
		t.Errorf("trust_score = %f, want 0.75", c.TrustScore)
	}
	if c.TrustLevel != "medium" {
		t.Errorf("trust_level = %s, want medium", c.TrustLevel)
	}
	if c.PolicyVersion != "v1-prod" {
		t.Errorf("policy_version = %s, want v1-prod", c.PolicyVersion)
	}
}

func TestInMemoryStore_CreateAndGet(t *testing.T) {
	store := NewInMemoryStore()
	c := NewContinuation("dec_1", "shell", "shell:ls").WithAgentID("agt_1")

	err := store.Create(c)
	if err != nil {
		t.Fatalf("create failed: %v", err)
	}

	found, ok := store.Get(c.ContinuationID)
	if !ok {
		t.Fatal("expected to find continuation")
	}
	if found.DecisionID != "dec_1" {
		t.Errorf("decision_id = %s, want dec_1", found.DecisionID)
	}
}

func TestInMemoryStore_GetNotFound(t *testing.T) {
	store := NewInMemoryStore()
	_, ok := store.Get("cnt_nonexistent")
	if ok {
		t.Error("expected not found")
	}
}

func TestInMemoryStore_Update(t *testing.T) {
	store := NewInMemoryStore()
	c := NewContinuation("dec_1", "shell", "shell:ls")
	store.Create(c)

	c.MarkApproved("admin")
	err := store.Update(c)
	if err != nil {
		t.Fatalf("update failed: %v", err)
	}

	found, _ := store.Get(c.ContinuationID)
	if found.State != StateApproved {
		t.Errorf("state = %s, want approved", found.State)
	}
}

func TestInMemoryStore_ListByState(t *testing.T) {
	store := NewInMemoryStore()
	c1 := NewContinuation("dec_1", "shell", "shell:ls")
	c2 := NewContinuation("dec_2", "git.push", "git:acme/repo")
	c1.MarkApproved("admin")
	store.Create(c1)
	store.Create(c2)

	approved := store.ListByState(StateApproved)
	if len(approved) != 1 {
		t.Errorf("approved count = %d, want 1", len(approved))
	}

	escalated := store.ListByState(StateEscalated)
	if len(escalated) != 1 {
		t.Errorf("escalated count = %d, want 1", len(escalated))
	}
}

func TestInMemoryStore_ListByDecision(t *testing.T) {
	store := NewInMemoryStore()
	c1 := NewContinuation("dec_1", "shell", "shell:ls")
	c2 := NewContinuation("dec_1", "git.push", "git:acme/repo")
	store.Create(c1)
	store.Create(c2)

	list := store.ListByDecision("dec_1")
	if len(list) != 2 {
		t.Errorf("count = %d, want 2", len(list))
	}
}

func TestInMemoryStore_ListByAgent(t *testing.T) {
	store := NewInMemoryStore()
	c1 := NewContinuation("dec_1", "shell", "shell:ls").WithAgentID("agt_a")
	c2 := NewContinuation("dec_2", "shell", "shell:ls").WithAgentID("agt_b")
	c3 := NewContinuation("dec_3", "shell", "shell:ls").WithAgentID("agt_a")
	store.Create(c1)
	store.Create(c2)
	store.Create(c3)

	list := store.ListByAgent("agt_a")
	if len(list) != 2 {
		t.Errorf("count = %d, want 2", len(list))
	}
}

func TestInMemoryStore_ListAll(t *testing.T) {
	store := NewInMemoryStore()
	for i := 0; i < 3; i++ {
		c := NewContinuation("dec_"+string(rune('0'+i)), "shell", "shell:ls")
		store.Create(c)
	}

	all := store.ListAll()
	if len(all) != 3 {
		t.Errorf("count = %d, want 3", len(all))
	}
}