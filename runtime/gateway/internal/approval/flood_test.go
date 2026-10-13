package approval

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"ovara.runtime.gateway/internal/models"
)

func openReq(decision, agent, resource string, ctx map[string]string) *CreateRequest {
	return &CreateRequest{
		DecisionID: decision, ActionType: models.ActionType("http.request"),
		Resource: resource, Environment: models.EnvironmentDev, AgentID: agent, Context: ctx,
	}
}

// One agent can keep at most MaxPendingPerAgent approvals waiting; past
// that, opening another fails until one is resolved or expires. Other
// agents are not affected.
func TestOpen_PerAgentPendingCap(t *testing.T) {
	now := time.Now().UTC()
	svc := NewService(NewInMemoryStore())
	svc.SetNow(clockAt(&now))
	if svc.MaxPendingPerAgent() != DefaultMaxPendingPerAgent || DefaultMaxPendingPerAgent != 16 {
		t.Fatalf("default cap %d", svc.MaxPendingPerAgent())
	}
	var first *ApprovalRequest
	for i := 0; i < DefaultMaxPendingPerAgent; i++ {
		a, reused, err := svc.Open(openReq(fmt.Sprintf("dec_%d", i), "agent-1", fmt.Sprintf("POST https://x.example/%d", i), nil))
		if err != nil || reused {
			t.Fatalf("approval %d: %v reused=%v", i, err, reused)
		}
		if first == nil {
			first = a
		}
	}
	if _, _, err := svc.Open(openReq("dec_over", "agent-1", "POST https://x.example/over", nil)); !errors.Is(err, ErrTooManyPending) {
		t.Fatalf("17th pending approval: %v", err)
	}
	if _, _, err := svc.Open(openReq("dec_other", "agent-2", "POST https://x.example/over", nil)); err != nil {
		t.Fatalf("another agent was capped too: %v", err)
	}
	// resolving one frees a slot
	if _, err := svc.Deny(first.ApprovalID, "operator", "no"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.Open(openReq("dec_over", "agent-1", "POST https://x.example/over", nil)); err != nil {
		t.Fatalf("after a deny: %v", err)
	}
	// expired approvals do not count
	now = now.Add(DefaultPendingTTL + time.Second)
	if _, _, err := svc.Open(openReq("dec_later", "agent-1", "POST https://x.example/later", nil)); err != nil {
		t.Fatalf("after expiry: %v", err)
	}
}

// The same request from the same agent while one is already waiting gets
// the waiting approval back instead of a second card.
func TestOpen_DeduplicatesIdenticalPending(t *testing.T) {
	now := time.Now().UTC()
	svc := NewService(NewInMemoryStore())
	svc.SetNow(clockAt(&now))
	ctx := map[string]string{"body_sha256": "abc", "body_bytes": "10"}
	a, reused, err := svc.Open(openReq("dec_1", "agent-1", "POST https://x.example/a", ctx))
	if err != nil || reused {
		t.Fatal(err, reused)
	}
	b, reused, err := svc.Open(openReq("dec_2", "agent-1", "POST https://x.example/a", map[string]string{"body_bytes": "10", "body_sha256": "abc"}))
	if err != nil || !reused || b.ApprovalID != a.ApprovalID {
		t.Fatalf("identical request: %v reused=%v id=%s want %s", err, reused, b.ApprovalID, a.ApprovalID)
	}
	if n := len(svc.ListPending()); n != 1 {
		t.Fatalf("%d pending cards for one request", n)
	}
	// anything different is a new card: body, resource, agent, action
	for _, r := range []*CreateRequest{
		openReq("dec_3", "agent-1", "POST https://x.example/a", map[string]string{"body_sha256": "def", "body_bytes": "10"}),
		openReq("dec_4", "agent-1", "POST https://x.example/b", ctx),
		openReq("dec_5", "agent-2", "POST https://x.example/a", ctx),
		{DecisionID: "dec_6", ActionType: "shell", Resource: "POST https://x.example/a", Environment: models.EnvironmentDev, AgentID: "agent-1", Context: ctx},
	} {
		c, reused, err := svc.Open(r)
		if err != nil || reused || c.ApprovalID == a.ApprovalID {
			t.Errorf("%s: deduplicated a different request (%v)", r.DecisionID, err)
		}
	}
	// once resolved, the same request opens a fresh card
	if _, err := svc.Approve(a.ApprovalID, "operator"); err != nil {
		t.Fatal(err)
	}
	c, reused, err := svc.Open(openReq("dec_7", "agent-1", "POST https://x.example/a", ctx))
	if err != nil || reused || c.ApprovalID == a.ApprovalID {
		t.Fatalf("after approval: reused=%v err=%v", reused, err)
	}
	// and an expired one is not reused either
	now = now.Add(DefaultPendingTTL + time.Second)
	d, reused, err := svc.Open(openReq("dec_8", "agent-1", "POST https://x.example/a", ctx))
	if err != nil || reused || d.ApprovalID == c.ApprovalID {
		t.Fatalf("after expiry: reused=%v err=%v", reused, err)
	}
}
