package continuation

import (
	"fmt"
	"testing"

	"ovara.runtime.gateway/internal/approval"
	"ovara.runtime.gateway/internal/models"
)

type errGetter struct{ err error }

func (e errGetter) Get(string) (*approval.ApprovalRequest, error) { return nil, e.err }

func provApproval(id, decID string, status approval.Status) *approval.ApprovalRequest {
	return &approval.ApprovalRequest{
		ApprovalID: id, DecisionID: decID,
		ActionType: models.ActionType("shell"), Resource: "shell:ls",
		Status: status, AgentID: "agt_a",
	}
}

func provContinuation(appID, decID string) *Continuation {
	c := NewContinuation(decID, "shell", "shell:ls").WithAgentID("agt_a")
	if appID != "" {
		c.WithApprovalID(appID)
	}
	return c
}

func TestCheckClaimProvenance(t *testing.T) {
	store := approval.NewInMemoryStore()
	_ = store.Create(provApproval("app_1", "dec_1", approval.StatusApproved))
	_ = store.Create(provApproval("app_pend", "dec_1", approval.StatusPending))

	cases := []struct {
		name     string
		getter   ApprovalGetter
		c        *Continuation
		wantDeny bool
		wantErr  bool
	}{
		{"nil boundary passes", nil, provContinuation("", "dec_1"), false, false},
		{"empty approval ref denied", store, provContinuation("", "dec_1"), true, false},
		{"unresolvable approval denied", store, provContinuation("app_ghost", "dec_1"), true, false},
		{"pending approval denied", store, provContinuation("app_pend", "dec_1"), true, false},
		{"approved matching passes", store, provContinuation("app_1", "dec_1"), false, false},
		{"decision mismatch denied", store, provContinuation("app_1", "dec_other"), true, false},
		{"resource mismatch denied", store, func() *Continuation {
			c := provContinuation("app_1", "dec_1")
			c.Resource = "shell:rm -rf"
			return c
		}(), true, false},
		{"agent mismatch denied", store, func() *Continuation {
			c := provContinuation("app_1", "dec_1")
			c.AgentID = "agt_evil"
			return c
		}(), true, false},
		{"storage error is UNKNOWN", errGetter{fmt.Errorf("disk io")}, provContinuation("app_1", "dec_1"), false, true},
	}
	for _, tc := range cases {
		deny, _, err := CheckClaimProvenance(tc.getter, nil, tc.c)
		if deny != tc.wantDeny || (err != nil) != tc.wantErr {
			t.Fatalf("%s: deny=%v err=%v, want deny=%v err=%v", tc.name, deny, err, tc.wantDeny, tc.wantErr)
		}
	}
}
