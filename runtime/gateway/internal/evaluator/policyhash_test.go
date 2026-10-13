package evaluator

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"ovara.runtime.gateway/internal/models"
	"ovara.runtime.gateway/internal/policy"
)

// Every decision's receipt stub names the exact policy content it was
// decided under, and follows a change to the policy.
func TestDecisionCarriesPolicyHash(t *testing.T) {
	st := specificStore(rule("GET https://pypi.org/*", "allow", "reads"))
	ev := New(st)
	eval := func() *models.DecisionResponse {
		t.Helper()
		resp, err := ev.Evaluate(&models.ActionRequest{
			Nonce: uuid.NewString(), IssuedAt: time.Now(),
			ActionType: "http.request", Resource: "GET https://pypi.org/simple/", Environment: models.EnvironmentDev,
			AgentIdentity: &models.AgentIdentity{Issuer: "t", SubjectID: "a"},
		})
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	resp := eval()
	if resp.ReceiptStub == nil || resp.ReceiptStub.PolicyHash == "" || resp.ReceiptStub.PolicyHash != st.Hash() {
		t.Fatalf("receipt stub policy_hash %+v, store %s", resp.ReceiptStub, st.Hash())
	}
	if ev.PolicyHash() != st.Hash() {
		t.Fatalf("evaluator policy hash %s", ev.PolicyHash())
	}
	before := resp.ReceiptStub.PolicyHash
	st.AddRule(policy.Rule{ActionType: "shell", Environment: "*", Deny: true})
	if after := eval().ReceiptStub.PolicyHash; after == before || after != st.Hash() {
		t.Fatalf("policy changed but hash did not follow: %s → %s", before, after)
	}
}
