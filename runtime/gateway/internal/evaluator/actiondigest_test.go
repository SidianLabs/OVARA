// actionDigest preimage tests: the recorded request binding
// (ReceiptStub.ActionDigest → approval RequestHash → continuation
// request_hash) must commit every evaluated field's bytes. The earlier
// unframed concatenation made "ab"+"c" and "a"+"bc" collide and
// truncated the sha256 to 64 bits.
package evaluator

import (
	"strings"
	"testing"

	"ovara.runtime.gateway/internal/models"
)

func adReq() *models.ActionRequest {
	return &models.ActionRequest{
		ActionType:      models.ActionTypeShell,
		Resource:        "shell:ls",
		AgentIdentity:   &models.AgentIdentity{Issuer: "iss", SubjectID: "agt_a"},
		CapabilityLease: &models.CapabilityLease{LeaseID: "lease_1"},
	}
}

func TestActionDigest_CommitsEveryField(t *testing.T) {
	base := actionDigest(adReq())
	cases := map[string]func(*models.ActionRequest){
		"action_type":  func(r *models.ActionRequest) { r.ActionType = "shelL" },
		"resource":     func(r *models.ActionRequest) { r.Resource = "shell:lt" },
		"agent":        func(r *models.ActionRequest) { r.AgentIdentity.SubjectID = "agt_b" },
		"lease":        func(r *models.ActionRequest) { r.CapabilityLease.LeaseID = "lease_2" },
		"agent_absent": func(r *models.ActionRequest) { r.AgentIdentity = nil },
		"lease_absent": func(r *models.ActionRequest) { r.CapabilityLease = nil },
	}
	for name, mut := range cases {
		r := adReq()
		mut(r)
		if actionDigest(r) == base {
			t.Fatalf("actionDigest blind to %s", name)
		}
	}
}

// Field-boundary slide: concatenated-equal inputs must not collide.
func TestActionDigest_NoBoundarySlide(t *testing.T) {
	a := adReq()
	a.ActionType, a.Resource = "sh", "ell:ls"
	b := adReq()
	b.ActionType, b.Resource = "s", "hell:ls"
	if actionDigest(a) == actionDigest(b) {
		t.Fatal("adjacent-field boundary slide collided")
	}
}

// Present-but-empty vs absent: a nil AgentIdentity and one with an
// empty SubjectID must not collapse to the same digest.
func TestActionDigest_PresentEmptyNotAbsent(t *testing.T) {
	a := adReq()
	a.AgentIdentity = nil
	b := adReq()
	b.AgentIdentity = &models.AgentIdentity{Issuer: "iss", SubjectID: ""}
	if actionDigest(a) == actionDigest(b) {
		t.Fatal("nil vs empty SubjectID collapsed")
	}
}

// The binding is the full sha256 — "sha256:" + 64 hex, not a truncated
// 64-bit prefix.
func TestActionDigest_FullLength(t *testing.T) {
	d := actionDigest(adReq())
	if !strings.HasPrefix(d, "sha256:") || len(d) != len("sha256:")+64 {
		t.Fatalf("actionDigest truncated or malformed: %q", d)
	}
}
