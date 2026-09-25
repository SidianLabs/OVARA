// Claim-time provenance enforcement for continuations (post-C2).
//
// The signed journal proves a record was signed by the gateway key —
// it does not prove the record was produced through the authorized
// evaluate → escalate → approve pipeline (C2-KEY-ROOT: a stolen key
// can inject a validly signed `queued` record directly). This check
// narrows that: a queued continuation must carry a resolvable,
// approved approval record whose decision/action/resource/agent
// context matches the continuation's own.
//
// Scope honesty: this is provenance hardening, NOT a signing-root
// fix — the same compromised key can also sign a coherent approval
// record, so a determined attacker can manufacture the whole graph.
// It raises the attack from "forge one empty record" to "forge a
// consistent cross-journal state" and eliminates the demonstrated
// cheap empty-authority path.
package continuation

import (
	"fmt"
	"strings"

	"ovara.runtime.gateway/internal/approval"
)

// ApprovalGetter resolves approval records — the evidence that a
// continuation's authority was produced by the approval pipeline.
type ApprovalGetter interface {
	Get(id string) (*approval.ApprovalRequest, error)
}

// ApproverKeyChecker reports whether a key id is a live approver-
// role key (C2-B A1: *gwidentity.Registry implements it). Role is
// part of the trust decision — the approval's envelope key_ref must
// resolve to a currently usable approver key.
type ApproverKeyChecker interface {
	ApproverUsable(keyID string) bool
}

// CheckClaimProvenance revalidates a claimed continuation's pipeline
// provenance at the same atomic claim boundary as CheckClaimAuthority.
//
//	deny=true            → terminal: transition to denied, audit why
//	err≠nil              → UNKNOWN (storage failure): never execute —
//	                      requeue so the claim fails closed
//	deny=false, err=nil  → provenance chain resolves
func CheckClaimProvenance(approvals ApprovalGetter, keys ApproverKeyChecker, c *Continuation) (deny bool, reason string, err error) {
	if approvals == nil {
		return false, "", nil // no provenance boundary configured — runtime-only mode
	}
	if c.ApprovalID == "" {
		return true, "continuation carries no approval reference", nil
	}
	ap, err := approvals.Get(c.ApprovalID)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return true, fmt.Sprintf("approval %s not resolvable", c.ApprovalID), nil
		}
		return false, "", err
	}
	if ap.Status != approval.StatusApproved {
		return true, fmt.Sprintf("approval %s not approved (status %s)", ap.ApprovalID, ap.Status), nil
	}
	if ap.DecisionID != c.DecisionID {
		return true, "approval/continuation decision mismatch", nil
	}
	if string(ap.ActionType) != c.ActionType || ap.Resource != c.Resource {
		return true, "approval/continuation action mismatch", nil
	}
	if ap.AgentID != "" && c.AgentID != "" && ap.AgentID != c.AgentID {
		return true, "approval/continuation agent mismatch", nil
	}
	// C2-B A1: when the registry is wired, a record that carries a
	// signer key_ref must have been made by a currently-usable
	// approver key. Legacy/unsigned records (no SignerKeyID) and
	// checker-less deployments (in-memory, runtime-only) skip this —
	// the journal fold already enforces signer authenticity when a
	// durable binding exists.
	if keys != nil && ap.SignerKeyID != "" && !keys.ApproverUsable(ap.SignerKeyID) {
		return true, fmt.Sprintf("approval signer %s is not a usable approver key", ap.SignerKeyID), nil
	}
	return false, "", nil
}
