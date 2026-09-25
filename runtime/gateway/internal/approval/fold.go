package approval

import (
	"encoding/json"
	"fmt"
	"slices"

	"ovara.runtime.gateway/internal/record"
)

// Signed-journal fold (C5): approvals follow a total state table —
// genesis is always pending; pending resolves exactly once to approved
// or denied; approved may rewrite once to consume its resume token.
// Nothing else is a legal record. The immutable authority core of an
// approval_id can never change across its history.
func (s *FileBackedStore) foldEvent(env *record.Envelope) error {
	switch env.Type {
	case "approval":
		var a ApprovalRequest
		if err := json.Unmarshal(env.Payload, &a); err != nil {
			return fmt.Errorf("corrupt approval payload: %w", err)
		}
		if env.RecordID != a.ApprovalID {
			return fmt.Errorf("envelope record_id %q does not match payload approval_id %q", env.RecordID, a.ApprovalID)
		}
		// C2-B A1: stamp the signing key_ref onto the folded record so
		// claim-time provenance can verify the approver-key role/state
		// without trusting the payload.
		a.SignerKeyID = env.KeyRef.KeyID
		return s.foldApproval(&a)
	case record.TypeTombstone:
		// Deletion: the approval is erased but the tombstone keeps the
		// id dead — a new genesis for the same id is a fold error.
		s.tombstones[env.RecordID] = true
		delete(s.items, env.RecordID)
		return nil
	case record.TypeCompact:
		return nil // approvals do not emit compact events; a stray one is inert
	case record.TypeMigration:
		return nil // provenance marker
	default:
		return fmt.Errorf("unknown record type %q", env.Type)
	}
}

func (s *FileBackedStore) foldApproval(a *ApprovalRequest) error {
	id := a.ApprovalID
	if id == "" {
		return fmt.Errorf("record_id-less approval")
	}
	if s.tombstones[id] {
		return fmt.Errorf("genesis over tombstone for %s", id)
	}
	prev, ok := s.items[id]
	if !ok {
		if a.Status != StatusPending {
			return fmt.Errorf("non-pending genesis for %s", id)
		}
		s.items[id] = a
		return nil
	}
	if !sameCore(prev, a) {
		return fmt.Errorf("immutable core of %s mutated", id)
	}
	// Total table: pending→{approved,denied}; approved→approved
	// (resume consume: ResumedAt nil→set, exactly once); everything
	// else refuses.
	switch {
	case prev.Status == StatusPending && (a.Status == StatusApproved || a.Status == StatusDenied):
	case prev.Status == StatusApproved && a.Status == StatusApproved &&
		prev.ResumedAt == nil && a.ResumedAt != nil:
	case prev.Status == a.Status && prev.ResumedAt == nil && a.ResumedAt == nil &&
		prev.ResolvedBy == a.ResolvedBy && prev.Reason == a.Reason:
		// Same-state rewrite (generic Update) — restates, never mutates
		// resolution evidence.
	default:
		return fmt.Errorf("illegal transition %s → %s", prev.Status, a.Status)
	}
	s.items[id] = a
	return nil
}

// sameCore: every authority-bearing field is frozen at genesis.
func sameCore(a, b *ApprovalRequest) bool {
	return a.DecisionID == b.DecisionID &&
		a.ActionType == b.ActionType &&
		a.Resource == b.Resource &&
		a.Environment == b.Environment &&
		a.CreatedAt.Equal(b.CreatedAt) &&
		a.AgentID == b.AgentID &&
		a.RequestHash == b.RequestHash &&
		a.PolicyVersion == b.PolicyVersion &&
		a.LeaseID == b.LeaseID &&
		slices.Equal(a.DelegationKeys, b.DelegationKeys) &&
		slices.Equal(a.Issuers, b.Issuers)
}
