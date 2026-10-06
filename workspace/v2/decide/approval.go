package decide

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

// Approval is a single-use, expiring, hash-bound operator grant
// (spec/approval_protocol.md). An approval is worthless for any
// action hash other than the one it was minted against.
type Approval struct {
	ID         string    `json:"id"`
	ActionHash string    `json:"action_hash"`
	PolicyID   string    `json:"policy_id"`
	Created    time.Time `json:"created"`
	Expires    time.Time `json:"expires"`
	State      string    `json:"state"` // pending | approved | denied | expired | consumed
	OpSig      string    `json:"op_sig"`
}

// MemApprovalStore is the reference in-memory implementation.
// Production swaps in a durable store; the contract is what matters.
type MemApprovalStore struct {
	mu         sync.Mutex
	approvals  map[string]*Approval
	ttl        time.Duration
	operatorPK ed25519.PublicKey
	now        func() time.Time
}

func NewApprovalStore(ttl time.Duration, opPub ed25519.PublicKey) *MemApprovalStore {
	return &MemApprovalStore{approvals: map[string]*Approval{},
		ttl: ttl, operatorPK: opPub, now: time.Now}
}

// Create registers a pending approval for an action hash.
func (s *MemApprovalStore) Create(id, actionHash, policyID string) *Approval {
	s.mu.Lock()
	defer s.mu.Unlock()
	a := &Approval{ID: id, ActionHash: actionHash, PolicyID: policyID,
		Created: s.now().UTC(), Expires: s.now().UTC().Add(s.ttl),
		State: "pending"}
	s.approvals[id] = a
	return a
}

// opPayload is what the operator signs — binding approval id to the
// action hash so a stolen token can't redirect the grant.
func (a *Approval) opPayload() string {
	return "appr|" + a.ID + "|" + a.ActionHash
}

// Resolve satisfies the ApprovalStore interface: verifies the
// operator signature over the bound payload, enforces expiry and
// single-use, and returns the covered action hash.
func (s *MemApprovalStore) Resolve(approvalID string, approve bool, opSigHex string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.approvals[approvalID]
	if !ok {
		return "", errors.New("approval: unknown id")
	}
	if s.now().After(a.Expires) {
		a.State = "expired"
		return "", errors.New("approval: expired")
	}
	if a.State != "pending" {
		return "", errors.New("approval: already resolved (single-use)")
	}
	sig, err := hex.DecodeString(opSigHex)
	if err != nil || !ed25519.Verify(s.operatorPK, []byte(a.opPayload()), sig) {
		return "", errors.New("approval: operator signature invalid")
	}
	if approve {
		a.State = "approved"
	} else {
		a.State = "denied"
		return "", errors.New("approval: denied by operator")
	}
	return a.ActionHash, nil
}

// Consume marks an approved approval as used — the second Consume or
// Resolve-after-consume fails (single-use).
func (s *MemApprovalStore) Consume(approvalID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.approvals[approvalID]
	if !ok {
		return errors.New("approval: unknown id")
	}
	if a.State != "approved" {
		return errors.New("approval: not in approved state")
	}
	a.State = "consumed"
	return nil
}

// CheckApproved returns whether an approved (not yet consumed)
// approval exists binding this action hash — used when a held action
// is retried after operator approval.
func (s *MemApprovalStore) CheckApproved(actionHash string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, a := range s.approvals {
		if a.ActionHash == actionHash && a.State == "approved" &&
			s.now().Before(a.Expires) {
			return a.ID, true
		}
	}
	return "", false
}
