// The emitter — domain A's side. Each authority boundary calls the
// matching Emit*: the bundle resolves the prior emission for the
// decision (latest-stage wins), carries its material forward, gets
// re-signed under the gateway's journal key, registered on the
// transparency ledger, and journaled. Emission is evidence, never
// authorization: callers log the error and continue.
package lineage

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"ovara.runtime.gateway/internal/approval"
	"ovara.runtime.gateway/internal/models"
	"ovara.runtime.gateway/internal/record"

	"github.com/google/uuid"
)

// Emitter assembles, signs, registers, and stores lineage bundles.
// signer is the gateway's journal signing identity (local or remote —
// custody model preserved through record.Signer).
type Emitter struct {
	domain  string
	signer  *record.Signer
	ledger  Publisher
	store   *Store
	onError func(error) // optional SECURITY-log hook
}

// NewEmitter binds the emitting domain. ledger and store are required:
// an emitter that cannot ledger or journal would emit claims that
// never happened — nil is rejected, not tolerated.
func NewEmitter(domainID string, signer *record.Signer, ledger Publisher, store *Store) (*Emitter, error) {
	if signer == nil || ledger == nil || store == nil || domainID == "" {
		return nil, fmt.Errorf("lineage: emitter requires domain, signer, ledger and store")
	}
	return &Emitter{domain: domainID, signer: signer, ledger: ledger, store: store}, nil
}

// SetErrorHook installs the notification for evidence-write failures.
func (e *Emitter) SetErrorHook(fn func(error)) { e.onError = fn }

func (e *Emitter) failf(format string, args ...any) error {
	err := fmt.Errorf(format, args...)
	if e.onError != nil {
		e.onError(err)
	}
	return err
}

// emit is the shared path: enrich the prior bundle (if any) for the
// decision with mutate, then sign → register → journal.
func (e *Emitter) emit(decisionID string, stage string, action ActionRef, mutate func(b *Bundle)) (*Bundle, error) {
	var b Bundle
	if prior := e.store.ByDecision(decisionID); prior != nil {
		b = *prior
	}
	b.V = Version
	b.LineageID = "lin_" + uuid.New().String()
	b.DomainID = e.domain
	b.Stage = stage
	b.IssuedAt = time.Now().UTC()
	if b.Action.ActionType == "" {
		b.Action = action
	} else if action.ActionType != "" && (action.ActionType != b.Action.ActionType || action.Resource != b.Action.Resource) {
		// A stage that disagrees with the recorded action is a broken
		// pipeline, not a new lineage — refuse rather than emit a
		// self-contradicting bundle.
		return nil, e.failf("lineage: stage %s action mismatch for decision %s", stage, decisionID)
	}
	b.Inclusion = nil
	mutate(&b)

	ref := e.signer.Ref()
	b.GatewayID, b.GatewayKeyID = ref.GatewayID, ref.KeyID
	sig, err := e.signer.Sign(b.Payload())
	if err != nil {
		return nil, e.failf("lineage: sign: %w", err)
	}
	b.Sig = sigPrefix + hex.EncodeToString(sig)

	inc, err := e.ledger.Register(b.StatementDigest())
	if err != nil {
		return nil, e.failf("lineage: ledger registration refused: %w", err)
	}
	b.Inclusion = inc

	if err := e.store.Put(&b); err != nil {
		return nil, e.failf("lineage: store: %w", err)
	}
	return &b, nil
}

// EmitDecision binds the evaluated request's presented authority
// (lease + delegation, as received) to the signed decision receipt.
func (e *Emitter) EmitDecision(req *models.ActionRequest, rc *models.Receipt) (*Bundle, error) {
	action := ActionRef{ActionType: string(req.ActionType), Resource: req.Resource,
		Environment: string(req.Environment)}
	if req.AgentIdentity != nil {
		action.AgentID = req.AgentIdentity.SubjectID
	}
	return e.emit(rc.DecisionID, StageDecision, action, func(b *Bundle) {
		b.Receipt = rc
		b.Lease = req.CapabilityLease
		b.Delegation = req.DelegationChain
	})
}

// EmitApproval binds an approval record and its approver-signed
// journal envelope (the provenance artifact proving the approval was
// minted under the approver root, not the gateway key).
func (e *Emitter) EmitApproval(decisionID string, ap *approval.ApprovalRequest, env *record.Envelope) (*Bundle, error) {
	if env == nil {
		return nil, e.failf("lineage: approval %s has no signed envelope — provenance would be unverifiable", ap.ApprovalID)
	}
	return e.emit(decisionID, StageApproval, ActionRef{
		ActionType: string(ap.ActionType), Resource: ap.Resource, AgentID: ap.AgentID,
		Environment: string(ap.Environment)}, func(b *Bundle) {
		b.Approval = ap
		b.ApprovalEnv = env
	})
}

// EmitExecution binds the dispatch the lineage culminates in.
func (e *Emitter) EmitExecution(decisionID string, ex ExecRef) (*Bundle, error) {
	return e.emit(decisionID, StageExecution, ActionRef{}, func(b *Bundle) {
		b.Execution = &ex
	})
}

// MarshalBundle is the wire form a counterparty receives.
func MarshalBundle(b *Bundle) ([]byte, error) { return json.Marshal(b) }

// UnmarshalBundle parses a received bundle (all bytes checked at
// verify time — this is transport, not trust).
func UnmarshalBundle(data []byte) (*Bundle, error) {
	var b Bundle
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, err
	}
	return &b, nil
}
