// Package decide is the v2 decision engine: composes capability
// verification, policy evaluation, provenance, revocation, quota and
// approval into one deterministic pipeline (spec/policy_ir.md §6,
// threat model P2/P3/P6). Every check returns a decision record —
// denials are audit entries, not silent returns.
package decide

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"ovara.runtime.gateway/core/action"
	"ovara.runtime.gateway/core/capability"
	"ovara.runtime.gateway/core/policy"
)

// Outcome is the external decision vocabulary.
type Outcome string

const (
	OutcomeAllow    Outcome = "allow"
	OutcomeDeny     Outcome = "deny"
	OutcomeEscalate Outcome = "escalate"
)

// Request is a signed action request (spec/capability_token.md §3).
type Request struct {
	Action    action.Action       `json:"action"`
	Token     *capability.Token   `json:"token,omitempty"`
	Nonce     string              `json:"nonce"`
	IssuedAt  time.Time           `json:"issued_at"`
	MinEpoch  uint64              `json:"min_epoch"`
	ActorID   string              `json:"actor_id"` // filled by auth layer, never trusted from wire
	Signature string              `json:"signature"`
}

// RequestCanonical is the signed payload — nonce and issued_at are
// inside the signature so replay/freshness checks are crypto-enforced
// (v1's SEC-0021: nonce on unsigned requests was decorative).
func (r *Request) RequestCanonical() string {
	aj, _ := json.Marshal(r.Action)
	tj := []byte("null")
	if r.Token != nil {
		tj, _ = json.Marshal(r.Token)
	}
	sum := sha256.Sum256(append(append(aj, tj...),
		[]byte(r.Nonce+r.IssuedAt.UTC().Format(time.RFC3339Nano))...))
	return "req|" + r.ActorID + "|" + hex.EncodeToString(sum[:])
}

func (r *Request) VerifySignature(pub ed25519.PublicKey) error {
	if len(r.Signature) < 9 || r.Signature[:9] != "edsig_v2:" {
		return errors.New("decide: bad signature scheme")
	}
	sig, err := hex.DecodeString(r.Signature[9:])
	if err != nil || !ed25519.Verify(pub, []byte(r.RequestCanonical()), sig) {
		return errors.New("decide: signature invalid")
	}
	return nil
}

// Result wraps the outcome with the audit-grade record.
type Result struct {
	Outcome     Outcome          `json:"outcome"`
	ReasonClass string           `json:"reason_class"` // agent-visible
	OpReason    string           `json:"op_reason"`    // operator-visible
	PolicyID    string           `json:"policy_id"`
	ActionHash  string           `json:"action_hash"`
	ApprovalID  string           `json:"approval_id,omitempty"`
}

// ApprovalStore binds approvals to action hashes (single-use,
// expiring — spec/approval_protocol.md).
type ApprovalStore interface {
	// Resolve records the resolution; returns the bound action hash
	// the approval covers.
	Resolve(approvalID string, approve bool, opSig string) (actionHash string, err error)
}

// Engine is the deterministic evaluator.
type Engine struct {
	Pol          *policy.Policy
	Issuers      map[string]ed25519.PublicKey
	ActorKeys    map[string]ed25519.PublicKey // actor -> request-signing key
	CurrentEpoch func() uint64
	FreshnessSec int
	mu           sync.Mutex
	seenNonces   map[string]time.Time // replay guard (durable impl later)
	now          func() time.Time
}

func NewEngine(p *policy.Policy, issuers, actorKeys map[string]ed25519.PublicKey, epoch func() uint64) *Engine {
	return &Engine{Pol: p, Issuers: issuers, ActorKeys: actorKeys,
		CurrentEpoch: epoch, FreshnessSec: 60,
		seenNonces: map[string]time.Time{}, now: time.Now}
}

// Evaluate runs the fixed pipeline. Order chosen so cheap checks run
// before crypto: schema → freshness → epoch → replay → signature →
// capability → policy.
func (e *Engine) Evaluate(req *Request) Result {
	ah := actionHash(req.Action)
	fail := func(cls, op string) Result {
		return Result{Outcome: OutcomeDeny, ReasonClass: cls,
			OpReason: op, ActionHash: ah, PolicyID: e.Pol.ID()}
	}
	if req.Action.Type == "" || req.Nonce == "" || req.ActorID == "" {
		return fail("action_not_allowed", "missing required fields")
	}
	now := e.now().UTC()
	if req.IssuedAt.After(now.Add(60*time.Second)) ||
		req.IssuedAt.Before(now.Add(-time.Duration(e.FreshnessSec)*time.Second)) {
		return fail("action_not_allowed", "issued_at outside freshness window")
	}
	if e.CurrentEpoch() < req.MinEpoch {
		return fail("action_not_allowed", "min_epoch beyond current epoch")
	}
	e.mu.Lock()
	if _, seen := e.seenNonces[req.Nonce]; seen {
		e.mu.Unlock()
		return fail("action_not_allowed", "nonce replay")
	}
	e.seenNonces[req.Nonce] = now
	e.mu.Unlock()

	pub, ok := e.ActorKeys[req.ActorID]
	if !ok {
		return fail("action_not_allowed", "actor has no registered signing key")
	}
	if err := req.VerifySignature(pub); err != nil {
		return fail("action_not_allowed", err.Error())
	}
	if req.Token != nil {
		eff, err := capability.Verify(req.Token, e.Issuers, e.CurrentEpoch())
		if err != nil {
			return fail("capability_missing", err.Error())
		}
		if !eff.Covers(req.Action) {
			return fail("capability_missing", "token scope does not cover action")
		}
	}
	pd := policy.Eval(e.Pol, req.Action, req.ActorID)
	out := Result{ReasonClass: pd.ReasonClass, OpReason: fmt.Sprintf(
		"matched %v", pd.MatchedIDs), ActionHash: ah, PolicyID: pd.PolicyID}
	switch pd.Outcome {
	case policy.Allow:
		out.Outcome = OutcomeAllow
	case policy.Deny:
		out.Outcome = OutcomeDeny
	case policy.Escalate:
		out.Outcome = OutcomeEscalate
	case policy.RequireCap:
		if req.Token == nil {
			out.Outcome, out.ReasonClass = OutcomeEscalate, "capability_missing"
		} else {
			out.Outcome = OutcomeAllow // capability verified + covers → allow
		}
	}
	return out
}

func actionHash(a action.Action) string {
	j, _ := json.Marshal(a)
	sum := sha256.Sum256(j)
	return "sha256:" + hex.EncodeToString(sum[:16])
}
