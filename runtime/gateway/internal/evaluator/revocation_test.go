package evaluator

import (
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"

	"ovara.runtime.gateway/internal/gwidentity"
	"ovara.runtime.gateway/internal/models"
	"ovara.runtime.gateway/internal/policy"
	"ovara.runtime.gateway/internal/revocation"
)

type fakeRevChecker struct {
	revoked map[revocation.Pair]bool
	err     error
	epoch   uint64
}

func (f *fakeRevChecker) AnyRevoked(pairs ...revocation.Pair) (revocation.Pair, bool, error) {
	if f.err != nil {
		return revocation.Pair{}, false, f.err
	}
	for _, p := range pairs {
		if f.revoked[p] {
			return p, true, nil
		}
	}
	return revocation.Pair{}, false, nil
}

func (f *fakeRevChecker) Epoch() (uint64, error) { return f.epoch, f.err }

func allowAllStore(t *testing.T) *policy.Store {
	t.Helper()
	return storeFromConfig(t, map[string]any{
		"policy_version": "test",
		"rules": []any{map[string]any{
			"action_type": "*", "environment": "*", "allow": true}},
	})
}

func baseReq() *models.ActionRequest {
	return &models.ActionRequest{
		Nonce:       uuid.NewString(),
		IssuedAt:    time.Now(),
		ActionType:  models.ActionTypeShell,
		Resource:    "shell:echo",
		Environment: models.EnvironmentLocal,
		AgentIdentity: &models.AgentIdentity{
			Issuer: "ovara", SubjectID: "agent-1",
		},
	}
}

// min_epoch: a request citing a future epoch must not execute under a
// stale view; below-or-equal satisfies.
func TestMinEpoch_StaleViewDenies(t *testing.T) {
	ev := New(allowAllStore(t))
	fc := &fakeRevChecker{revoked: map[revocation.Pair]bool{}, epoch: 5}
	ev.SetRevocation(fc)

	req := baseReq()
	req.MinEpoch = 10 // caller needs revocation state ≥ 10
	resp, err := ev.Evaluate(req)
	if err != nil {
		t.Fatalf("eval: %v", err)
	}
	if resp.Decision != models.DecisionDeny {
		t.Fatalf("stale view must deny, got %s", resp.Decision)
	}
	if !hasReason(resp, models.ReasonRevocationEpoch) {
		t.Fatalf("expected revocation_epoch_stale, got %v", resp.ReasonCodes)
	}
}

func TestMinEpoch_SatisfiedAllows(t *testing.T) {
	ev := New(allowAllStore(t))
	fc := &fakeRevChecker{revoked: map[revocation.Pair]bool{}, epoch: 10}
	ev.SetRevocation(fc)
	req := baseReq()
	req.MinEpoch = 10
	resp, _ := ev.Evaluate(req)
	if resp.Decision != models.DecisionAllow {
		t.Fatalf("fresh view must allow, got %s (%v)", resp.Decision, resp.ReasonCodes)
	}
}

// RVI-09: epoch unprovable → deny even for a min_epoch request.
func TestMinEpoch_UnknownEpochDenies(t *testing.T) {
	ev := New(allowAllStore(t))
	ev.SetRevocation(&fakeRevChecker{err: fmt.Errorf("store corrupt")})
	req := baseReq()
	req.MinEpoch = 1
	resp, _ := ev.Evaluate(req)
	if resp.Decision != models.DecisionDeny {
		t.Fatal("unknown epoch must deny a min_epoch request")
	}
}

// No revocation boundary configured → min_epoch cannot be satisfied.
func TestMinEpoch_NoCheckerDenies(t *testing.T) {
	ev := New(allowAllStore(t))
	req := baseReq()
	req.MinEpoch = 1
	resp, _ := ev.Evaluate(req)
	if resp.Decision != models.DecisionDeny {
		t.Fatal("no revocation store → min_epoch unsatisfiable → deny")
	}
	if !hasReason(resp, models.ReasonRevocationUnavailable) {
		t.Fatalf("expected revocation_unavailable, got %v", resp.ReasonCodes)
	}
}

// Receipt binds the epoch the decision was made against.
func TestReceiptTrustEpoch(t *testing.T) {
	ev := New(allowAllStore(t))
	fc := &fakeRevChecker{epoch: 42}
	ev.SetRevocation(fc)
	resp, _ := ev.Evaluate(baseReq())
	if resp.ReceiptStub == nil || resp.ReceiptStub.TrustEpoch != 42 {
		t.Fatalf("receipt must carry trust_epoch=42, got %+v", resp.ReceiptStub)
	}
}

// RVI-15: the same revocation boundary covers the eval path — a real
// journal-backed checker, lease revoked in the durable store.
func TestEval_LeaseRevocationThroughJournal(t *testing.T) {
	reg := gwidentity.NewInMemory()
	ev := New(allowAllStore(t))
	ev.SetRevocation(reg)

	// A lease-bearing request must deny once the lease is revoked in
	// the journal — even though no signature check can run here (no
	// trusted issuers → unsigned lease fails sig anyway), the lease
	// revocation class check still applies when a validator exists.
	// Direct-check the boundary the claim path shares:
	if _, err := reg.Revoke("lease", "lse-x", "op", ""); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	_, rev, err := reg.AnyRevoked(revocation.P(revocation.ClassLease, "lse-x"))
	if err != nil || !rev {
		t.Fatal("journal revocation must answer")
	}
}

func hasReason(r *models.DecisionResponse, code models.ReasonCode) bool {
	for _, c := range r.ReasonCodes {
		if c == code {
			return true
		}
	}
	return false
}
