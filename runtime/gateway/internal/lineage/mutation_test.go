// Canonical-preimage mutation property for lin_v1 (docs/ACTION_LINEAGE.md).
//
// Regression class under test: a preimage helper that commits field
// LENGTHS but drops field CONTENTS — lp returning append(l[:], b...)
// instead of length‖content — makes every digest/signature blind to
// same-length tampering: two bundles that differ in every byte but
// share a field-length profile sign identically. The property is
// brute-simple: mutate ONE covered field to a different value of the
// SAME length, rebuild, and the preimage must differ. Every builder
// in the signing path gets the same table.
package lineage

import (
	"bytes"
	"testing"
	"time"

	"ovara.runtime.gateway/internal/approval"
	"ovara.runtime.gateway/internal/models"
	"ovara.runtime.gateway/internal/record"
)

// mutationBundle is a fully-populated bundle — every Payload member is
// non-nil so each digestHex position carries real content.
const resShellXX = "shell:xx" // same-length mutation target for Resource fields

func mutationBundle() *Bundle {
	return &Bundle{
		V:         Version,
		LineageID: "lin_aaa",
		DomainID:  "domA",
		Stage:     StageExecution,
		IssuedAt:  time.Unix(1700000000, 500).UTC(),
		Action: ActionRef{
			ActionType:  "shell",
			Resource:    "shell:ls",
			AgentID:     "agt_a",
			Environment: "local",
		},
		Receipt: &models.Receipt{
			ReceiptID:  "rcpt_1",
			DecisionID: "dec_1",
			ActionType: "shell",
			Resource:   "shell:ls",
			IssuedAt:   time.Unix(1700000000, 0).UTC(),
		},
		Lease: &models.CapabilityLease{
			LeaseID: "lease_1", Issuer: "iss_a", Subject: "agt_a",
			AllowedActions: []string{"shell"}, Expiry: time.Unix(1700003600, 0).UTC(),
		},
		Delegation: &models.DelegationChain{Authorities: []models.Authority{
			{Issuer: "iss_a", SubjectID: "agt_a", Nonce: "n1"},
		}},
		Approval: &approval.ApprovalRequest{
			ApprovalID: "app_1", DecisionID: "dec_1",
			ActionType: models.ActionTypeShell, Resource: "shell:ls",
			Status: approval.StatusApproved, AgentID: "agt_a",
		},
		ApprovalEnv: &record.Envelope{
			V: record.Version, Type: "approval", DomainID: "domA",
			Seq: 7, RecordID: "app_1", Parent: "pp",
			Payload: []byte(`{"approval_id":"app_1"}`),
			KeyRef:  record.KeyRef{GatewayID: "approver", KeyID: "ak1"},
			Sig:     "aa",
		},
		Execution:    &ExecRef{ContinuationID: "cnt_1", ExecutionID: "exe_1", State: "running"},
		GatewayID:    "gw1",
		GatewayKeyID: "gk1",
		Sig:          "lin_v1:" + "00",
	}
}

// Every string mutation swaps contents at the SAME length — the
// discriminating case a length-only framer cannot see. Member
// mutations change the member's digestHex at a fixed 64-char width,
// so they are same-length edits of the covered position.
func TestPayload_FieldMutationChangesPreimage(t *testing.T) {
	base := mutationBundle().Payload()
	mutations := []struct {
		name string
		mut  func(*Bundle)
	}{
		{"lineage_id", func(b *Bundle) { b.LineageID = "lin_bbb" }},
		{"domain_id", func(b *Bundle) { b.DomainID = "domB" }},
		{"stage", func(b *Bundle) { b.Stage = StageDecision }},
		{"stage_same_len", func(b *Bundle) { b.Stage = "executi_n" }},
		{"issued_at", func(b *Bundle) { b.IssuedAt = b.IssuedAt.Add(time.Second) }},
		{"action_type", func(b *Bundle) { b.Action.ActionType = "fetch" }},
		{"action_resource", func(b *Bundle) { b.Action.Resource = resShellXX }},
		{"action_agent", func(b *Bundle) { b.Action.AgentID = "agt_b" }},
		{"action_env", func(b *Bundle) { b.Action.Environment = "cloud" }},
		{"receipt_member", func(b *Bundle) { b.Receipt.Resource = resShellXX }},
		{"receipt_nil", func(b *Bundle) { b.Receipt = nil }},
		{"lease_member", func(b *Bundle) { b.Lease.LeaseID = "lease_2" }},
		{"delegation_member", func(b *Bundle) { b.Delegation.Authorities[0].Nonce = "n2" }},
		{"approval_member", func(b *Bundle) { b.Approval.Resource = resShellXX }},
		{"approval_env_member", func(b *Bundle) { b.ApprovalEnv.Seq = 8 }},
		{"approval_env_payload", func(b *Bundle) { b.ApprovalEnv.Payload = []byte(`{"approval_id":"app_2"}`) }},
		{"execution_member", func(b *Bundle) { b.Execution.ExecutionID = "exe_2" }},
		{"execution_nil", func(b *Bundle) { b.Execution = nil }},
		{"gateway_id", func(b *Bundle) { b.GatewayID = "gw2" }},
		{"gateway_key_id", func(b *Bundle) { b.GatewayKeyID = "gk2" }},
	}
	for _, m := range mutations {
		b := mutationBundle()
		m.mut(b)
		if bytes.Equal(b.Payload(), base) {
			t.Errorf("%s: mutation produced identical signing preimage", m.name)
		}
	}
}

// The ledger countersignature preimage binds (ledger domain, statement
// digest, seq, parent). A content-blind builder lets a forged
// inclusion receipt verify — the digest field is fixed-width hex, so
// same-length substitution is the attack that must not pass.
func TestInclusionPayload_FieldMutationChangesPreimage(t *testing.T) {
	const digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	const parent = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
	base := InclusionPayload("domA/ledger", digest, 41, parent)
	mutations := []struct {
		name string
		got  []byte
	}{
		{"domain", InclusionPayload("domB/ledger", digest, 41, parent)},
		{"digest", InclusionPayload("domA/ledger", "1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", 41, parent)},
		{"seq", InclusionPayload("domA/ledger", digest, 42, parent)},
		{"parent", InclusionPayload("domA/ledger", digest, 41, "0edcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210")},
	}
	for _, m := range mutations {
		if bytes.Equal(m.got, base) {
			t.Errorf("%s: inclusion preimage unchanged by mutation", m.name)
		}
	}
}

// StatementDigest covers the signed bundle (sans inclusion). A field
// mutation must move the registered digest — otherwise the ledger
// vouches a statement the verifier never saw.
func TestStatementDigest_FieldMutationChangesDigest(t *testing.T) {
	base := mutationBundle().StatementDigest()
	mutations := []struct {
		name string
		mut  func(*Bundle)
	}{
		{"lineage_id", func(b *Bundle) { b.LineageID = "lin_bbb" }},
		{"stage", func(b *Bundle) { b.Stage = StageApproval }},
		{"receipt_member", func(b *Bundle) { b.Receipt.Resource = resShellXX }},
		{"sig", func(b *Bundle) { b.Sig = "lin_v1:" + "ff" }},
	}
	for _, m := range mutations {
		b := mutationBundle()
		m.mut(b)
		if b.StatementDigest() == base {
			t.Errorf("%s: statement digest unchanged by mutation", m.name)
		}
	}
	// Inclusion is deliberately outside the statement digest — the
	// receipt is minted over it, not under it.
	b := mutationBundle()
	b.Inclusion = &Inclusion{LedgerDomain: "x", Seq: 9, Parent: "p", Digest: "d", KeyID: "k", Sig: "s"}
	if b.StatementDigest() != mutationBundle().StatementDigest() {
		t.Error("inclusion must not affect the statement digest")
	}
}
