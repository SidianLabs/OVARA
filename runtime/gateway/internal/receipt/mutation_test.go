package receipt

import (
	"testing"
	"time"

	"ovara.runtime.gateway/internal/models"
)

// Canonical-preimage mutation property: every field the edsig_v1
// signature covers must move the preimage bytes — including a
// same-length substitution, which a length-only framer cannot see.
// Complements TestTamper_EverySignedField (which asserts verification
// failure); this asserts it at the byte layer.
func TestSignedPayload_FieldMutationChangesPreimage(t *testing.T) {
	base := SignedPayload(sampleReceipt())
	mutations := []struct {
		name string
		mut  func(*models.Receipt)
	}{
		{"receipt_id", func(r *models.Receipt) { r.ReceiptID = "rcpt_2" }},
		{"decision_id", func(r *models.Receipt) { r.DecisionID = "dec_2" }},
		{"action_digest", func(r *models.Receipt) { r.ActionDigest = "sha256:abce" }},
		{"action_type", func(r *models.Receipt) { r.ActionType = "fetch" }},
		{"resource", func(r *models.Receipt) { r.Resource = "post" }},
		{"agent_id", func(r *models.Receipt) { r.AgentID = "ag_y" }},
		{"lease_id", func(r *models.Receipt) { r.CapabilityLeaseID = "lse_2" }},
		{"decision", func(r *models.Receipt) { r.Decision = "denyy" }},
		{"policy_version", func(r *models.Receipt) { r.PolicyVersion = "v2" }},
		{"trust_score", func(r *models.Receipt) { r.TrustScore = 0.74 }},
		{"trust_level", func(r *models.Receipt) { r.TrustLevel = models.TrustLevelLow }},
		{"anomaly_code", func(r *models.Receipt) { r.AnomalySignals[0].Code = "curst" }},
		{"anomaly_pattern", func(r *models.Receipt) { r.AnomalySignals[0].Pattern = "q" }},
		{"anomaly_severity", func(r *models.Receipt) { r.AnomalySignals[0].Severity = "hig" }},
		{"anomaly_count", func(r *models.Receipt) {
			r.AnomalySignals = append(r.AnomalySignals, models.AnomalySignal{Code: "x", Pattern: "y", Severity: "z"})
		}},
		{"shield_active", func(r *models.Receipt) { r.ShieldActive = false }},
		{"restricted", func(r *models.Receipt) { r.Restricted = true }},
		{"risk_count", func(r *models.Receipt) { r.RiskCount = 3 }},
		{"approval_id", func(r *models.Receipt) { r.ApprovalID = "ap_2" }},
		{"approval_decision", func(r *models.Receipt) { r.ApprovalDecision = "approvde" }},
		{"trust_epoch", func(r *models.Receipt) { r.TrustEpoch = 8 }},
		{"issued_at", func(r *models.Receipt) { r.IssuedAt = r.IssuedAt.Add(time.Nanosecond) }},
		{"signature_hmac", func(r *models.Receipt) { r.Signature = "sig_v1:deadbeee" }},
	}
	for _, m := range mutations {
		r := sampleReceipt()
		m.mut(r)
		if string(SignedPayload(r)) == string(base) {
			t.Errorf("%s: mutation produced identical signed payload", m.name)
		}
	}
}

// The legacy HMAC preimage (sig_v1) is the weaker pipe format — the
// mutation property still holds field-for-field.
func TestCanonicalPayload_FieldMutationChangesString(t *testing.T) {
	s := NewSigner([]byte("test-signing-key"))
	base := s.canonicalPayload(sampleReceipt())
	mutations := []struct {
		name string
		mut  func(*models.Receipt)
	}{
		{"receipt_id", func(r *models.Receipt) { r.ReceiptID = "rcpt_2" }},
		{"decision_id", func(r *models.Receipt) { r.DecisionID = "dec_2" }},
		{"action_digest", func(r *models.Receipt) { r.ActionDigest = "sha256:abce" }},
		{"action_type", func(r *models.Receipt) { r.ActionType = "fetch" }},
		{"resource", func(r *models.Receipt) { r.Resource = "post" }},
		{"agent_id", func(r *models.Receipt) { r.AgentID = "ag_y" }},
		{"decision", func(r *models.Receipt) { r.Decision = "denyy" }},
		{"policy_version", func(r *models.Receipt) { r.PolicyVersion = "v2" }},
		{"trust_score", func(r *models.Receipt) { r.TrustScore = 0.74 }},
		{"issued_at", func(r *models.Receipt) { r.IssuedAt = r.IssuedAt.Add(time.Second) }},
	}
	for _, m := range mutations {
		r := sampleReceipt()
		m.mut(r)
		if s.canonicalPayload(r) == base {
			t.Errorf("%s: mutation produced identical canonical payload", m.name)
		}
	}
}

func TestComputeActionDigest_FieldMutationChangesDigest(t *testing.T) {
	at := time.Unix(1700000000, 0).UTC()
	base := ComputeActionDigest("shell", "shell:ls", at)
	if ComputeActionDigest("fetch", "shell:ls", at) == base {
		t.Error("action type mutation invisible to digest")
	}
	if ComputeActionDigest("shell", "shell:xx", at) == base {
		t.Error("same-length resource mutation invisible to digest")
	}
	if ComputeActionDigest("shell", "shell:ls", at.Add(time.Second)) == base {
		t.Error("issued_at mutation invisible to digest")
	}
}

// signatureVersion is the scheme discriminator on legacy HMAC sigs —
// it must parse "sig_v1:..." and reject malformed forms so a future
// scheme can never be silently misrouted into v1 verification.
func TestSignatureVersion_SchemeTagParsing(t *testing.T) {
	for sig, want := range map[string]string{
		"sig_v1:abc123": "sig_v1",
		"sig_v9:x:y":    "sig_v9",
		"abc123":        "",
		":abc123":       "", // no scheme before the colon
		"":              "",
	} {
		if got := signatureVersion(sig); got != want {
			t.Errorf("signatureVersion(%q) = %q, want %q", sig, got, want)
		}
	}
}
