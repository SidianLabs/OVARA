// Preimage-binding tests for the HMAC receipt signer and the exported
// action digest: pipe-joined framing is field-boundary ambiguous, so
// any string carrying '|' could be split into a colliding field pair.
// The lp-framed sig_v2 preimage pins this shut.
package receipt

import (
	"testing"
	"time"

	"ovara.runtime.gateway/internal/models"
)

func pmsb(s string) string {
	if s == "" {
		return "x"
	}
	b := []byte(s)
	b[0] ^= 0x01
	if b[0] == 0 || b[0] == '|' {
		b[0] = 'z'
	}
	return string(b)
}

func ptestReceipt() *models.Receipt {
	return &models.Receipt{
		ReceiptID:     "rcpt_1",
		DecisionID:    "dec_1",
		ActionDigest:  "abc123",
		ActionType:    "shell",
		Resource:      "shell:ls",
		AgentID:       "agt_a",
		Decision:      "escalated",
		PolicyVersion: "p1",
		TrustScore:    0.4,
		IssuedAt:      time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC),
	}
}

// Every field the signature covers must move the preimage — same-length
// mutations included.
func TestPreimage_CanonicalPayloadCommitsEveryField(t *testing.T) {
	s := NewSigner([]byte("k"))
	base := s.canonicalPayload(ptestReceipt())
	cases := map[string]func(*models.Receipt){
		"receipt_id":     func(r *models.Receipt) { r.ReceiptID = pmsb(r.ReceiptID) },
		"decision_id":    func(r *models.Receipt) { r.DecisionID = pmsb(r.DecisionID) },
		"action_digest":  func(r *models.Receipt) { r.ActionDigest = pmsb(r.ActionDigest) },
		"action_type":    func(r *models.Receipt) { r.ActionType = pmsb(r.ActionType) },
		"resource":       func(r *models.Receipt) { r.Resource = pmsb(r.Resource) },
		"agent_id":       func(r *models.Receipt) { r.AgentID = pmsb(r.AgentID) },
		"decision":       func(r *models.Receipt) { r.Decision = pmsb(r.Decision) },
		"policy_version": func(r *models.Receipt) { r.PolicyVersion = pmsb(r.PolicyVersion) },
		"trust_score":    func(r *models.Receipt) { r.TrustScore = 0.41 },
		"issued_at":      func(r *models.Receipt) { r.IssuedAt = r.IssuedAt.Add(time.Second) },
	}
	for name, mut := range cases {
		r := ptestReceipt()
		mut(r)
		if string(s.canonicalPayload(r)) == string(base) {
			t.Fatalf("canonicalPayload blind to %s", name)
		}
	}
}

// The regression the sig_v1 scheme carried: "|" inside a field made
// "a|b"‖"c" identical to "a"‖"b|c". Post-fix these are two distinct
// receipts AND two distinct signatures.
func TestPreimage_CanonicalPayload_NoPipeSlide(t *testing.T) {
	s := NewSigner([]byte("k"))
	a := ptestReceipt()
	a.ActionType, a.Resource = "a|b", "c"
	b := ptestReceipt()
	b.ActionType, b.Resource = "a", "b|c"
	if string(s.canonicalPayload(a)) == string(s.canonicalPayload(b)) {
		t.Fatal("pipe-bearing fields collide — boundary ambiguity")
	}
	sa, sb := s.Sign(a), s.Sign(b)
	if sa == sb {
		t.Fatal("distinct receipts produced identical sig")
	}
	a.Signature, b.Signature = sa, sb
	if !s.Verify(a) || !s.Verify(b) {
		t.Fatal("sig_v2 round-trip failed")
	}
}

// Same class on the exported digest: "%s|%s|%d" let ("a|b","c",t) and
// ("a","b|c",t) collide.
func TestPreimage_ComputeActionDigest_NoPipeSlide(t *testing.T) {
	ts := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)
	if ComputeActionDigest("a|b", "c", ts) == ComputeActionDigest("a", "b|c", ts) {
		t.Fatal("ComputeActionDigest: pipe slide produced identical digest")
	}
	if ComputeActionDigest("shell", "shell:ls", ts) ==
		ComputeActionDigest("shell", "shell:ls", ts.Add(time.Second)) {
		t.Fatal("ComputeActionDigest blind to issued_at")
	}
}
