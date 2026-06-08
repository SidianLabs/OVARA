package receipt

import (
	"testing"
	"time"

	"ovara.runtime.gateway/internal/models"
)

func TestSigner_Sign_Roundtrips(t *testing.T) {
	signer := NewSigner([]byte("test-secret-key"))

	r := &models.Receipt{
		ReceiptID:     "rec-001",
		DecisionID:    "dec-001",
		ActionDigest:  "abc123",
		ActionType:    "shell",
		Resource:      "repo:example/web",
		AgentID:       "agent-1",
		Decision:      "allowed",
		PolicyVersion: "v1-local",
		TrustScore:    0.95,
		IssuedAt:      time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC),
	}

	sig := signer.Sign(r)
	r.Signature = sig

	if !signer.Verify(r) {
		t.Fatal("Verify returned false for valid signature")
	}
}

func TestSigner_Verify_RejectsTamperedReceipt(t *testing.T) {
	signer := NewSigner([]byte("test-secret-key"))

	r := &models.Receipt{
		ReceiptID:     "rec-002",
		DecisionID:    "dec-002",
		ActionDigest:  "abc123",
		ActionType:    "shell",
		Resource:      "repo:example/web",
		AgentID:       "agent-1",
		Decision:      "allowed",
		PolicyVersion: "v1-local",
		TrustScore:    0.95,
		IssuedAt:      time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC),
	}

	sig := signer.Sign(r)
	r.Signature = sig

	r.Decision = "denied"

	if signer.Verify(r) {
		t.Fatal("Verify returned true for tampered receipt")
	}
}

func TestSigner_Verify_NilReceipt(t *testing.T) {
	signer := NewSigner([]byte("test-secret-key"))
	if signer.Verify(nil) {
		t.Fatal("Verify returned true for nil receipt")
	}
}

func TestSigner_DifferentKeys_ProduceDifferentSignatures(t *testing.T) {
	signerA := NewSigner([]byte("key-a"))
	signerB := NewSigner([]byte("key-b"))

	r := &models.Receipt{
		ReceiptID:     "rec-003",
		DecisionID:    "dec-003",
		ActionDigest:  "abc123",
		ActionType:    "shell",
		Resource:      "repo:example/web",
		AgentID:       "agent-1",
		Decision:      "allowed",
		PolicyVersion: "v1-local",
		TrustScore:    0.95,
		IssuedAt:      time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC),
	}

	sigA := signerA.Sign(r)
	sigB := signerB.Sign(r)

	if sigA == sigB {
		t.Fatal("different keys produced identical signatures")
	}
}

func TestSigner_SamePayload_ProducesConsistentSignature(t *testing.T) {
	signer := NewSigner([]byte("test-secret-key"))

	r := &models.Receipt{
		ReceiptID:     "rec-004",
		DecisionID:    "dec-004",
		ActionDigest:  "abc123",
		ActionType:    "shell",
		Resource:      "repo:example/web",
		AgentID:       "agent-1",
		Decision:      "allowed",
		PolicyVersion: "v1-local",
		TrustScore:    0.95,
		IssuedAt:      time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC),
	}

	sig1 := signer.Sign(r)
	sig2 := signer.Sign(r)

	if sig1 != sig2 {
		t.Fatal("same payload produced different signatures")
	}
}

func TestComputeActionDigest_DifferentInputs_ProduceDifferentDigests(t *testing.T) {
	d1 := ComputeActionDigest("shell", "repo:a", time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC))
	d2 := ComputeActionDigest("shell", "repo:b", time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC))

	if d1 == d2 {
		t.Fatal("different resources produced identical digests")
	}
}

func TestComputeActionDigest_Deterministic(t *testing.T) {
	ts := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)
	d1 := ComputeActionDigest("shell", "repo:example", ts)
	d2 := ComputeActionDigest("shell", "repo:example", ts)

	if d1 != d2 {
		t.Fatal("same input produced different digests")
	}
}

func TestSigner_SignatureFormat(t *testing.T) {
	signer := NewSigner([]byte("test-secret-key"))

	r := &models.Receipt{
		ReceiptID:     "rec-005",
		DecisionID:    "dec-005",
		ActionDigest:  "abc123",
		ActionType:    "shell",
		Resource:      "repo:example/web",
		AgentID:       "agent-1",
		Decision:      "allowed",
		PolicyVersion: "v1-local",
		TrustScore:    0.95,
		IssuedAt:      time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC),
	}

	sig := signer.Sign(r)

	if len(sig) < 7 || sig[:7] != "sig_v1:" {
		t.Fatalf("signature does not start with sig_v1: prefix: %s", sig)
	}
}

func TestSigner_emptyKey(t *testing.T) {
	signer := NewSigner([]byte(""))

	r := &models.Receipt{
		ReceiptID:     "rec-006",
		DecisionID:    "dec-006",
		ActionDigest:  "abc123",
		ActionType:    "shell",
		Resource:      "repo:example/web",
		AgentID:       "agent-1",
		Decision:      "allowed",
		PolicyVersion: "v1-local",
		TrustScore:    0.95,
		IssuedAt:      time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC),
	}

	sig := signer.Sign(r)
	r.Signature = sig

	if !signer.Verify(r) {
		t.Fatal("Verify returned false for receipt signed with empty key")
	}
}
