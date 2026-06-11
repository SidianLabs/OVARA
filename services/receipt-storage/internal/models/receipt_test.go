package models

import (
	"testing"
	"time"
)

func TestReceipt_Digest_Deterministic(t *testing.T) {
	r1 := &Receipt{
		ID:             "rcpt-001",
		DecisionID:     "dec-001",
		GatewayID:      "gw-001",
		OrganizationID: "org-001",
		ActionType:     "shell",
		Resource:       "shell:ls",
		Decision:       "allow",
		AgentID:        "agent-001",
		TrustScore:     0.95,
		IssuedAt:       time.Date(2026, 6, 11, 10, 0, 0, 0, time.UTC),
	}
	r2 := &Receipt{
		ID:             "rcpt-001",
		DecisionID:     "dec-001",
		GatewayID:      "gw-001",
		OrganizationID: "org-001",
		ActionType:     "shell",
		Resource:       "shell:ls",
		Decision:       "allow",
		AgentID:        "agent-001",
		TrustScore:     0.95,
		IssuedAt:       time.Date(2026, 6, 11, 10, 0, 0, 0, time.UTC),
	}
	d1 := r1.Digest()
	d2 := r2.Digest()
	if d1 != d2 {
		t.Errorf("digest should be deterministic: %s != %s", d1, d2)
	}
}

func TestReceipt_Digest_Format(t *testing.T) {
	r := &Receipt{
		ID:             "rcpt-001",
		DecisionID:     "dec-001",
		GatewayID:      "gw-001",
		OrganizationID: "org-001",
		ActionType:     "shell",
		Resource:       "shell:ls",
		Decision:       "allow",
		AgentID:        "agent-001",
		TrustScore:     0.95,
		IssuedAt:       time.Date(2026, 6, 11, 10, 0, 0, 0, time.UTC),
	}
	digest := r.Digest()
	if len(digest) != 64 {
		t.Errorf("expected 64-char hex digest, got %d chars: %s", len(digest), digest)
	}
}

func TestReceipt_Digest_DifferentInputs(t *testing.T) {
	base := &Receipt{
		ID:             "rcpt-001",
		DecisionID:     "dec-001",
		GatewayID:      "gw-001",
		OrganizationID: "org-001",
		ActionType:     "shell",
		Resource:       "shell:ls",
		Decision:       "allow",
		AgentID:        "agent-001",
		TrustScore:     0.95,
		IssuedAt:       time.Date(2026, 6, 11, 10, 0, 0, 0, time.UTC),
	}

	digest1 := base.Digest()

	modified := *base
	modified.Resource = "shell:pwd"
	digest2 := modified.Digest()

	if digest1 == digest2 {
		t.Errorf("different inputs should produce different digests")
	}
}

func TestReceipt_Digest_EmptyAgentID(t *testing.T) {
	r := &Receipt{
		ID:             "rcpt-001",
		DecisionID:     "dec-001",
		GatewayID:      "gw-001",
		OrganizationID: "org-001",
		ActionType:     "shell",
		Resource:       "shell:ls",
		Decision:       "allow",
		AgentID:        "",
		TrustScore:     0.95,
		IssuedAt:       time.Date(2026, 6, 11, 10, 0, 0, 0, time.UTC),
	}
	digest := r.Digest()
	if len(digest) != 64 {
		t.Errorf("expected 64-char hex digest, got %d", len(digest))
	}
}

func TestReceipt_AllFields(t *testing.T) {
	now := time.Now().UTC()
	r := &Receipt{
		ID:             "rcpt-001",
		DecisionID:     "dec-001",
		GatewayID:      "gw-001",
		OrganizationID: "org-001",
		ActionType:     "shell",
		Resource:       "shell:ls",
		Decision:       "allow",
		AgentID:        "agent-001",
		TrustScore:     0.95,
		Payload:        "test payload",
		Signature:      "sig_v1:abc123",
		IssuedAt:       now,
		ArchivedAt:     now,
	}
	if r.ID != "rcpt-001" {
		t.Errorf("expected rcpt-001, got %s", r.ID)
	}
	if r.Decision != "allow" {
		t.Errorf("expected allow, got %s", r.Decision)
	}
	if r.Payload != "test payload" {
		t.Errorf("expected test payload, got %s", r.Payload)
	}
}

func TestVerificationResult_Fields(t *testing.T) {
	vr := &VerificationResult{
		Valid:         true,
		ReceiptDigest: "abc123def456",
		Errors:        []string{},
	}
	if !vr.Valid {
		t.Errorf("expected valid=true")
	}
	if vr.ReceiptDigest != "abc123def456" {
		t.Errorf("expected digest, got %s", vr.ReceiptDigest)
	}
}

func TestVerificationResult_WithErrors(t *testing.T) {
	vr := &VerificationResult{
		Valid:         false,
		ReceiptDigest: "abc123def456",
		Errors:        []string{"signature too short", "invalid format"},
	}
	if vr.Valid {
		t.Errorf("expected valid=false")
	}
	if len(vr.Errors) != 2 {
		t.Errorf("expected 2 errors, got %d", len(vr.Errors))
	}
}

func TestReceipt_Digest_LargeTrustScore(t *testing.T) {
	r := &Receipt{
		ID:             "rcpt-001",
		DecisionID:     "dec-001",
		GatewayID:      "gw-001",
		OrganizationID: "org-001",
		ActionType:     "shell",
		Resource:       "shell:ls",
		Decision:       "allow",
		AgentID:        "agent-001",
		TrustScore:     0.999,
		IssuedAt:       time.Date(2026, 6, 11, 10, 0, 0, 0, time.UTC),
	}
	digest := r.Digest()
	if len(digest) != 64 {
		t.Errorf("expected 64-char hex digest, got %d", len(digest))
	}
}

func TestReceipt_Digest_ZeroTrustScore(t *testing.T) {
	r := &Receipt{
		ID:             "rcpt-001",
		DecisionID:     "dec-001",
		GatewayID:      "gw-001",
		OrganizationID: "org-001",
		ActionType:     "shell",
		Resource:       "shell:ls",
		Decision:       "deny",
		AgentID:        "agent-001",
		TrustScore:     0.0,
		IssuedAt:       time.Date(2026, 6, 11, 10, 0, 0, 0, time.UTC),
	}
	digest := r.Digest()
	if len(digest) != 64 {
		t.Errorf("expected 64-char hex digest, got %d", len(digest))
	}
}

func TestReceipt_Digest_DifferentTimestamps(t *testing.T) {
	r1 := &Receipt{
		ID:             "rcpt-001",
		DecisionID:     "dec-001",
		GatewayID:      "gw-001",
		OrganizationID: "org-001",
		ActionType:     "shell",
		Resource:       "shell:ls",
		Decision:       "allow",
		AgentID:        "agent-001",
		TrustScore:     0.95,
		IssuedAt:       time.Date(2026, 6, 11, 10, 0, 0, 0, time.UTC),
	}
	r2 := &Receipt{
		ID:             "rcpt-001",
		DecisionID:     "dec-001",
		GatewayID:      "gw-001",
		OrganizationID: "org-001",
		ActionType:     "shell",
		Resource:       "shell:ls",
		Decision:       "allow",
		AgentID:        "agent-001",
		TrustScore:     0.95,
		IssuedAt:       time.Date(2026, 6, 11, 10, 0, 1, 0, time.UTC),
	}
	d1 := r1.Digest()
	d2 := r2.Digest()
	if d1 == d2 {
		t.Errorf("different timestamps should produce different digests")
	}
}