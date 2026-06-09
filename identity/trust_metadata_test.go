package identity

import (
	"testing"
	"time"
)

func TestSignTrustMetadata_Succeeds(t *testing.T) {
	id, priv, err := NewAgentIdentity("ovara", "agent-1", "owner-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	tm, err := SignTrustMetadata(id, priv, "agent-1", "production", "v1.0.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tm.SubjectID != "agent-1" {
		t.Errorf("subject_id = %s, want agent-1", tm.SubjectID)
	}
	if tm.Environment != "production" {
		t.Errorf("environment = %s, want production", tm.Environment)
	}
	if tm.AttestationStatus != AttestationVerified {
		t.Errorf("attestation = %v, want verified", tm.AttestationStatus)
	}
	if len(tm.Signature) == 0 {
		t.Error("signature is empty")
	}
	if tm.IssuedBy != id.ID {
		t.Errorf("issued_by = %s, want %s", tm.IssuedBy, id.ID)
	}
}

func TestSignTrustMetadata_RequiresActiveIssuer(t *testing.T) {
	id, priv, err := NewAgentIdentity("ovara", "agent-1", "owner-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	id.Revoke()

	_, err = SignTrustMetadata(id, priv, "agent-1", "production", "v1.0.0")
	if err == nil {
		t.Error("expected error for revoked issuer")
	}
}

func TestSignTrustMetadata_RequiresSubjectID(t *testing.T) {
	id, priv, _ := NewAgentIdentity("ovara", "agent-1", "owner-1")
	_, err := SignTrustMetadata(id, priv, "", "production", "v1.0.0")
	if err == nil {
		t.Error("expected error for empty subject_id")
	}
}

func TestSignTrustMetadata_RequiresEnvironment(t *testing.T) {
	id, priv, _ := NewAgentIdentity("ovara", "agent-1", "owner-1")
	_, err := SignTrustMetadata(id, priv, "agent-1", "", "v1.0.0")
	if err == nil {
		t.Error("expected error for empty environment")
	}
}

func TestTrustMetadata_Verify(t *testing.T) {
	id, priv, _ := NewAgentIdentity("ovara", "agent-1", "owner-1")
	tm, _ := SignTrustMetadata(id, priv, "agent-1", "production", "v1.0.0")

	if !tm.Verify(id.PublicKey) {
		t.Error("Verify returned false for valid signature")
	}
	if tm.Verify(nil) {
		t.Error("Verify returned true for nil key")
	}
	if tm.Verify([]byte("short")) {
		t.Error("Verify returned true for invalid key length")
	}
}

func TestTrustMetadata_Digest(t *testing.T) {
	id, priv, _ := NewAgentIdentity("ovara", "agent-1", "owner-1")
	tm, _ := SignTrustMetadata(id, priv, "agent-1", "production", "v1.0.0")

	d1 := tm.Digest()
	d2 := tm.Digest()
	if d1 != d2 {
		t.Error("digest is not deterministic")
	}
}

func TestTrustMetadata_IsExpired(t *testing.T) {
	id, priv, _ := NewAgentIdentity("ovara", "agent-1", "owner-1")
	tm, _ := SignTrustMetadata(id, priv, "agent-1", "production", "v1.0.0")

	if tm.IsExpired(5 * time.Minute) {
		t.Error("fresh metadata should not be expired")
	}

	tm.EvaluationTime = time.Now().UTC().Add(-10 * time.Minute)
	if !tm.IsExpired(5 * time.Minute) {
		t.Error("metadata 10 min old should be expired with 5 min maxAge")
	}
}

func TestTrustMetadata_Validate(t *testing.T) {
	tm := &TrustMetadata{}
	errs := tm.Validate()
	if len(errs) != 3 {
		t.Errorf("expected 3 validation errors, got %d: %v", len(errs), errs)
	}

	id, priv, _ := NewAgentIdentity("ovara", "agent-1", "owner-1")
	tm, _ = SignTrustMetadata(id, priv, "agent-1", "production", "v1.0.0")
	if len(tm.Validate()) != 0 {
		t.Errorf("expected no errors, got: %v", tm.Validate())
	}
}

func TestTrustMetadata_NilIssuer(t *testing.T) {
	_, err := SignTrustMetadata(nil, nil, "agent-1", "production", "v1.0.0")
	if err == nil {
		t.Error("expected error for nil issuer")
	}
}
