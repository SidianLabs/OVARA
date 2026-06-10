package crypto

import (
	"crypto/ed25519"
	"testing"
)

func TestNewAgentIdentity_CreatesActiveIdentity(t *testing.T) {
	id, priv, err := NewAgentIdentity("ovara", "agent-1", "owner-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id.ID == "" {
		t.Error("id is empty")
	}
	if id.Lifecycle != LifecycleActive {
		t.Errorf("lifecycle = %v, want active", id.Lifecycle)
	}
	if !id.IsActive() {
		t.Error("IsActive returned false for newly created identity")
	}
	if len(id.PublicKey) == 0 {
		t.Error("no public key generated")
	}
	if len(priv) == 0 {
		t.Error("no private key returned")
	}
}

func TestNewAgentIdentity_RequiresIssuer(t *testing.T) {
	_, _, err := NewAgentIdentity("", "agent-1", "owner-1")
	if err == nil {
		t.Error("expected error for missing issuer")
	}
}

func TestNewAgentIdentity_RequiresSubjectID(t *testing.T) {
	_, _, err := NewAgentIdentity("ovara", "", "owner-1")
	if err == nil {
		t.Error("expected error for missing subject_id")
	}
}

func TestAgentIdentity_DigestIsDeterministic(t *testing.T) {
	id, _, err := NewAgentIdentity("ovara", "agent-1", "owner-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	d1 := id.Digest()
	d2 := id.Digest()
	if d1 != d2 {
		t.Error("digest is not deterministic")
	}
}

func TestAgentIdentity_DigestChangesOnSuspension(t *testing.T) {
	id, _, err := NewAgentIdentity("ovara", "agent-1", "owner-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	before := id.Digest()
	id.Suspend()
	after := id.Digest()
	if before == after {
		t.Error("digest should change when lifecycle changes")
	}
	if id.IsActive() {
		t.Error("IsActive returned true after suspension")
	}
}

func TestAgentIdentity_Revoke(t *testing.T) {
	id, _, err := NewAgentIdentity("ovara", "agent-1", "owner-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	id.Revoke()
	if id.Lifecycle != LifecycleRevoked {
		t.Errorf("lifecycle = %v, want revoked", id.Lifecycle)
	}
	if id.IsActive() {
		t.Error("IsActive returned true after revocation")
	}
}

func TestAgentIdentity_VerifyKey(t *testing.T) {
	id, _, err := NewAgentIdentity("ovara", "agent-1", "owner-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !id.Verify(id.PublicKey) {
		t.Error("Verify returned false for correct public key")
	}
	if id.Verify([]byte("wrong-key")) {
		t.Error("Verify returned true for wrong key")
	}
	if id.Verify(nil) {
		t.Error("Verify returned true for nil key")
	}
}

func TestAgentIdentity_Validate(t *testing.T) {
	id := &AgentIdentity{}
	errs := id.Validate()
	if len(errs) != 3 {
		t.Errorf("expected 3 validation errors, got %d: %v", len(errs), errs)
	}

	id, priv, err := NewAgentIdentity("ovara", "agent-1", "owner-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_ = priv
	if len(id.Validate()) != 0 {
		t.Errorf("expected no errors for valid identity, got: %v", id.Validate())
	}
}

func TestAgentIdentity_PrivateKeySignsAndVerifies(t *testing.T) {
	id, priv, err := NewAgentIdentity("ovara", "agent-1", "owner-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	message := []byte("capability lease payload")
	sig := ed25519.Sign(priv, message)
	if !ed25519.Verify(id.PublicKey, message, sig) {
		t.Error("ed25519 signature verification failed")
	}

	sig[0] ^= 0x01
	if ed25519.Verify(id.PublicKey, message, sig) {
		t.Error("ed25519 verification should fail for tampered signature")
	}
}
