package identity

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"

	"ovara.runtime.gateway/internal/models"
)

func TestValidator_ValidateAgentIdentity_Valid(t *testing.T) {
	v := NewValidator()
	identity := &models.AgentIdentity{
		Issuer:    "ovara",
		SubjectID: "agent-001",
	}

	result := v.ValidateAgentIdentity(identity)
	if !result.Valid {
		t.Errorf("expected valid, got %v: %v", result.Valid, result.Reasons)
	}
}

func TestValidator_ValidateAgentIdentity_Missing(t *testing.T) {
	v := NewValidator()

	result := v.ValidateAgentIdentity(nil)
	if result.Valid {
		t.Error("expected invalid for nil identity")
	}
	if len(result.Reasons) != 1 || result.Reasons[0] != "agent_identity is required" {
		t.Errorf("unexpected reasons: %v", result.Reasons)
	}
}

func TestValidator_ValidateAgentIdentity_MissingIssuer(t *testing.T) {
	v := NewValidator()
	identity := &models.AgentIdentity{
		SubjectID: "agent-001",
	}

	result := v.ValidateAgentIdentity(identity)
	if result.Valid {
		t.Error("expected invalid for missing issuer")
	}
}

func TestValidator_ValidateAgentIdentity_MissingSubjectID(t *testing.T) {
	v := NewValidator()
	identity := &models.AgentIdentity{
		Issuer: "ovara",
	}

	result := v.ValidateAgentIdentity(identity)
	if result.Valid {
		t.Error("expected invalid for missing subject_id")
	}
}

func TestValidator_ValidateCapabilityLease_Valid(t *testing.T) {
	v := NewValidator()
	lease := &models.CapabilityLease{
		LeaseID:        "cap_123",
		Issuer:         "ovara",
		Subject:        "agent-001",
		AllowedActions: []string{"shell", "git.push"},
		ResourceScope:   "repo:acme/api",
		Expiry:         time.Now().Add(1 * time.Hour),
		DelegationDepth: 1,
	}

	result := v.ValidateCapabilityLease(lease)
	if !result.Valid {
		t.Errorf("expected valid, got %v: %v", result.Valid, result.Reasons)
	}
}

func TestValidator_ValidateCapabilityLease_Missing(t *testing.T) {
	v := NewValidator()

	result := v.ValidateCapabilityLease(nil)
	if result.Valid {
		t.Error("expected invalid for nil lease")
	}
}

func TestValidator_ValidateCapabilityLease_Expired(t *testing.T) {
	v := NewValidator()
	lease := &models.CapabilityLease{
		LeaseID:        "cap_123",
		Issuer:         "ovara",
		Subject:        "agent-001",
		AllowedActions: []string{"shell"},
		ResourceScope:   "*",
		Expiry:         time.Now().Add(-1 * time.Hour),
		DelegationDepth: 1,
	}

	result := v.ValidateCapabilityLease(lease)
	if result.Valid {
		t.Error("expected invalid for expired lease")
	}
}

func TestValidator_ValidateCapabilityLease_EmptyActions(t *testing.T) {
	v := NewValidator()
	lease := &models.CapabilityLease{
		LeaseID:        "cap_123",
		Issuer:         "ovara",
		Subject:        "agent-001",
		AllowedActions: []string{},
		ResourceScope:   "*",
		Expiry:         time.Now().Add(1 * time.Hour),
		DelegationDepth: 1,
	}

	result := v.ValidateCapabilityLease(lease)
	if result.Valid {
		t.Error("expected invalid for empty allowed_actions")
	}
}

func TestValidator_ValidateCapabilityLease_NegativeDelegationDepth(t *testing.T) {
	v := NewValidator()
	lease := &models.CapabilityLease{
		LeaseID:        "cap_123",
		Issuer:         "ovara",
		Subject:        "agent-001",
		AllowedActions: []string{"shell"},
		ResourceScope:   "*",
		Expiry:         time.Now().Add(1 * time.Hour),
		DelegationDepth: -1,
	}

	result := v.ValidateCapabilityLease(lease)
	if result.Valid {
		t.Error("expected invalid for negative delegation_depth")
	}
}

func TestValidator_ValidateCapabilityLeaseScope_Allowed(t *testing.T) {
	v := NewValidator()
	lease := &models.CapabilityLease{
		LeaseID:        "cap_123",
		AllowedActions: []string{"shell", "git.push"},
		ResourceScope:   "repo:acme/api",
		Expiry:         time.Now().Add(1 * time.Hour),
	}

	result := v.ValidateCapabilityLeaseScope(lease, "shell", "repo:acme/api")
	if !result.Valid {
		t.Errorf("expected valid, got %v: %v", result.Valid, result.Reasons)
	}
}

func TestValidator_ValidateCapabilityLeaseScope_ActionNotAllowed(t *testing.T) {
	v := NewValidator()
	lease := &models.CapabilityLease{
		LeaseID:        "cap_123",
		AllowedActions: []string{"shell"},
		ResourceScope:   "repo:acme/api",
		Expiry:         time.Now().Add(1 * time.Hour),
	}

	result := v.ValidateCapabilityLeaseScope(lease, "git.push", "repo:acme/api")
	if result.Valid {
		t.Error("expected invalid for action not in allowed_actions")
	}
}

func TestValidator_ValidateCapabilityLeaseScope_ResourceMismatch(t *testing.T) {
	v := NewValidator()
	lease := &models.CapabilityLease{
		LeaseID:        "cap_123",
		AllowedActions: []string{"shell"},
		ResourceScope:   "repo:acme/api",
		Expiry:         time.Now().Add(1 * time.Hour),
	}

	result := v.ValidateCapabilityLeaseScope(lease, "shell", "repo:other/api")
	if result.Valid {
		t.Error("expected invalid for resource mismatch")
	}
}

func TestValidator_ValidateCapabilityLeaseScope_WildcardScope(t *testing.T) {
	v := NewValidator()
	lease := &models.CapabilityLease{
		LeaseID:        "cap_123",
		AllowedActions: []string{"shell"},
		ResourceScope:   "*",
		Expiry:         time.Now().Add(1 * time.Hour),
	}

	result := v.ValidateCapabilityLeaseScope(lease, "shell", "repo:anything")
	if !result.Valid {
		t.Errorf("expected valid for wildcard scope, got %v: %v", result.Valid, result.Reasons)
	}
}

func TestValidator_ValidateDelegationChain_Empty(t *testing.T) {
	v := NewValidator()

	result := v.ValidateDelegationChain(&models.DelegationChain{})
	if result.Valid {
		t.Error("expected invalid for empty delegation chain")
	}
}

func TestValidator_ValidateDelegationChain_Valid(t *testing.T) {
	v := NewValidator()
	chain := &models.DelegationChain{
		Authorities: []models.Authority{
			{Issuer: "root", SubjectID: "agent-001"},
		},
		Depth: 1,
	}

	result := v.ValidateDelegationChain(chain)
	if !result.Valid {
		t.Errorf("expected valid, got %v: %v", result.Valid, result.Reasons)
	}
}

func TestValidator_ValidateDelegationChain_Nil(t *testing.T) {
	v := NewValidator()

	result := v.ValidateDelegationChain(nil)
	if !result.Valid {
		t.Error("expected valid for nil delegation chain")
	}
}

func TestValidationResult_Add(t *testing.T) {
	result := &ValidationResult{Valid: true}
	result.Add("reason 1")
	result.Add("reason 2")

	if result.Valid {
		t.Error("expected valid to be false after Add")
	}
	if len(result.Reasons) != 2 {
		t.Errorf("len(reasons) = %d, want 2", len(result.Reasons))
	}
}

func TestValidator_ValidateAll_MissingBoth(t *testing.T) {
	v := NewValidator()
	req := &models.ActionRequest{
		ActionType:  models.ActionTypeShell,
		Resource:    "shell:echo",
		Environment: models.EnvironmentLocal,
	}

	result := v.ValidateAll(req)
	if result.Valid {
		t.Error("expected invalid when both identity and lease are missing")
	}
}

func TestValidator_ValidateAll_Valid(t *testing.T) {
	v := NewValidator()
	req := &models.ActionRequest{
		ActionType:  models.ActionTypeShell,
		Resource:    "shell:echo",
		Environment: models.EnvironmentLocal,
		AgentIdentity: &models.AgentIdentity{
			Issuer:    "ovara",
			SubjectID: "agent-001",
		},
		CapabilityLease: &models.CapabilityLease{
			LeaseID:        "cap_123",
			Issuer:         "ovara",
			Subject:        "agent-001",
			AllowedActions: []string{"shell"},
			ResourceScope:   "shell:*",
			Expiry:         time.Now().Add(1 * time.Hour),
		},
	}

	result := v.ValidateAll(req)
	if !result.Valid {
		t.Errorf("expected valid, got %v: %v", result.Valid, result.Reasons)
	}
}

// TestCapabilityLeaseSignatureVerification validates that leases signed
// with ed25519 are correctly verified by the gateway validator. The payload
// format matches ovara.identity.CapabilityLease.digestPayload().
func TestCapabilityLeaseSignatureVerification(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("key gen failed: %v", err)
	}
	verifyKeyHex := hex.EncodeToString(pub)

	now := time.Now().UTC()
	expiry := now.Add(1 * time.Hour)

	// This payload format matches ovara.identity module:
	// LeaseID|Issuer|Subject|AllowedActions|ResourceScope|ExpiryUnix|DelegationDepth|IssuedAtUnix
	payload := fmt.Sprintf("%s|%s|%s|%v|%s|%d|%d|%d",
		"lse_test", "ovara", "agent-001", []string{"shell", "exec"},
		"*", expiry.Unix(), 1, now.Unix(),
	)
	sig := ed25519.Sign(priv, []byte(payload))

	lease := &models.CapabilityLease{
		LeaseID:         "lse_test",
		Issuer:          "ovara",
		Subject:         "agent-001",
		AllowedActions:  []string{"shell", "exec"},
		ResourceScope:   "*",
		Expiry:          expiry,
		DelegationDepth: 1,
		IssuedAt:        now,
		Signature:       sig,
		VerifyKey:       verifyKeyHex,
	}

	v := NewValidator()
	result := v.ValidateCapabilityLease(lease)
	if !result.Valid {
		t.Fatalf("expected valid, got: %v", result.Reasons)
	}
}

// TestCapabilityLeaseSignatureRejection validates that a tampered lease
// (wrong subject) fails signature verification.
func TestCapabilityLeaseSignatureRejection(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("key gen failed: %v", err)
	}
	verifyKeyHex := hex.EncodeToString(pub)

	now := time.Now().UTC()
	expiry := now.Add(1 * time.Hour)

	// Sign for "agent-001"
	payload := fmt.Sprintf("%s|%s|%s|%v|%s|%d|%d|%d",
		"lse_test", "ovara", "agent-001", []string{"shell"},
		"*", expiry.Unix(), 1, now.Unix(),
	)
	sig := ed25519.Sign(priv, []byte(payload))

	// But present as "agent-002" (tampered)
	lease := &models.CapabilityLease{
		LeaseID:         "lse_test",
		Issuer:          "ovara",
		Subject:         "agent-002", // tampered!
		AllowedActions:  []string{"shell"},
		ResourceScope:   "*",
		Expiry:          expiry,
		DelegationDepth: 1,
		IssuedAt:        now,
		Signature:       sig,
		VerifyKey:       verifyKeyHex,
	}

	v := NewValidator()
	result := v.ValidateCapabilityLease(lease)
	if result.Valid {
		t.Fatal("expected invalid for tampered lease")
	}
	found := false
	for _, r := range result.Reasons {
		if strings.Contains(r, "signature verification failed") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected signature verification failure reason, got: %v", result.Reasons)
	}
}

// TestCapabilityLeaseSignatureMissingKey validates that signature without
// verify key is rejected.
func TestCapabilityLeaseSignatureMissingKey(t *testing.T) {
	now := time.Now().UTC()
	lease := &models.CapabilityLease{
		LeaseID:         "lse_test",
		Issuer:          "ovara",
		Subject:         "agent-001",
		AllowedActions:  []string{"shell"},
		ResourceScope:   "*",
		Expiry:          now.Add(1 * time.Hour),
		DelegationDepth: 1,
		IssuedAt:        now,
		Signature:       []byte{0x01, 0x02, 0x03},
		// VerifyKey intentionally empty
	}

	v := NewValidator()
	result := v.ValidateCapabilityLease(lease)
	if result.Valid {
		t.Fatal("expected invalid for signature without verify key")
	}
	found := false
	for _, r := range result.Reasons {
		if strings.Contains(r, "signature verification failed") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected signature verification failure reason, got: %v", result.Reasons)
	}
}

// TestDelegationChainHashVerification validates chain hash integrity.
func TestDelegationChainHashVerification(t *testing.T) {
	// Compute hash using same algorithm as ovara.identity
	payload := "2|root|agent-root|1000|delegator|agent-leaf|2000|"
	hash := hex.EncodeToString(testSHA256Hash([]byte(payload)))

	chain := &models.DelegationChain{
		Authorities: []models.Authority{
			{Issuer: "root", SubjectID: "agent-root", DelegatedAt: time.Unix(1000, 0)},
			{Issuer: "delegator", SubjectID: "agent-leaf", DelegatedAt: time.Unix(2000, 0)},
		},
		ChainHash: hash,
		Depth:     2,
	}

	v := NewValidator()
	result := v.ValidateDelegationChain(chain)
	if !result.Valid {
		t.Errorf("expected valid chain hash, got: %v", result.Reasons)
	}
}

// TestDelegationChainHashRejection validates that a tampered chain hash is rejected.
func TestDelegationChainHashRejection(t *testing.T) {
	chain := &models.DelegationChain{
		Authorities: []models.Authority{
			{Issuer: "root", SubjectID: "agent-root", DelegatedAt: time.Unix(1000, 0)},
		},
		ChainHash: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
		Depth:     1,
	}

	v := NewValidator()
	result := v.ValidateDelegationChain(chain)
	if result.Valid {
		t.Fatal("expected invalid for tampered chain hash")
	}
	found := false
	for _, r := range result.Reasons {
		if strings.Contains(r, "chain_hash verification failed") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected chain_hash verification failure reason, got: %v", result.Reasons)
	}
}

func testSHA256Hash(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}
