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

// testIssuerKeys returns a trusted-issuer registry and the private key
// that signs leases for "ovara" in tests.
func testIssuerKeys(t *testing.T, issuer string) (map[string][]byte, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("key gen failed: %v", err)
	}
	return map[string][]byte{issuer: pub}, priv
}

// signTestLease signs the lease with priv using the payload format that
// matches ovara.identity.CapabilityLease.digestPayload().
func signTestLease(t *testing.T, lease *models.CapabilityLease, priv ed25519.PrivateKey) {
	t.Helper()
	lease.Signature = ed25519.Sign(priv, leasePayload(lease))
}

// signHops signs every delegation hop with the matching issuer key.
func signHops(chain *models.DelegationChain, keys map[string]ed25519.PrivateKey) {
	prevSig := ""
	for i := range chain.Authorities {
		priv, ok := keys[chain.Authorities[i].Issuer]
		if !ok {
			panic("no test key for issuer " + chain.Authorities[i].Issuer)
		}
		chain.Authorities[i].Signature = ed25519.Sign(priv, hopPayload(chain.Authorities, i, prevSig))
		prevSig = hex.EncodeToString(chain.Authorities[i].Signature)
	}
}

func TestValidator_ValidateCapabilityLease_Valid(t *testing.T) {
	trusted, priv := testIssuerKeys(t, "ovara")
	v := NewValidatorWithTrustedKeys(trusted)
	lease := &models.CapabilityLease{
		LeaseID:         "cap_123",
		Issuer:          "ovara",
		Subject:         "agent-001",
		AllowedActions:  []string{"shell", "git.push"},
		ResourceScope:   "repo:acme/api",
		Expiry:          time.Now().Add(1 * time.Hour),
		DelegationDepth: 1,
	}
	signTestLease(t, lease, priv)

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
		LeaseID:         "cap_123",
		Issuer:          "ovara",
		Subject:         "agent-001",
		AllowedActions:  []string{"shell"},
		ResourceScope:   "*",
		Expiry:          time.Now().Add(-1 * time.Hour),
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
		LeaseID:         "cap_123",
		Issuer:          "ovara",
		Subject:         "agent-001",
		AllowedActions:  []string{},
		ResourceScope:   "*",
		Expiry:          time.Now().Add(1 * time.Hour),
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
		LeaseID:         "cap_123",
		Issuer:          "ovara",
		Subject:         "agent-001",
		AllowedActions:  []string{"shell"},
		ResourceScope:   "*",
		Expiry:          time.Now().Add(1 * time.Hour),
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
		ResourceScope:  "repo:acme/api",
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
		ResourceScope:  "repo:acme/api",
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
		ResourceScope:  "repo:acme/api",
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
		ResourceScope:  "*",
		Expiry:         time.Now().Add(1 * time.Hour),
	}

	result := v.ValidateCapabilityLeaseScope(lease, "shell", "repo:anything")
	if !result.Valid {
		t.Errorf("expected valid for wildcard scope, got %v: %v", result.Valid, result.Reasons)
	}
}

func TestValidator_ValidateDelegationChain_Empty(t *testing.T) {
	v := NewValidator()

	result := v.ValidateDelegationChain(&models.DelegationChain{}, "", nil)
	if result.Valid {
		t.Error("expected invalid for empty delegation chain")
	}
}

func TestValidator_ValidateDelegationChain_Valid(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	v := NewValidatorWithTrustedKeys(map[string][]byte{"root": pub})
	chain := &models.DelegationChain{
		Authorities: []models.Authority{
			{Issuer: "root", SubjectID: "agent-001", Nonce: "n1"},
		},
		Depth: 1,
	}
	signHops(chain, map[string]ed25519.PrivateKey{"root": priv})

	result := v.ValidateDelegationChain(chain, "agent-001", nil)
	if !result.Valid {
		t.Errorf("expected valid, got %v: %v", result.Valid, result.Reasons)
	}
}

func TestValidator_ValidateDelegationChain_Nil(t *testing.T) {
	v := NewValidator()

	result := v.ValidateDelegationChain(nil, "", nil)
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
	trusted, priv := testIssuerKeys(t, "ovara")
	v := NewValidatorWithTrustedKeys(trusted)
	lease := &models.CapabilityLease{
		LeaseID:        "cap_123",
		Issuer:         "ovara",
		Subject:        "agent-001",
		AllowedActions: []string{"shell"},
		ResourceScope:  "shell:*",
		Expiry:         time.Now().Add(1 * time.Hour),
	}
	signTestLease(t, lease, priv)
	req := &models.ActionRequest{
		ActionType:  models.ActionTypeShell,
		Resource:    "shell:echo",
		Environment: models.EnvironmentLocal,
		AgentIdentity: &models.AgentIdentity{
			Issuer:    "ovara",
			SubjectID: "agent-001",
		},
		CapabilityLease: lease,
	}

	result := v.ValidateAll(req)
	if !result.Valid {
		t.Errorf("expected valid, got %v: %v", result.Valid, result.Reasons)
	}
}

// TestCapabilityLeaseSignatureVerification validates that leases signed
// with ed25519 by a trusted issuer are correctly verified by the gateway
// validator. The payload format matches ovara.identity.CapabilityLease.digestPayload().
func TestCapabilityLeaseSignatureVerification(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("key gen failed: %v", err)
	}
	verifyKeyHex := hex.EncodeToString(pub)

	now := time.Now().UTC()
	expiry := now.Add(1 * time.Hour)

	lease := &models.CapabilityLease{
		LeaseID:         "lse_test",
		Issuer:          "ovara",
		Subject:         "agent-001",
		AllowedActions:  []string{"shell", "exec"},
		ResourceScope:   "*",
		Expiry:          expiry,
		DelegationDepth: 1,
		IssuedAt:        now,
		VerifyKey:       verifyKeyHex,
	}
	lease.Signature = ed25519.Sign(priv, leasePayload(lease))

	v := NewValidatorWithTrustedKeys(map[string][]byte{"ovara": pub})
	result := v.ValidateCapabilityLease(lease)
	if !result.Valid {
		t.Fatalf("expected valid, got: %v", result.Reasons)
	}
}

// TestCapabilityLeaseSignatureRejection validates that a tampered lease
// (wrong subject) fails signature verification against the trusted key.
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

	v := NewValidatorWithTrustedKeys(map[string][]byte{"ovara": pub})
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

// TestCapabilityLeaseSignatureUntrustedIssuer validates that a lease signed
// by an issuer with no registered trusted key is rejected, even when the
// request self-asserts a matching verify_key.
func TestCapabilityLeaseSignatureUntrustedIssuer(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("key gen failed: %v", err)
	}

	now := time.Now().UTC()
	lease := &models.CapabilityLease{
		LeaseID:         "lse_test",
		Issuer:          "evil-issuer",
		Subject:         "agent-001",
		AllowedActions:  []string{"shell"},
		ResourceScope:   "*",
		Expiry:          now.Add(1 * time.Hour),
		DelegationDepth: 1,
		IssuedAt:        now,
		VerifyKey:       hex.EncodeToString(pub), // self-asserted key
	}
	signTestLease(t, lease, priv)

	v := NewValidator()
	result := v.ValidateCapabilityLease(lease)
	if result.Valid {
		t.Fatal("expected invalid for lease from untrusted issuer")
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

// TestCapabilityLeaseSignatureRequired validates that an unsigned lease is
// rejected: a signature is mandatory.
func TestCapabilityLeaseSignatureRequired(t *testing.T) {
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
	}

	v := NewValidator()
	result := v.ValidateCapabilityLease(lease)
	if result.Valid {
		t.Fatal("expected invalid for unsigned lease")
	}
	found := false
	for _, r := range result.Reasons {
		if strings.Contains(r, "signature is required") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected signature required reason, got: %v", result.Reasons)
	}
}

// TestCapabilityLeaseSignatureFailClosed validates that a validator with no
// trusted keys rejects even a properly signed lease.
func TestCapabilityLeaseSignatureFailClosed(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("key gen failed: %v", err)
	}

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
	}
	signTestLease(t, lease, priv)

	v := NewValidator()
	result := v.ValidateCapabilityLease(lease)
	if result.Valid {
		t.Fatal("expected invalid: signed lease must fail closed without trusted keys")
	}
}

// TestDelegationChainHashVerification validates chain hash integrity.
func TestDelegationChainHashVerification(t *testing.T) {
	// Compute hash using same algorithm as ovara.identity
	payload := "2|root|delegator|1000|delegator|agent-leaf|2000|"
	hash := hex.EncodeToString(testSHA256Hash([]byte(payload)))

	chain := &models.DelegationChain{
		Authorities: []models.Authority{
			{Issuer: "root", SubjectID: "delegator", DelegatedAt: time.Unix(1000, 0)},
			{Issuer: "delegator", SubjectID: "agent-leaf", DelegatedAt: time.Unix(2000, 0), Nonce: "n-hash"},
		},
		ChainHash: hash,
		Depth:     2,
	}

	// Both hops must be signed by trusted issuer keys; the intermediate
	// subject ("delegator") is itself a trusted issuer so it may chain.
	pubR, privR, _ := ed25519.GenerateKey(nil)
	pubD, privD, _ := ed25519.GenerateKey(nil)
	v := NewValidatorWithTrustedKeys(map[string][]byte{"root": pubR, "delegator": pubD})
	signHops(chain, map[string]ed25519.PrivateKey{"root": privR, "delegator": privD})
	result := v.ValidateDelegationChain(chain, "agent-leaf", nil)
	if !result.Valid {
		t.Errorf("expected valid chain hash, got: %v", result.Reasons)
	}
}

// TestDelegationChainHashRejection validates that a tampered chain hash is rejected.
func TestDelegationChainHashRejection(t *testing.T) {
	chain := &models.DelegationChain{
		Authorities: []models.Authority{
			{Issuer: "root", SubjectID: "agent-root", DelegatedAt: time.Unix(1000, 0), Nonce: "n-tamper"},
		},
		ChainHash: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
		Depth:     1,
	}

	pub, priv, _ := ed25519.GenerateKey(nil)
	v := NewValidatorWithTrustedKeys(map[string][]byte{"root": pub})
	signHops(chain, map[string]ed25519.PrivateKey{"root": priv})
	result := v.ValidateDelegationChain(chain, "agent-root", nil)
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
