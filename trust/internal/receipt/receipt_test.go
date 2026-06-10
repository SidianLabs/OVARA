package receipt

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

func TestCrossOrgReceipt_SignAndVerify(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)

	receipt := &CrossOrgReceipt{
		ReceiptID:      "rcpt_001",
		DecisionID:     "dec_001",
		IssuingGateway: "gw_a",
		IssuingOrg:     "acme.com",
		ActionType:     "shell.execute",
		Resource:       "sudo",
		Decision:       "deny",
		AgentIdentity:  "agt_abc123",
		TrustScore:     0.85,
		Timestamp:      time.Now().UTC(),
	}

	err := SignCrossOrgReceipt(receipt, priv)
	if err != nil {
		t.Fatalf("SignCrossOrgReceipt failed: %v", err)
	}
	if len(receipt.Signature) == 0 {
		t.Fatal("signature should not be empty")
	}

	if !receipt.Verify(pub) {
		t.Error("receipt verification failed with correct public key")
	}

	wrongPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if receipt.Verify(wrongPub) {
		t.Error("receipt verification succeeded with wrong public key")
	}
}

func TestCrossOrgReceipt_VerifyTampered(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)

	receipt := &CrossOrgReceipt{
		ReceiptID:      "rcpt_001",
		DecisionID:     "dec_001",
		IssuingGateway: "gw_a",
		IssuingOrg:     "acme.com",
		ActionType:     "shell.execute",
		Resource:       "sudo",
		Decision:       "deny",
		AgentIdentity:  "agt_abc123",
		TrustScore:     0.85,
		Timestamp:      time.Now().UTC(),
	}

	SignCrossOrgReceipt(receipt, priv)
	receipt.Decision = "allow"

	if receipt.Verify(pub) {
		t.Error("tampered receipt should fail verification")
	}
}

func TestFederatedIdentity_Basic(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	digest := "sha256:abc123"

	fid := &FederatedIdentity{
		IdentityDigest: digest,
		Domain:         "acme.com",
		SigningKey:     priv,
		IssuedAt:       time.Now().UTC(),
		ExpiresAt:      time.Now().UTC().Add(24 * time.Hour),
	}

	if fid.IdentityDigest != digest {
		t.Errorf("IdentityDigest = %v, want %v", fid.IdentityDigest, digest)
	}
	if fid.Domain != "acme.com" {
		t.Errorf("Domain = %v, want acme.com", fid.Domain)
	}
}
