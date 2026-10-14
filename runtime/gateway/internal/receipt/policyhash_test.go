package receipt

import (
	"testing"
)

// policy_hash is covered by the gateway signature: changing, adding or
// stripping it invalidates the receipt. Receipts without it keep the
// preimage they were signed with.
func TestPolicyHashIsSigned(t *testing.T) {
	reg, priv, gw, kid := testRegistry(t)
	signer := NewEdSigner(priv, gw, kid)

	r := sampleReceipt()
	r.PolicyHash = "sha256:aaaa"
	signer.SignReceipt(r)
	if ok, err := VerifySignature(resolver(reg), r); !ok || err != nil {
		t.Fatalf("receipt with policy_hash rejected: %v %v", ok, err)
	}
	r.PolicyHash = "sha256:bbbb"
	if ok, _ := VerifySignature(resolver(reg), r); ok {
		t.Fatal("changed policy_hash verified")
	}
	r.PolicyHash = ""
	if ok, _ := VerifySignature(resolver(reg), r); ok {
		t.Fatal("stripped policy_hash verified")
	}

	old := sampleReceipt()
	signer.SignReceipt(old)
	if ok, err := VerifySignature(resolver(reg), old); !ok || err != nil {
		t.Fatalf("receipt without policy_hash rejected: %v %v", ok, err)
	}
	old.PolicyHash = "sha256:aaaa"
	if ok, _ := VerifySignature(resolver(reg), old); ok {
		t.Fatal("added policy_hash verified")
	}
}
