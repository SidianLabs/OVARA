package receipt

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"
)

// A stolen key that has been revoked must not be able to mint receipts
// that verify as new: anything claiming to be issued after the revocation
// is refused, while receipts from before it keep verifying.
func TestRevokedKey_ReceiptIssuedAfterRevocationRejected(t *testing.T) {
	reg, priv, gw, kid := testRegistry(t)
	pub2, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := reg.Rotate(gw, pub2, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := reg.RevokeKey(gw, kid); err != nil {
		t.Fatal(err)
	}

	before := sampleReceipt() // issued in 2023, long before the revocation
	NewEdSigner(priv, gw, kid).SignReceipt(before)
	if ok, err := VerifySignature(resolver(reg), before); !ok || err != nil {
		t.Fatalf("pre-revocation receipt must verify: ok=%v err=%v", ok, err)
	}

	after := sampleReceipt()
	after.IssuedAt = time.Now().UTC().Add(time.Minute)
	NewEdSigner(priv, gw, kid).SignReceipt(after) // attacker still holds the key
	ok, err := VerifySignature(resolver(reg), after)
	if ok || !errors.Is(err, ErrSignedAfterRevocation) {
		t.Fatalf("post-revocation receipt must be rejected: ok=%v err=%v", ok, err)
	}
}

func TestDestroyedKey_ReceiptIssuedAfterDestroyRejected(t *testing.T) {
	reg, priv, gw, kid := testRegistry(t)
	if err := reg.Destroy(gw); err != nil {
		t.Fatal(err)
	}
	r := sampleReceipt()
	r.IssuedAt = time.Now().UTC().Add(time.Minute)
	NewEdSigner(priv, gw, kid).SignReceipt(r)
	if ok, err := VerifySignature(resolver(reg), r); ok || !errors.Is(err, ErrSignedAfterRevocation) {
		t.Fatalf("post-destroy receipt must be rejected: ok=%v err=%v", ok, err)
	}
}

// Rotation is routine, not compromise: a superseded key's receipts are not
// subject to the revocation-time rule.
func TestSupersededKey_NotTreatedAsRevoked(t *testing.T) {
	reg, priv, gw, kid := testRegistry(t)
	pub2, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := reg.Rotate(gw, pub2, 0); err != nil {
		t.Fatal(err)
	}
	r := sampleReceipt()
	r.IssuedAt = time.Now().UTC()
	NewEdSigner(priv, gw, kid).SignReceipt(r)
	if ok, err := VerifySignature(resolver(reg), r); !ok || err != nil {
		t.Fatalf("superseded-key receipt must still verify: ok=%v err=%v", ok, err)
	}
}
