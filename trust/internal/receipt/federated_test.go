package receipt

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

func TestFederatedIdentity_SignAndVerify(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)

	fid := &FederatedIdentity{
		IdentityDigest: "sha256:deadbeef",
		Domain:         "acme.com",
		IssuedAt:       time.Now().UTC(),
		ExpiresAt:      time.Now().UTC().Add(24 * time.Hour),
	}

	err := fid.Sign(priv)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	if len(fid.Signature) == 0 {
		t.Fatal("signature should not be empty")
	}

	if !fid.Verify(pub) {
		t.Error("verification failed with correct public key")
	}

	wrongPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if fid.Verify(wrongPub) {
		t.Error("verification succeeded with wrong public key")
	}
}

func TestFederatedIdentity_VerifyTampered(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)

	fid := &FederatedIdentity{
		IdentityDigest: "sha256:deadbeef",
		Domain:         "acme.com",
		IssuedAt:       time.Now().UTC(),
		ExpiresAt:      time.Now().UTC().Add(24 * time.Hour),
	}

	fid.Sign(priv)
	fid.Domain = "evil.com"

	if fid.Verify(pub) {
		t.Error("tampered identity should fail verification")
	}
}

func TestFederatedIdentity_DigestDeterministic(t *testing.T) {
	fid := &FederatedIdentity{
		IdentityDigest: "sha256:abc",
		Domain:         "test.com",
		IssuedAt:       time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		ExpiresAt:      time.Date(2025, 1, 2, 0, 0, 0, 0, time.UTC),
	}

	d1 := fid.Digest()
	d2 := fid.Digest()
	if d1 != d2 {
		t.Error("Digest should be deterministic")
	}
	if d1 != "sha256:abc|test.com|1735689600|1735776000" {
		t.Errorf("unexpected digest: %s", d1)
	}
}

func TestFederatedIdentity_VerifyNoSignature(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)

	fid := &FederatedIdentity{
		IdentityDigest: "sha256:abc",
		Domain:         "test.com",
		IssuedAt:       time.Now().UTC(),
		ExpiresAt:      time.Now().UTC().Add(time.Hour),
	}

	if fid.Verify(pub) {
		t.Error("verification without signature should fail")
	}
}

func TestFederatedIdentity_SignInvalidKey(t *testing.T) {
	fid := &FederatedIdentity{
		IdentityDigest: "sha256:abc",
		Domain:         "test.com",
		IssuedAt:       time.Now().UTC(),
		ExpiresAt:      time.Now().UTC().Add(time.Hour),
	}

	err := fid.Sign(ed25519.PrivateKey([]byte("short")))
	if err == nil {
		t.Error("expected error for invalid key size")
	}
}
