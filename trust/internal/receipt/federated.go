package receipt

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"time"
)

type FederatedIdentity struct {
	IdentityDigest string    `json:"identity_digest"`
	Domain         string    `json:"domain"`
	PublicKey      []byte    `json:"public_key,omitempty"`
	IssuedAt       time.Time `json:"issued_at"`
	ExpiresAt      time.Time `json:"expires_at"`
	Signature      []byte    `json:"signature"`
}

// Digest returns the canonical (JSON) byte representation of the fields
// covered by the identity signature.
func (fi *FederatedIdentity) Digest() []byte {
	payload, _ := json.Marshal(struct {
		IdentityDigest string `json:"identity_digest"`
		Domain         string `json:"domain"`
		IssuedAt       int64  `json:"issued_at"`
		ExpiresAt      int64  `json:"expires_at"`
	}{
		IdentityDigest: fi.IdentityDigest,
		Domain:         fi.Domain,
		IssuedAt:       fi.IssuedAt.Unix(),
		ExpiresAt:      fi.ExpiresAt.Unix(),
	})
	return payload
}

func (fi *FederatedIdentity) Sign(privateKey ed25519.PrivateKey) error {
	if len(privateKey) != ed25519.PrivateKeySize {
		return fmt.Errorf("invalid private key size: expected %d, got %d", ed25519.PrivateKeySize, len(privateKey))
	}
	fi.Signature = ed25519.Sign(privateKey, fi.Digest())
	return nil
}

func (fi *FederatedIdentity) Verify(publicKey ed25519.PublicKey) bool {
	if len(fi.Signature) == 0 || len(publicKey) != ed25519.PublicKeySize {
		return false
	}
	return ed25519.Verify(publicKey, fi.Digest(), fi.Signature)
}
