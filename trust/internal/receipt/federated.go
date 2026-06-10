package receipt

import (
	"crypto/ed25519"
	"fmt"
	"time"
)

type FederatedIdentity struct {
	IdentityDigest string    `json:"identity_digest"`
	Domain         string    `json:"domain"`
	SigningKey     []byte    `json:"signing_key,omitempty"`
	IssuedAt       time.Time `json:"issued_at"`
	ExpiresAt      time.Time `json:"expires_at"`
	Signature      []byte    `json:"signature"`
}

func (fi *FederatedIdentity) Digest() string {
	payload := fmt.Sprintf("%s|%s|%d|%d",
		fi.IdentityDigest, fi.Domain,
		fi.IssuedAt.Unix(), fi.ExpiresAt.Unix(),
	)
	return payload
}

func (fi *FederatedIdentity) Sign(privateKey ed25519.PrivateKey) error {
	if len(privateKey) != ed25519.PrivateKeySize {
		return fmt.Errorf("invalid private key size: expected %d, got %d", ed25519.PrivateKeySize, len(privateKey))
	}
	payload := fi.Digest()
	fi.Signature = ed25519.Sign(privateKey, []byte(payload))
	return nil
}

func (fi *FederatedIdentity) Verify(publicKey ed25519.PublicKey) bool {
	if len(fi.Signature) == 0 || len(publicKey) != ed25519.PublicKeySize {
		return false
	}
	payload := fi.Digest()
	return ed25519.Verify(publicKey, []byte(payload), fi.Signature)
}
