package receipt

import (
	"time"
)

type FederatedIdentity struct {
	IdentityDigest string    `json:"identity_digest"`
	Domain         string    `json:"domain"`
	SigningKey     []byte    `json:"signing_key,omitempty"`
	IssuedAt       time.Time `json:"issued_at"`
	ExpiresAt      time.Time `json:"expires_at"`
}
