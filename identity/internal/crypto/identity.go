package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

type LifecycleState string

const (
	LifecycleActive    LifecycleState = "active"
	LifecycleSuspended LifecycleState = "suspended"
	LifecycleRevoked   LifecycleState = "revoked"
)

type AgentIdentity struct {
	ID        string         `json:"id"`
	Issuer    string         `json:"issuer"`
	SubjectID string         `json:"subject_id"`
	Owner     string         `json:"owner"`
	Lifecycle LifecycleState `json:"lifecycle"`
	PublicKey []byte         `json:"public_key,omitempty"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
}

func NewAgentIdentity(issuer, subjectID, owner string) (*AgentIdentity, ed25519.PrivateKey, error) {
	if issuer == "" {
		return nil, nil, fmt.Errorf("issuer is required")
	}
	if subjectID == "" {
		return nil, nil, fmt.Errorf("subject_id is required")
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate key: %w", err)
	}

	now := time.Now().UTC()
	return &AgentIdentity{
		ID:        "agt_" + hex.EncodeToString(pub[:8]),
		Issuer:    issuer,
		SubjectID: subjectID,
		Owner:     owner,
		Lifecycle: LifecycleActive,
		PublicKey: pub,
		CreatedAt: now,
		UpdatedAt: now,
	}, priv, nil
}

func (a *AgentIdentity) Digest() string {
	payload := fmt.Sprintf("%s|%s|%s|%s|%s",
		a.ID, a.Issuer, a.SubjectID, a.Owner, a.Lifecycle)
	h := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(h[:])
}

func (a *AgentIdentity) IsActive() bool {
	return a.Lifecycle == LifecycleActive
}

func (a *AgentIdentity) Suspend() {
	a.Lifecycle = LifecycleSuspended
	a.UpdatedAt = time.Now().UTC()
}

func (a *AgentIdentity) Revoke() {
	a.Lifecycle = LifecycleRevoked
	a.UpdatedAt = time.Now().UTC()
}

func (a *AgentIdentity) Verify(publicKey []byte) bool {
	return len(a.PublicKey) > 0 && len(publicKey) > 0 &&
		hex.EncodeToString(a.PublicKey) == hex.EncodeToString(publicKey)
}

func (a *AgentIdentity) Validate() []string {
	var errs []string
	if a.Issuer == "" {
		errs = append(errs, "issuer is required")
	}
	if a.SubjectID == "" {
		errs = append(errs, "subject_id is required")
	}
	if a.Owner == "" {
		errs = append(errs, "owner is required")
	}
	return errs
}
