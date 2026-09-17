package crypto

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

type AttestationStatus string

const (
	AttestationVerified AttestationStatus = "verified"
	AttestationPending  AttestationStatus = "pending"
	AttestationExpired  AttestationStatus = "expired"
)

type TrustMetadata struct {
	SubjectID         string            `json:"subject_id"`
	Environment       string            `json:"environment"`
	AttestationStatus AttestationStatus `json:"attestation_status"`
	RuntimeVersion    string            `json:"runtime_version,omitempty"`
	EvaluationTime    time.Time         `json:"evaluation_time"`
	IssuedBy          string            `json:"issued_by"`
	Signature         []byte            `json:"signature,omitempty"`
}

func SignTrustMetadata(issuer *AgentIdentity, issuerKey ed25519.PrivateKey, subjectID, environment, runtimeVersion string) (*TrustMetadata, error) {
	if issuer == nil {
		return nil, fmt.Errorf("issuer identity is required")
	}
	if !issuer.IsActive() {
		return nil, fmt.Errorf("issuer identity is not active")
	}
	if subjectID == "" {
		return nil, fmt.Errorf("subject_id is required")
	}
	if environment == "" {
		return nil, fmt.Errorf("environment is required")
	}

	now := time.Now().UTC()
	tm := &TrustMetadata{
		SubjectID:         subjectID,
		Environment:       environment,
		AttestationStatus: AttestationVerified,
		RuntimeVersion:    runtimeVersion,
		EvaluationTime:    now,
		IssuedBy:          issuer.ID,
	}

	sig := ed25519.Sign(issuerKey, tm.digestPayload())
	tm.Signature = sig
	return tm, nil
}

// digestPayload returns the canonical (JSON) byte representation of the
// fields covered by the metadata signature.
func (t *TrustMetadata) digestPayload() []byte {
	return canonicalJSON(struct {
		SubjectID         string            `json:"subject_id"`
		Environment       string            `json:"environment"`
		AttestationStatus AttestationStatus `json:"attestation_status"`
		RuntimeVersion    string            `json:"runtime_version"`
		EvaluationTime    int64             `json:"evaluation_time"`
		IssuedBy          string            `json:"issued_by"`
	}{
		SubjectID:         t.SubjectID,
		Environment:       t.Environment,
		AttestationStatus: t.AttestationStatus,
		RuntimeVersion:    t.RuntimeVersion,
		EvaluationTime:    t.EvaluationTime.Unix(),
		IssuedBy:          t.IssuedBy,
	})
}

func (t *TrustMetadata) Digest() string {
	h := sha256.Sum256(t.digestPayload())
	return hex.EncodeToString(h[:])
}

func (t *TrustMetadata) Verify(publicKey []byte) bool {
	if len(t.Signature) == 0 || len(publicKey) != ed25519.PublicKeySize {
		return false
	}
	return ed25519.Verify(publicKey, t.digestPayload(), t.Signature)
}

func (t *TrustMetadata) IsExpired(maxAge time.Duration) bool {
	return time.Now().UTC().Sub(t.EvaluationTime) > maxAge
}

func (t *TrustMetadata) Validate() []string {
	var errs []string
	if t.SubjectID == "" {
		errs = append(errs, "subject_id is required")
	}
	if t.Environment == "" {
		errs = append(errs, "environment is required")
	}
	if t.IssuedBy == "" {
		errs = append(errs, "issued_by is required")
	}
	return errs
}
