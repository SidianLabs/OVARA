package evaluator

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type FederatedIdentity struct {
	IdentityDigest string    `json:"identity_digest"`
	Domain         string    `json:"domain"`
	IssuedAt       time.Time `json:"issued_at"`
	ExpiresAt      time.Time `json:"expires_at"`
	Signature      []byte    `json:"signature"`
}

type FederatedVerifyResult struct {
	Valid      bool
	Signature  bool
	NotExpired bool
	Domain     string
	Error      error
}

type FederatedTrustClient interface {
	VerifyFederatedIdentity(ctx context.Context, fid *FederatedIdentity, publicKey ed25519.PublicKey) *FederatedVerifyResult
}

type HTTPFederatedTrustClient struct {
	serverURL string
	client    *http.Client
}

func NewHTTPFederatedTrustClient(serverURL string) *HTTPFederatedTrustClient {
	return &HTTPFederatedTrustClient{
		serverURL: serverURL,
		client:    &http.Client{Timeout: 5 * time.Second},
	}
}

func (c *HTTPFederatedTrustClient) VerifyFederatedIdentity(ctx context.Context, fid *FederatedIdentity, publicKey ed25519.PublicKey) *FederatedVerifyResult {
	reqBody := map[string]interface{}{
		"identity_digest": fid.IdentityDigest,
		"domain":         fid.Domain,
		"signature":      hex.EncodeToString(fid.Signature),
		"public_key":     hex.EncodeToString(publicKey),
		"issued_at":      fid.IssuedAt.Format(time.RFC3339),
		"expires_at":     fid.ExpiresAt.Format(time.RFC3339),
	}
	b, err := json.Marshal(reqBody)
	if err != nil {
		return &FederatedVerifyResult{Error: err}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.serverURL+"/v1/identities/verify", bytes.NewReader(b))
	if err != nil {
		return &FederatedVerifyResult{Error: err}
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return &FederatedVerifyResult{Error: err}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return &FederatedVerifyResult{Error: fmt.Errorf("trust server returned status %d", resp.StatusCode)}
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return &FederatedVerifyResult{Error: err}
	}

	return &FederatedVerifyResult{
		Valid:      result["valid"].(bool),
		Signature:  result["signature"].(bool),
		NotExpired: result["not_expired"].(bool),
		Domain:     result["domain"].(string),
	}
}

type NoOpFederatedTrustClient struct{}

func (NoOpFederatedTrustClient) VerifyFederatedIdentity(ctx context.Context, fid *FederatedIdentity, publicKey ed25519.PublicKey) *FederatedVerifyResult {
	return &FederatedVerifyResult{Valid: true, NotExpired: true}
}