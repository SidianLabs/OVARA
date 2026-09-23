package record

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// HTTPSigner returns a sign func that delegates each envelope payload
// to a remote signing service (signerd). The gateway sends the exact
// canonical payload bytes and the claimed (domain, gateway, key)
// identity; the service authenticates the caller, checks the identity
// against its own, signs, and returns the signature. The private key
// never enters gateway memory — custody separation (C2-B A2).
func HTTPSigner(endpoint, token, domainID, gatewayID, keyID string) func([]byte) ([]byte, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	type signReq struct {
		Payload   string `json:"payload"`
		DomainID  string `json:"domain_id"`
		GatewayID string `json:"gateway_id"`
		KeyID     string `json:"key_id"`
	}
	type signResp struct {
		Sig   string `json:"sig"`
		Error string `json:"error"`
	}
	return func(payload []byte) ([]byte, error) {
		body, _ := json.Marshal(signReq{
			Payload:   hex.EncodeToString(payload),
			DomainID:  domainID,
			GatewayID: gatewayID,
			KeyID:     keyID,
		})
		req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
		if err != nil {
			return nil, fmt.Errorf("remote signer request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("remote signer unreachable: %w", err)
		}
		defer resp.Body.Close()
		data, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		if err != nil {
			return nil, fmt.Errorf("remote signer: read response: %w", err)
		}
		var out signResp
		if err := json.Unmarshal(data, &out); err != nil {
			return nil, fmt.Errorf("remote signer: bad response: %w", err)
		}
		if resp.StatusCode != http.StatusOK || out.Sig == "" {
			return nil, fmt.Errorf("remote signer refused: %s", out.Error)
		}
		sig, err := hex.DecodeString(out.Sig)
		if err != nil {
			return nil, fmt.Errorf("remote signer: bad signature encoding: %w", err)
		}
		return sig, nil
	}
}
