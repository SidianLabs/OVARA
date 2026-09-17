// Package gateway evaluates action requests against the Ovara runtime
// gateway's decision endpoint.
package gateway

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type Client struct {
	baseURL string
	token   string
	env     string
	hc      *http.Client
}

func New(baseURL, token, env string) *Client {
	return &Client{
		baseURL: baseURL,
		token:   token,
		env:     env,
		hc:      &http.Client{Timeout: 5 * time.Second},
	}
}

type Decision struct {
	Decision         string   `json:"decision"` // allow | deny | escalate
	DecisionID       string   `json:"decision_id"`
	ReasonCodes      []string `json:"reason_codes"`
	RequiresApproval bool     `json:"requires_approval"`
	TrustScore       float64  `json:"trust_score"`
}

func nonce() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// Check evaluates an HTTP egress action. resource is "METHOD scheme://host/path".
func (c *Client) Check(ctx context.Context, method, url string) (*Decision, error) {
	body, _ := json.Marshal(map[string]any{
		"action_type": "http.request",
		"resource":    fmt.Sprintf("%s %s", method, url),
		"environment": c.env,
		"agent_identity": map[string]string{
			"issuer":     "ovara-proxy",
			"subject_id": "egress-agent",
		},
		"nonce":     nonce(),
		"issued_at": time.Now().UTC().Format(time.RFC3339Nano),
	})
	req, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/v1/runtime/check", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("gateway returned %d", resp.StatusCode)
	}
	var d Decision
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
		return nil, err
	}
	return &d, nil
}
