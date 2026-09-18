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
	ApprovalID       string   `json:"approval_id"`
	TrustScore       float64  `json:"trust_score"`
	TrustLevel       string   `json:"trust_level"`
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

// CreateApproval opens an approval request (+ continuation) for an escalated
// decision. Returns the approval_id to poll.
func (c *Client) CreateApproval(ctx context.Context, d *Decision, method, url string) (string, error) {
	body, _ := json.Marshal(map[string]any{
		"decision_id": d.DecisionID,
		"action_type": "http.request",
		"resource":    fmt.Sprintf("%s %s", method, url),
		"environment": c.env,
		"agent_id":    "egress-agent",
		"trust_score": d.TrustScore,
		"trust_level": d.TrustLevel,
	})
	var out struct {
		ApprovalID string `json:"approval_id"`
	}
	if err := c.do(ctx, "POST", "/v1/approval/create", body, &out); err != nil {
		return "", err
	}
	return out.ApprovalID, nil
}

// ApprovalStatus returns pending | approved | denied for an approval_id.
func (c *Client) ApprovalStatus(ctx context.Context, approvalID string) (string, error) {
	var out struct {
		Status string `json:"status"`
	}
	if err := c.do(ctx, "GET", "/v1/approval/"+approvalID, nil, &out); err != nil {
		return "", err
	}
	return out.Status, nil
}

func (c *Client) do(ctx context.Context, method, path string, body []byte, out any) error {
	var req *http.Request
	var err error
	if body != nil {
		req, err = http.NewRequestWithContext(ctx, method, c.baseURL+path, bytes.NewReader(body))
	} else {
		req, err = http.NewRequestWithContext(ctx, method, c.baseURL+path, nil)
	}
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("gateway returned %d", resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
