// Package gateway evaluates action requests against the Ovara runtime
// gateway's decision endpoint.
package gateway

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

type Client struct {
	baseURL string
	token   string
	env     string
	subject    string
	resolveMu  sync.Mutex
	resolved   bool
	hc         *http.Client
}

// subjectID mirrors the gateway's credential-derived principal
// (ag_<sha256(token)[:16]>) — the gateway binds agent_identity.subject_id
// to the authenticated principal and rejects anything else. With no token
// (auth-disabled dev mode) the identity stays a descriptive constant.
func subjectID(token string) string {
	if token == "" {
		return "egress-agent"
	}
	sum := sha256.Sum256([]byte(token))
	return "ag_" + hex.EncodeToString(sum[:])[:16]
}

func New(baseURL, token, env string) *Client {
	return &Client{
		baseURL: baseURL,
		token:   token,
		env:     env,
		subject: subjectID(token),
		hc:      &http.Client{Timeout: 5 * time.Second},
	}
}

// resolveSubject asks the gateway who this credential is (P2.2): a
// rotated credential still binds to its stable identity, so the local
// hash derivation can be stale. Falls back to the RC1 derivation —
// bindIdentity on the gateway rejects a wrong guess either way.
// It reports whether the answer is final. A transport error (the gateway is
// not up yet) is NOT final and is retried on the next request; before, the
// lookup ran once and a gateway that was slow to start left the proxy with
// the derived fallback for the life of the process. Any HTTP answer, even an
// error from an older gateway without /v1/whoami, is final.
func (c *Client) resolveSubject() (final bool) {
	if c.token == "" {
		return true // auth-disabled dev mode keeps the descriptive constant
	}
	req, err := http.NewRequest(http.MethodGet, c.baseURL+"/v1/whoami", nil)
	if err != nil {
		return true
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	resp, err := c.hc.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return true
	}
	var body struct {
		PrincipalID string `json:"principal_id"`
	}
	if json.NewDecoder(resp.Body).Decode(&body) == nil && body.PrincipalID != "" {
		c.subject = body.PrincipalID
	}
	return true
}

func (c *Client) resolvedSubject() string {
	c.resolveMu.Lock()
	defer c.resolveMu.Unlock()
	if !c.resolved {
		c.resolved = c.resolveSubject()
	}
	return c.subject
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
	return c.CheckWithContext(ctx, method, url, nil)
}

// CheckWithContext is Check plus a display-only preview of the request (query
// string, body size and type, a short redacted body snippet). The gateway
// records it with the evaluated request and shows it to the human who is asked
// to approve; it takes no part in the policy decision.
func (c *Client) CheckWithContext(ctx context.Context, method, url string, preview map[string]string) (*Decision, error) {
	payload := map[string]any{
		"action_type": "http.request",
		"resource":    fmt.Sprintf("%s %s", method, url),
		"environment": c.env,
		"agent_identity": map[string]string{
			"issuer":     "ovara-proxy",
			"subject_id": c.resolvedSubject(),
		},
		"nonce":     nonce(),
		"issued_at": time.Now().UTC().Format(time.RFC3339Nano),
	}
	if len(preview) > 0 {
		payload["metadata"] = map[string]any{"proxy_context": preview}
	}
	body, _ := json.Marshal(payload)
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
		"agent_id":    c.resolvedSubject(),
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
