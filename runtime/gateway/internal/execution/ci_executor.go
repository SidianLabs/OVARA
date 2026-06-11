package execution

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type CIProvider interface {
	Name() string
	Trigger(ctx context.Context, action, resource string) (*http.Response, error)
}

type GitHubActionsProvider struct {
	Token   string
	BaseURL string
	Client  *http.Client
}

func NewGitHubActionsProvider(token string, timeoutSec int) *GitHubActionsProvider {
	if timeoutSec <= 0 {
		timeoutSec = 30
	}
	return &GitHubActionsProvider{
		Token:   token,
		BaseURL: "https://api.github.com",
		Client: &http.Client{
			Timeout: time.Duration(timeoutSec) * time.Second,
		},
	}
}

func (g *GitHubActionsProvider) Name() string { return "github-actions" }

func (g *GitHubActionsProvider) Trigger(ctx context.Context, action, resource string) (*http.Response, error) {
	parts := strings.SplitN(resource, ":", 3)
	if len(parts) < 2 {
		return nil, fmt.Errorf("resource must be <owner>/<repo>:<workflow>, got: %s", resource)
	}

	repoParts := strings.SplitN(parts[0], "/", 2)
	if len(repoParts) != 2 {
		return nil, fmt.Errorf("repo must be <owner>/<repo>, got: %s", parts[0])
	}

	owner, repo := repoParts[0], repoParts[1]
	workflow := parts[1]
	ref := "main"
	if len(parts) > 2 {
		ref = parts[2]
	}

	url := fmt.Sprintf("%s/repos/%s/%s/actions/workflows/%s/dispatches", g.BaseURL, owner, repo, workflow)
	payload := map[string]interface{}{
		"ref": ref,
		"inputs": map[string]string{
			"trigger": action,
			"source":  "ovara",
		},
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+g.Token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")

	return g.Client.Do(req)
}

type WebhookProvider struct {
	URL     string
	Token   string
	Client  *http.Client
}

func NewWebhookProvider(url, token string, timeoutSec int) *WebhookProvider {
	if timeoutSec <= 0 {
		timeoutSec = 30
	}
	return &WebhookProvider{
		URL:   url,
		Token: token,
		Client: &http.Client{
			Timeout: time.Duration(timeoutSec) * time.Second,
		},
	}
}

func (w *WebhookProvider) Name() string { return "webhook" }

func (w *WebhookProvider) Trigger(ctx context.Context, action, resource string) (*http.Response, error) {
	payload := map[string]interface{}{
		"action":   action,
		"resource": resource,
		"source":   "ovara",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", w.URL, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	if w.Token != "" {
		req.Header.Set("Authorization", "Bearer "+w.Token)
	}

	return w.Client.Do(req)
}

type CIExecutor struct {
	Providers map[string]CIProvider
	Timeout   time.Duration
}

func NewCIExecutor(timeoutSec int) *CIExecutor {
	if timeoutSec <= 0 {
		timeoutSec = 30
	}
	return &CIExecutor{
		Providers: make(map[string]CIProvider),
		Timeout:   time.Duration(timeoutSec) * time.Second,
	}
}

func (c *CIExecutor) RegisterProvider(provider CIProvider) {
	c.Providers[provider.Name()] = provider
}

func (c *CIExecutor) Execute(ctx context.Context, e *Execution) error {
	e.MarkStarted()

	parts, err := ParseCIResource(e.Resource)
	if err != nil {
		e.MarkFailed("invalid ci resource: "+err.Error(), 1)
		return err
	}

	provider, ok := c.Providers[parts.Provider]
	if !ok {
		e.MarkFailed("ci provider not registered: "+parts.Provider, 1)
		return fmt.Errorf("ci provider not registered: %s", parts.Provider)
	}

	timeout := c.Timeout
	if e.TimeoutSeconds > 0 {
		timeout = time.Duration(e.TimeoutSeconds) * time.Second
	}
	execCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	resp, err := provider.Trigger(execCtx, e.ActionType, parts.Resource)
	if err != nil {
		e.MarkFailed("ci trigger error: "+err.Error(), 1)
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		e.MarkFailed("failed to read ci response: "+err.Error(), 1)
		return fmt.Errorf("reading ci response: %w", err)
	}
	stdout := string(body)

	if resp.StatusCode >= 400 {
		e.MarkFailed(fmt.Sprintf("ci api returned %d: %s", resp.StatusCode, truncate(stdout, 500)), resp.StatusCode)
		return fmt.Errorf("ci api returned %d", resp.StatusCode)
	}

	e.MarkSucceeded(0, truncate(stdout, 1024*1024), "")
	return nil
}

type CIResourceParts struct {
	Provider string
	Resource string
}

func ParseCIResource(resource string) (*CIResourceParts, error) {
	resource = strings.TrimPrefix(resource, "ci:")
	parts := strings.SplitN(resource, ":", 2)
	if len(parts) < 2 {
		return nil, fmt.Errorf("resource must be ci:<provider>:<resource>, got: %s", resource)
	}

	return &CIResourceParts{
		Provider: parts[0],
		Resource: parts[1],
	}, nil
}
