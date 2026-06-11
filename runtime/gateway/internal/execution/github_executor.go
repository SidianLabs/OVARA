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

type GitHubExecutor struct {
	Token     string
	BaseURL   string
	Timeout   time.Duration
	Client    *http.Client
}

func NewGitHubExecutor(token string, timeoutSec int) *GitHubExecutor {
	if timeoutSec <= 0 {
		timeoutSec = 30
	}
	return &GitHubExecutor{
		Token:   token,
		BaseURL: "https://api.github.com",
		Timeout: time.Duration(timeoutSec) * time.Second,
		Client: &http.Client{
			Timeout: time.Duration(timeoutSec) * time.Second,
		},
	}
}

func (g *GitHubExecutor) Execute(ctx context.Context, e *Execution) error {
	e.MarkStarted()

	parts, err := ParseGitHubResource(e.Resource)
	if err != nil {
		e.MarkFailed("invalid github resource: "+err.Error(), 1)
		return err
	}

	var resp *http.Response
	var apiErr error

	switch e.ActionType {
	case "github.push":
		resp, apiErr = g.createPushEvent(ctx, parts)
	case "github.pr":
		resp, apiErr = g.createPullRequest(ctx, parts)
	case "github.merge":
		resp, apiErr = g.mergePullRequest(ctx, parts)
	case "github.delete_branch":
		resp, apiErr = g.deleteBranch(ctx, parts)
	default:
		e.MarkFailed("unsupported github action: "+e.ActionType, 1)
		return fmt.Errorf("unsupported github action: %s", e.ActionType)
	}

	if apiErr != nil {
		e.MarkFailed("github api error: "+apiErr.Error(), 1)
		return apiErr
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	stdout := string(body)

	if resp.StatusCode >= 400 {
		e.MarkFailed(fmt.Sprintf("github api returned %d: %s", resp.StatusCode, truncate(stdout, 500)), resp.StatusCode)
		return fmt.Errorf("github api returned %d", resp.StatusCode)
	}

	e.MarkSucceeded(0, truncate(stdout, 1024*1024), "")
	return nil
}

type GitHubParts struct {
	Owner  string
	Repo   string
	Action string
	Ref    string
	Title  string
	Body   string
}

func ParseGitHubResource(resource string) (*GitHubParts, error) {
	resource = strings.TrimPrefix(resource, "github:")
	parts := strings.SplitN(resource, ":", 3)
	if len(parts) < 2 {
		return nil, fmt.Errorf("resource must be github:<owner>/<repo>:<action>, got: %s", resource)
	}

	repoParts := strings.SplitN(parts[0], "/", 2)
	if len(repoParts) != 2 {
		return nil, fmt.Errorf("repo must be <owner>/<repo>, got: %s", parts[0])
	}

	result := &GitHubParts{
		Owner:  repoParts[0],
		Repo:   repoParts[1],
		Action: parts[1],
	}

	if len(parts) > 2 {
		extra := strings.SplitN(parts[2], "|", 2)
		result.Ref = extra[0]
		if len(extra) > 1 {
			result.Title = extra[1]
		}
	}

	return result, nil
}

func (g *GitHubExecutor) createPushEvent(ctx context.Context, parts *GitHubParts) (*http.Response, error) {
	url := fmt.Sprintf("%s/repos/%s/%s/dispatches", g.BaseURL, parts.Owner, parts.Repo)
	payload := map[string]interface{}{
		"event_type": "ovara_push",
		"client_payload": map[string]string{
			"ref":    parts.Ref,
			"action": "push",
		},
	}
	return g.doRequest(ctx, "POST", url, payload)
}

func (g *GitHubExecutor) createPullRequest(ctx context.Context, parts *GitHubParts) (*http.Response, error) {
	url := fmt.Sprintf("%s/repos/%s/%s/pulls", g.BaseURL, parts.Owner, parts.Repo)
	title := parts.Title
	if title == "" {
		title = "Ovara-initiated pull request"
	}
	payload := map[string]interface{}{
		"title": title,
		"head":  parts.Ref,
		"base":  "main",
		"body":  fmt.Sprintf("Automated PR created by Ovara Runtime Gateway"),
	}
	return g.doRequest(ctx, "POST", url, payload)
}

func (g *GitHubExecutor) mergePullRequest(ctx context.Context, parts *GitHubParts) (*http.Response, error) {
	prNumber := parts.Ref
	if prNumber == "" {
		return nil, fmt.Errorf("pr number required for merge action")
	}
	url := fmt.Sprintf("%s/repos/%s/%s/pulls/%s/merge", g.BaseURL, parts.Owner, parts.Repo, prNumber)
	payload := map[string]interface{}{
		"commit_title": fmt.Sprintf("Merge PR #%s via Ovara", prNumber),
	}
	return g.doRequest(ctx, "PUT", url, payload)
}

func (g *GitHubExecutor) deleteBranch(ctx context.Context, parts *GitHubParts) (*http.Response, error) {
	branch := parts.Ref
	if branch == "" {
		return nil, fmt.Errorf("branch name required for delete_branch action")
	}
	url := fmt.Sprintf("%s/repos/%s/%s/git/refs/heads/%s", g.BaseURL, parts.Owner, parts.Repo, branch)
	req, err := http.NewRequestWithContext(ctx, "DELETE", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+g.Token)
	req.Header.Set("Accept", "application/vnd.github+json")
	return g.Client.Do(req)
}

func (g *GitHubExecutor) doRequest(ctx context.Context, method, url string, payload interface{}) (*http.Response, error) {
	var body io.Reader
	if payload != nil {
		data, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+g.Token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	return g.Client.Do(req)
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "...(truncated)"
}
