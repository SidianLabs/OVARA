package execution

import (
	"context"
	"testing"
)

func TestParseGitHubResource(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
		owner   string
		repo    string
		action  string
	}{
		{
			name:    "valid push",
			input:   "github:acme/api:create_pr",
			wantErr: false,
			owner:   "acme",
			repo:    "api",
			action:  "create_pr",
		},
		{
			name:    "valid with ref",
			input:   "github:acme/api:delete_branch:feature-x",
			wantErr: false,
			owner:   "acme",
			repo:    "api",
			action:  "delete_branch",
		},
		{
			name:    "missing repo",
			input:   "github:acme:",
			wantErr: true,
		},
		{
			name:    "missing owner",
			input:   "github:api:create_pr",
			wantErr: true,
		},
		{
			name:    "no action",
			input:   "github:acme/api",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parts, err := ParseGitHubResource(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if parts.Owner != tt.owner {
				t.Errorf("owner = %q, want %q", parts.Owner, tt.owner)
			}
			if parts.Repo != tt.repo {
				t.Errorf("repo = %q, want %q", parts.Repo, tt.repo)
			}
			if parts.Action != tt.action {
				t.Errorf("action = %q, want %q", parts.Action, tt.action)
			}
		})
	}
}

func TestGitHubExecutor_Execute_NoToken(t *testing.T) {
	exec := NewGitHubExecutor("", 5)
	e := NewExecution("cnt_test", "dec_test", "", "", "github.push", "github:acme/api:create_pr", 5)
	err := exec.Execute(context.Background(), e)
	if err == nil {
		t.Error("expected error for missing token")
	}
	if e.State != StateFailed {
		t.Errorf("state = %q, want %q", e.State, StateFailed)
	}
}

func TestGitHubExecutor_Execute_InvalidResource(t *testing.T) {
	exec := NewGitHubExecutor("test-token", 5)
	e := NewExecution("cnt_test", "dec_test", "", "", "github.push", "invalid-resource", 5)
	err := exec.Execute(context.Background(), e)
	if err == nil {
		t.Error("expected error for invalid resource")
	}
	if e.State != StateFailed {
		t.Errorf("state = %q, want %q", e.State, StateFailed)
	}
}

func TestGitHubExecutor_Execute_UnsupportedAction(t *testing.T) {
	exec := NewGitHubExecutor("test-token", 5)
	e := NewExecution("cnt_test", "dec_test", "", "", "github.unknown", "github:acme/api:action", 5)
	err := exec.Execute(context.Background(), e)
	if err == nil {
		t.Error("expected error for unsupported action")
	}
	if e.State != StateFailed {
		t.Errorf("state = %q, want %q", e.State, StateFailed)
	}
}

func TestGitHubExecutor_DeleteBranch_NoRef(t *testing.T) {
	exec := NewGitHubExecutor("test-token", 5)
	e := NewExecution("cnt_test", "dec_test", "", "", "github.delete_branch", "github:acme/api:delete_branch:", 5)
	err := exec.Execute(context.Background(), e)
	if err == nil {
		t.Error("expected error for missing branch ref")
	}
}

func TestTruncate(t *testing.T) {
	short := "hello"
	if truncate(short, 10) != short {
		t.Errorf("truncate short string failed")
	}
	long := "hello world this is a very long string"
	truncated := truncate(long, 10)
	if len(truncated) != 24 { // 10 + "...(truncated)"
		t.Errorf("truncated length = %d, want 24", len(truncated))
	}
}
