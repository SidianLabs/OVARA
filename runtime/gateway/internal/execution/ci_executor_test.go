package execution

import (
	"context"
	"testing"
)

func TestParseCIResource(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantErr  bool
		provider string
		resource string
	}{
		{
			name:     "valid github-actions",
			input:    "ci:github-actions:deploy:acme/api:main",
			wantErr:  false,
			provider: "github-actions",
			resource: "deploy:acme/api:main",
		},
		{
			name:     "valid webhook",
			input:    "ci:webhook:https://hooks.example.com/deploy",
			wantErr:  false,
			provider: "webhook",
			resource: "https://hooks.example.com/deploy",
		},
		{
			name:    "missing provider",
			input:   "ci:deploy",
			wantErr: true,
		},
		{
			name:    "empty",
			input:   "ci:",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parts, err := ParseCIResource(tt.input)
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
			if parts.Provider != tt.provider {
				t.Errorf("provider = %q, want %q", parts.Provider, tt.provider)
			}
		})
	}
}

func TestCIExecutor_Execute_NoProvider(t *testing.T) {
	exec := NewCIExecutor(5)
	e := NewExecution("cnt_test", "dec_test", "", "", "ci.deploy", "ci:github-actions:deploy", 5)
	err := exec.Execute(context.Background(), e)
	if err == nil {
		t.Error("expected error for unregistered provider")
	}
	if e.State != StateFailed {
		t.Errorf("state = %q, want %q", e.State, StateFailed)
	}
}

func TestCIExecutor_Execute_InvalidResource(t *testing.T) {
	exec := NewCIExecutor(5)
	e := NewExecution("cnt_test", "dec_test", "", "", "ci.deploy", "invalid-resource", 5)
	err := exec.Execute(context.Background(), e)
	if err == nil {
		t.Error("expected error for invalid resource")
	}
	if e.State != StateFailed {
		t.Errorf("state = %q, want %q", e.State, StateFailed)
	}
}

func TestCIExecutor_RegisterProvider(t *testing.T) {
	exec := NewCIExecutor(5)
	provider := NewWebhookProvider("https://hooks.example.com", "", 5)
	exec.RegisterProvider(provider)

	types := []string{}
	for name := range exec.Providers {
		types = append(types, name)
	}
	if len(types) != 1 {
		t.Errorf("expected 1 provider, got %d", len(types))
	}
}
