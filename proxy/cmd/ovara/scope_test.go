package main

import (
	"testing"

	"ovara.proxy/internal/creds"
)

func TestScopeBindings(t *testing.T) {
	in := []creds.Binding{
		{Host: "api.github.com", Headers: map[string]string{"Authorization": "Bearer ghp_aaaaaaaaaaaaaaaa"}},
		{Host: "github.com", Headers: map[string]string{"Authorization": "Basic eDp5eXl5eXl5eXl5"}},
		{Host: "api.anthropic.com", Headers: map[string]string{"x-api-key": "sk-ant-aaaaaaaa"}},
	}
	none, err := scopeBindings(in, scopeRepoNone)
	if err != nil || len(none) != 1 || none[0].Host != "api.anthropic.com" {
		t.Fatalf("none: want only the non-GitHub binding, got %+v (%v)", none, err)
	}
	one, err := scopeBindings(in, "acme/app")
	if err != nil || len(one) != 3 {
		t.Fatalf("acme/app: %+v (%v)", one, err)
	}
	for _, b := range one[:2] {
		if len(b.Paths) == 0 {
			t.Fatalf("GitHub binding for %s not narrowed: %+v", b.Host, b)
		}
	}
	for _, bad := range []string{"*/*", "acme", "acme/app/x", "../x", "acme/a b", ""} {
		if bad == "" {
			continue
		}
		if _, err := scopeBindings(in, bad); err == nil {
			t.Errorf("scope %q accepted", bad)
		}
	}
}
