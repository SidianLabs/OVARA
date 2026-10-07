package creds

import (
	"testing"
)

func TestMatchExact(t *testing.T) {
	b := []Binding{
		{Host: "api.github.com", Headers: map[string]string{"Authorization": "tok"}},
	}
	got := Match(b, "api.github.com")
	if got == nil || got["Authorization"] != "tok" {
		t.Fatalf("expected headers for exact match, got %v", got)
	}
	// case-insensitive on both sides
	got = Match(b, "API.GitHub.COM")
	if got == nil {
		t.Fatal("expected case-insensitive match")
	}
}

func TestMatchGlob(t *testing.T) {
	b := []Binding{
		{Host: "*.example.com", Headers: map[string]string{"X-Key": "v"}},
	}
	cases := []struct {
		host string
		want bool
	}{
		{"api.example.com", true},
		{"example.com", false},      // glob requires the leading label + dot
		{"a.b.example.com", true},   // path.Match '*' spans dots (only '/' is separator)
		{"example.com.evil.org", false},
		{"otherexample.com", false},
	}
	for _, c := range cases {
		got := Match(b, c.host)
		if (got != nil) != c.want {
			t.Errorf("host %q: match=%v want %v", c.host, got != nil, c.want)
		}
	}
}

func TestMatchNone(t *testing.T) {
	b := []Binding{{Host: "a.com", Headers: map[string]string{"k": "v"}}}
	if got := Match(b, "b.com"); got != nil {
		t.Fatalf("expected nil, got %v", got)
	}
	if got := Match(nil, "a.com"); got != nil {
		t.Fatalf("expected nil for empty bindings, got %v", got)
	}
}

func TestMatchFirstBindingWins(t *testing.T) {
	b := []Binding{
		{Host: "*.example.com", Headers: map[string]string{"H": "first"}},
		{Host: "api.example.com", Headers: map[string]string{"H": "second"}},
	}
	got := Match(b, "api.example.com")
	if got["H"] != "first" {
		t.Fatalf("expected first-match precedence, got %q", got["H"])
	}
}

func TestLoadEnvExpansion(t *testing.T) {
	t.Setenv("CREDS_TEST_TOKEN", "s3cr3t")
	b := Load([]Binding{
		{Host: "x.com", Headers: map[string]string{
			"Authorization": "Bearer ${CREDS_TEST_TOKEN}",
			"X-Plain":       "literal",
		}},
	})
	h := b[0].Headers
	if h["Authorization"] != "Bearer s3cr3t" {
		t.Fatalf("env expansion failed: %q", h["Authorization"])
	}
	// (A binding with an unset variable is dropped entirely: see
	// TestLoadReport_DropsBindingsWithUnsetKeys.)
	if h["X-Plain"] != "literal" {
		t.Fatalf("literal changed: %q", h["X-Plain"])
	}
}

// A binding whose key is not set must not be injected: it would replace
// the agent's own working header with "Bearer " or an empty key.
func TestLoadReport_DropsBindingsWithUnsetKeys(t *testing.T) {
	t.Setenv("OVARA_TEST_SET", "real")
	t.Setenv("OVARA_TEST_EMPTY", "")
	got, skipped := LoadReport([]Binding{
		{Host: "a.example", Headers: map[string]string{"Authorization": "Bearer ${OVARA_TEST_SET}"}},
		{Host: "b.example", Headers: map[string]string{"Authorization": "Bearer ${OVARA_TEST_EMPTY}"}},
		{Host: "c.example", Headers: map[string]string{"x-api-key": "${OVARA_TEST_UNSET_XYZ}", "v": "1"}},
	})
	if len(got) != 1 || got[0].Host != "a.example" || got[0].Headers["Authorization"] != "Bearer real" {
		t.Fatalf("loaded = %+v", got)
	}
	if len(skipped) != 2 || skipped[0].Host != "b.example" || skipped[1].Missing[0] != "OVARA_TEST_UNSET_XYZ" {
		t.Fatalf("skipped = %+v", skipped)
	}
	if Match(got, "c.example") != nil {
		t.Fatal("binding with unset key must not match")
	}
}
