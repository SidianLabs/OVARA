package creds

import (
	"reflect"
	"strings"
	"testing"
)

func TestMatchRequest_PathsAndMethods(t *testing.T) {
	b := []Binding{{
		Host:    "api.github.com",
		Paths:   []string{"/repos/acme/app", "/repos/acme/app/*"},
		Methods: []string{"GET", "post"},
		Headers: map[string]string{"Authorization": "tok"},
	}}
	cases := []struct {
		method, path string
		want         bool
	}{
		{"GET", "/repos/acme/app", true},
		{"GET", "/repos/acme/app/pulls/1", true},
		{"POST", "/repos/acme/app/issues", true},
		{"DELETE", "/repos/acme/app", false},
		{"GET", "/repos/acme/app-other", false},
		{"GET", "/repos/acme/other/contents/x", false},
		{"GET", "/user", false},
		{"GET", "/repos/acme/app/../../other/secrets", false},
		{"GET", "/repos/acme/app/./x", false},
		{"", "/repos/acme/app", false},
	}
	for _, c := range cases {
		got := MatchRequest(b, Request{Host: "api.github.com", Method: c.method, Path: c.path}) != nil
		if got != c.want {
			t.Errorf("%s %s: match=%v want %v", c.method, c.path, got, c.want)
		}
	}
	// Host-only Match never picks a binding that is narrowed.
	if Match(b, "api.github.com") != nil {
		t.Error("Match without a path must not use a path-scoped binding")
	}
}

// A binding with no port matches port 443 only; one with a port, only that.
func TestMatchRequest_Port(t *testing.T) {
	b := []Binding{
		{Host: "api.example.com", Headers: map[string]string{"H": "a"}},
		{Host: "*.example.org:8443", Headers: map[string]string{"H": "b"}},
	}
	for _, c := range []struct {
		host, port string
		want       string
	}{
		{"api.example.com", "", "a"},
		{"api.example.com", "443", "a"},
		{"api.example.com", "8443", ""},
		{"api.example.com", "80", ""},
		{"x.example.org", "8443", "b"},
		{"x.example.org", "443", ""},
	} {
		got := MatchRequest(b, Request{Host: c.host, Port: c.port, Method: "GET", Path: "/"})
		if (got == nil && c.want != "") || (got != nil && got["H"] != c.want) {
			t.Errorf("%s:%s -> %v, want %q", c.host, c.port, got, c.want)
		}
	}
}

func TestScopeToRepo(t *testing.T) {
	in := []Binding{
		{Host: "api.github.com", Headers: map[string]string{"Authorization": "Bearer t"}},
		{Host: "github.com", Headers: map[string]string{"Authorization": "Basic x"}},
		{Host: "api.openai.com", Headers: map[string]string{"Authorization": "Bearer o"}},
	}
	out := ScopeToRepo(in, "api.github.com", "acme", "app")
	if len(in[0].Paths) != 0 {
		t.Fatal("input was modified")
	}
	if want := []string{"/repos/acme/app", "/repos/acme/app/*"}; !reflect.DeepEqual(out[0].Paths, want) {
		t.Fatalf("api paths = %v, want %v", out[0].Paths, want)
	}
	if out[1].Paths != nil || out[2].Paths != nil {
		t.Fatal("other hosts must be unchanged")
	}
	req := func(p string) Request { return Request{Host: "api.github.com", Method: "GET", Path: p} }
	if MatchRequest(out, req("/repos/acme/app/contents/README.md")) == nil {
		t.Error("project repo must get the token")
	}
	for _, p := range []string{"/repos/acme/other", "/user/repos", "/graphql", "/gists", "/repos/acme/app2"} {
		if MatchRequest(out, req(p)) != nil {
			t.Errorf("%s must not get the token", p)
		}
	}

	git := ScopeToRepo(in, "github.com", "acme", "app")
	if want := []string{"/acme/app", "/acme/app/*", "/acme/app.git", "/acme/app.git/*"}; !reflect.DeepEqual(git[1].Paths, want) {
		t.Fatalf("git paths = %v", git[1].Paths)
	}

	// Existing paths are intersected, never widened.
	narrowed := []Binding{{Host: "api.github.com", Paths: []string{"/repos/acme/app/issues*", "/repos/*", "/user"}, Headers: map[string]string{"A": "b"}}}
	got := ScopeToRepo(narrowed, "api.github.com", "acme", "app")
	if len(got) != 1 || !reflect.DeepEqual(got[0].Paths, []string{"/repos/acme/app/issues*"}) {
		t.Fatalf("intersected = %+v", got)
	}
	disjoint := []Binding{{Host: "api.github.com", Paths: []string{"/user"}, Headers: map[string]string{"A": "b"}}}
	if got := ScopeToRepo(disjoint, "api.github.com", "acme", "app"); len(got) != 0 {
		t.Fatalf("a binding with no path left must be dropped, got %+v", got)
	}
}

// Found by FuzzScopeToRepo: an owner or repo of "*" made the scope a glob
// over every repository ("/repos/*/*"), and one with a '/' moved the
// scope's boundary. Such a scope now drops the host's bindings instead.
func TestScopeToRepo_RefusesNamesThatAreNotNames(t *testing.T) {
	in := []Binding{
		{Host: "api.github.com", Headers: map[string]string{"Authorization": "Bearer t"}},
		{Host: "api.openai.com", Headers: map[string]string{"Authorization": "Bearer o"}},
	}
	for _, c := range [][2]string{{"*", "*"}, {"acme", "*"}, {"acme/app", "x"}, {"acme", ".."}, {"", "app"}, {"acme", "app x"}} {
		out := ScopeToRepo(in, "api.github.com", c[0], c[1])
		if len(out) != 1 || out[0].Host != "api.openai.com" {
			t.Errorf("scope %q/%q kept %+v", c[0], c[1], out)
		}
		if MatchRequest(out, Request{Host: "api.github.com", Method: "GET", Path: "/repos/evil/x"}) != nil {
			t.Errorf("scope %q/%q sends the key to another repository", c[0], c[1])
		}
	}
}

// CR-11: a secret too short to scrub is refused, not silently injected.
func TestLoadReport_RefusesShortSecrets(t *testing.T) {
	t.Setenv("OVARA_TEST_SHORT", "abc")
	t.Setenv("OVARA_TEST_LONG", "abcdefgh12345")
	got, _, err := LoadReport([]Binding{
		{Host: "a.example", Headers: map[string]string{"Authorization": "Bearer ${OVARA_TEST_SHORT}"}},
		{Host: "b.example", Headers: map[string]string{"x-api-key": "${OVARA_TEST_LONG}", "anthropic-version": "${OVARA_TEST_SHORT}"}},
	})
	if err == nil || !strings.Contains(err.Error(), "a.example") || !strings.Contains(err.Error(), "OVARA_TEST_SHORT") {
		t.Fatalf("err = %v", err)
	}
	if len(got) != 1 || got[0].Host != "b.example" {
		t.Fatalf("loaded = %+v (a non-secret header may be short)", got)
	}
}

func TestLoadReport_RejectsBadPatterns(t *testing.T) {
	if _, _, err := LoadReport([]Binding{{Host: "a.example", Paths: []string{"repos/x"}, Headers: map[string]string{"h": "v"}}}); err == nil {
		t.Error("a path without a leading slash must be refused")
	}
	if _, _, err := LoadReport([]Binding{{Host: "[", Headers: map[string]string{"h": "v"}}}); err == nil {
		t.Error("a malformed host glob must be refused")
	}
}

func TestNonSecretHeaderExactNames(t *testing.T) {
	for _, n := range []string{"anthropic-version", "Content-Type", "accept", "User-Agent"} {
		if !NonSecretHeader(n) {
			t.Errorf("%s should be non-secret", n)
		}
	}
	for _, n := range []string{"X-Api-Version-Key", "x-version-token", "Authorization"} {
		if NonSecretHeader(n) {
			t.Errorf("%s must be treated as a secret", n)
		}
	}
}
