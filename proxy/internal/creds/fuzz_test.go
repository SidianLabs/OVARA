package creds

import (
	"strings"
	"testing"
)

func hasDotSegment(p string) bool {
	for _, seg := range strings.Split(p, "/") {
		if seg == "." || seg == ".." {
			return true
		}
	}
	return false
}

// A credential scoped to one repository is sent only with requests about
// that repository, whatever path the agent asks for and whatever owner and
// repo the scope was given; a path with "." or ".." segments never gets a
// credential from a binding that names paths.
func FuzzScopeToRepo(f *testing.F) {
	f.Add("acme", "app", "/repos/acme/app/pulls", "", "GET")
	f.Add("acme", "app", "/repos/acme/app-evil/pulls", "", "GET")
	f.Add("acme", "app", "/repos/acme/app/../other/pulls", "", "GET")
	f.Add("acme", "app", "/repos/acme/other", "/repos/acme/*", "POST")
	f.Add("acme", "*", "/repos/acme/other", "", "GET")
	f.Add("*", "*", "/repos/evil/x", "", "GET")
	f.Add("acme/app", "x", "/repos/acme/app/x", "", "GET")
	f.Add("acme", "..", "/repos/acme/../x", "", "GET")
	f.Add("acme", "app", "/acme/app.git/info/refs", "", "GET")
	f.Add("acme", "app", "/acme/app/./x", "/acme/app/*", "GET")
	f.Fuzz(func(t *testing.T, owner, repo, reqPath, boundPath, method string) {
		var paths []string
		if boundPath != "" {
			paths = []string{boundPath}
		}
		hdr := map[string]string{"Authorization": "Bearer t"}
		bindings := []Binding{
			{Host: "api.github.com", Paths: paths, Headers: hdr},
			{Host: "github.com", Paths: paths, Headers: hdr},
			{Host: "other.example", Headers: map[string]string{"X-Key": "k"}},
		}
		scoped := bindings
		for _, h := range []string{"api.github.com", "github.com"} {
			scoped = ScopeToRepo(scoped, h, owner, repo)
		}
		if MatchRequest(scoped, Request{Host: "other.example", Path: reqPath}) == nil {
			t.Fatalf("scoping GitHub dropped another host's binding")
		}
		valid := RepoName(owner) && RepoName(repo)
		inTree := func(p string, roots ...string) bool {
			for _, r := range roots {
				if p == r || strings.HasPrefix(p, r+"/") {
					return true
				}
			}
			return false
		}
		if MatchRequest(scoped, Request{Host: "api.github.com", Method: method, Path: reqPath}) != nil {
			if !valid || hasDotSegment(reqPath) || !inTree(reqPath, "/repos/"+owner+"/"+repo) {
				t.Fatalf("scope %q/%q sent the key with api.github.com%s", owner, repo, reqPath)
			}
		}
		if MatchRequest(scoped, Request{Host: "github.com", Method: method, Path: reqPath}) != nil {
			if !valid || hasDotSegment(reqPath) || !inTree(reqPath, "/"+owner+"/"+repo, "/"+owner+"/"+repo+".git") {
				t.Fatalf("scope %q/%q sent the key with github.com%s", owner, repo, reqPath)
			}
		}
		// Unscoped bindings that name paths refuse dot segments too.
		if boundPath != "" && hasDotSegment(reqPath) && MatchRequest(bindings, Request{Host: "api.github.com", Method: method, Path: reqPath}) != nil {
			t.Fatalf("path %q with a dot segment matched %q", reqPath, boundPath)
		}
	})
}
