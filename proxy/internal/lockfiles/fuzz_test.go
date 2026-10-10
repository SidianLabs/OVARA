package lockfiles

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var refShape = regexp.MustCompile(`^(npm|pypi|go|crate):.+@.+$`)

// A download URL is agent-controlled: naming it must never panic, and a name
// it does give is always ecosystem:name@version.
func FuzzDownload(f *testing.F) {
	for _, s := range []string{
		"/left-pad/-/left-pad-1.3.0.tgz", "/@types/node/-/node-20.1.0.tgz", "/@a%2fb/-/b-1.tgz",
		"/packages/ab/cd/six-1.16.0-py2.py3-none-any.whl", "/packages/x/Django-4.2.tar.gz",
		"/github.com/!a/b/@v/v1.0.0.zip", "/crates/serde/serde-1.0.200.crate", "/-/", "/%zz",
	} {
		for _, h := range []string{"registry.npmjs.org", "files.pythonhosted.org", "proxy.golang.org", "static.crates.io"} {
			f.Add(h, s)
		}
	}
	f.Fuzz(func(t *testing.T, host, path string) {
		ref, ok := Download(host, path)
		if ok && !refShape.MatchString(ref) {
			t.Fatalf("Download(%q, %q) = %q: not ecosystem:name@version", host, path, ref)
		}
	})
}

// A lockfile is project content the agent may have written: reading any
// bytes under any lockfile name must never panic, and every ref has the
// ecosystem:name@version shape.
func FuzzScan(f *testing.F) {
	f.Add("package-lock.json", `{"packages":{"node_modules/a":{"version":"1.0.0"}}}`)
	f.Add("yarn.lock", "\"a@^1\":\n  version \"1.0.0\"\n")
	f.Add("pnpm-lock.yaml", "packages:\n  a@1.0.0:\n    x: y\n")
	f.Add("requirements.txt", "a==1.0\n")
	f.Add("poetry.lock", "[[package]]\nname = \"a\"\nversion = \"1\"\n")
	f.Add("Pipfile.lock", `{"default":{"a":{"version":"==1"}}}`)
	f.Add("go.sum", "a v1 h1:x\n")
	f.Add("Cargo.lock", "[[package]]\nname = \"a\"\nversion = \"1\"\n")
	names := []string{"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "requirements.txt", "poetry.lock", "uv.lock", "Pipfile.lock", "go.sum", "Cargo.lock"}
	f.Fuzz(func(t *testing.T, name, content string) {
		ok := false
		for _, n := range names {
			ok = ok || n == name
		}
		if !ok {
			name = names[len(content)%len(names)]
		}
		d := t.TempDir()
		if err := os.WriteFile(filepath.Join(d, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		refs, _ := Scan(d)
		for _, r := range refs {
			if !refShape.MatchString(r) || strings.ContainsAny(r, "\n\r") {
				t.Fatalf("%s: bad ref %q", name, r)
			}
		}
	})
}
