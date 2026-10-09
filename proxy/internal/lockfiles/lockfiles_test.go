package lockfiles

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func put(t *testing.T, dir, rel, content string) {
	t.Helper()
	p := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestScan(t *testing.T) {
	d := t.TempDir()
	put(t, d, "package-lock.json", `{"lockfileVersion":3,"packages":{
	  "":{"name":"app","version":"1.0.0"},
	  "node_modules/left-pad":{"version":"1.3.0"},
	  "node_modules/@types/node":{"version":"20.1.0"},
	  "node_modules/a/node_modules/b":{"version":"2.0.0"},
	  "node_modules/alias":{"name":"real-pkg","version":"3.1.0"},
	  "node_modules/linked":{"link":true}}}`)
	put(t, d, "old/package-lock.json", `{"lockfileVersion":1,"dependencies":{
	  "x":{"version":"1.0.0","dependencies":{"y":{"version":"2.0.0"}}},
	  "gitdep":{"version":"git+https://example.org/x.git"}}}`)
	put(t, d, "web/yarn.lock", "# yarn lockfile v1\n\n\"lodash@^4.17.0\", lodash@^4.17.21:\n  version \"4.17.21\"\n  resolved \"https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz\"\n\n\"@babel/core@^7.0.0\":\n  version \"7.24.0\"\n")
	put(t, d, "berry/yarn.lock", "__metadata:\n  version: 8\n\n\"chalk@npm:^5.0.0\":\n  version: 5.3.0\n")
	put(t, d, "p/pnpm-lock.yaml", "lockfileVersion: '9.0'\n\npackages:\n\n  is-odd@3.0.1:\n    resolution: {integrity: x}\n\n  '@scope/pkg@1.0.0':\n    resolution: {integrity: x}\n\nsnapshots:\n\n  react-dom@18.2.0(react@18.2.0):\n    dependencies: {}\n")
	put(t, d, "p5/pnpm-lock.yaml", "lockfileVersion: 5.4\npackages:\n  /ms/2.1.3:\n    resolution: {integrity: x}\n")
	put(t, d, "requirements.txt", "# pins\nDjango==4.2.1\nrequests[socks] == 2.31.0 ; python_version > '3.8'\nflask>=2\n-e .\nzope.interface===6.0\n")
	put(t, d, "poetry.lock", "[[package]]\nname = \"Typing_Extensions\"\nversion = \"4.9.0\"\n\n[package.dependencies]\nfoo = \">=1\"\n\n[[package]]\nname = \"idna\"\nversion = \"3.7\"\n\n[metadata]\nlock-version = \"2.0\"\n")
	put(t, d, "Pipfile.lock", `{"default":{"six":{"version":"==1.16.0"}},"develop":{"pytest":{"version":"==8.0.0"},"local":{"path":"."}}}`)
	put(t, d, "go.sum", "golang.org/x/sys v0.20.0 h1:abc=\ngolang.org/x/sys v0.20.0/go.mod h1:def=\n")
	put(t, d, "rs/Cargo.lock", "version = 3\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.200\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n")
	// a dependency's own lockfile is not the project's
	put(t, d, "node_modules/evil/package-lock.json", `{"packages":{"node_modules/backdoor":{"version":"6.6.6"}}}`)

	refs, files := Scan(d)
	have := map[string]bool{}
	for _, r := range refs {
		have[r] = true
	}
	want := []string{
		"npm:left-pad@1.3.0", "npm:@types/node@20.1.0", "npm:b@2.0.0", "npm:real-pkg@3.1.0",
		"npm:x@1.0.0", "npm:y@2.0.0",
		"npm:lodash@4.17.21", "npm:@babel/core@7.24.0", "npm:chalk@5.3.0",
		"npm:is-odd@3.0.1", "npm:@scope/pkg@1.0.0", "npm:react-dom@18.2.0", "npm:ms@2.1.3",
		"pypi:django@4.2.1", "pypi:requests@2.31.0", "pypi:zope-interface@6.0",
		"pypi:typing-extensions@4.9.0", "pypi:idna@3.7", "pypi:six@1.16.0", "pypi:pytest@8.0.0",
		"go:golang.org/x/sys@v0.20.0", "crate:serde@1.0.200",
	}
	for _, w := range want {
		if !have[w] {
			t.Errorf("missing %s (got %v)", w, refs)
		}
	}
	for _, bad := range []string{"npm:backdoor@6.6.6", "npm:alias@3.1.0", "npm:gitdep@git+https://example.org/x.git", "pypi:flask@2"} {
		if have[bad] {
			t.Errorf("should not have %s", bad)
		}
	}
	if strings.Join(files, ",") != "Pipfile.lock,berry/yarn.lock,go.sum,old/package-lock.json,p/pnpm-lock.yaml,p5/pnpm-lock.yaml,package-lock.json,poetry.lock,requirements.txt,rs/Cargo.lock,web/yarn.lock" {
		t.Errorf("files = %v", files)
	}
}

func TestDownload(t *testing.T) {
	cases := map[string]string{
		"registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz":                                      "npm:left-pad@1.3.0",
		"registry.npmjs.org/@types/node/-/node-20.1.0.tgz":                                      "npm:@types/node@20.1.0",
		"registry.npmjs.org/@types%2fnode/-/node-20.1.0.tgz":                                    "npm:@types/node@20.1.0",
		"REGISTRY.NPMJS.ORG./is-number/-/is-number-7.0.0-beta.1.tgz":                            "npm:is-number@7.0.0-beta.1",
		"registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz":                                      "npm:lodash@4.17.21",
		"files.pythonhosted.org/packages/d9/5a/e7/six-1.16.0-py2.py3-none-any.whl":              "pypi:six@1.16.0",
		"files.pythonhosted.org/packages/ab/cd/Django-4.2.tar.gz":                               "pypi:django@4.2",
		"files.pythonhosted.org/packages/ab/cd/zope.interface-6.0-cp311-cp311-linux_x86_64.whl": "pypi:zope-interface@6.0",
		"proxy.golang.org/github.com/!burnt!sushi/toml/@v/v1.3.2.zip":                           "go:github.com/BurntSushi/toml@v1.3.2",
		"static.crates.io/crates/serde/serde-1.0.200.crate":                                     "crate:serde@1.0.200",
	}
	for in, want := range cases {
		host, path, _ := strings.Cut(in, "/")
		got, ok := Download(host, "/"+path)
		if !ok || got != want {
			t.Errorf("%s: got %q %v, want %q", in, got, ok, want)
		}
	}
	not := []string{
		"registry.npmjs.org/left-pad",                                   // packument
		"registry.npmjs.org/-/npm/v1/security/advisories/bulk",          // audit
		"registry.npmjs.org/left-pad/-/other-1.0.0.tgz",                 // name mismatch
		"registry.npmjs.org/a/b/c/-/c-1.0.0.tgz",                        // not a package path
		"pypi.org/simple/six/",                                          // index page
		"files.pythonhosted.org/packages/ab/cd/six-1.16.0.whl.metadata", // metadata
		"proxy.golang.org/golang.org/x/sys/@v/v0.20.0.info",             // metadata
		"proxy.golang.org/golang.org/x/sys/@v/list",                     // metadata
		"example.org/left-pad/-/left-pad-1.3.0.tgz",                     // not a pinned registry
	}
	for _, in := range not {
		host, path, _ := strings.Cut(in, "/")
		if got, ok := Download(host, "/"+path); ok {
			t.Errorf("%s named %q", in, got)
		}
	}
}
