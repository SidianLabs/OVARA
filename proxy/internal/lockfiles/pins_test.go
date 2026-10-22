package lockfiles

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

func TestClassify(t *testing.T) {
	cases := map[string]struct {
		kind Kind
		ref  string
	}{
		"rubygems.org/gems/rails-7.1.0.gem":                                                         {Artifact, "gem:rails@7.1.0"},
		"rubygems.org/downloads/nokogiri-1.15.4-x86_64-linux.gem":                                   {Artifact, "gem:nokogiri@1.15.4-x86_64-linux"},
		"rubygems.org/gems/net-http-persistent-4.0.2.gem":                                           {Artifact, "gem:net-http-persistent@4.0.2"},
		"rubygems.org/info/rails":                                                                   {Metadata, ""},
		"rubygems.org/api/v1/dependencies":                                                          {Metadata, ""},
		"rubygems.org/specs.4.8.gz":                                                                 {Metadata, ""},
		"rubygems.org/gems/rails":                                                                   {Metadata, ""},
		"rubygems.org/quick/Marshal.4.8/rails-7.1.0.gemspec.rz":                                     {Metadata, ""},
		"rubygems.org/somewhere/else.tar":                                                           {Unrecognised, ""},
		"repo1.maven.org/maven2/org/slf4j/slf4j-api/2.0.9/slf4j-api-2.0.9.jar":                      {Artifact, "maven:org.slf4j:slf4j-api@2.0.9"},
		"repo.maven.apache.org/maven2/junit/junit/4.13.2/junit-4.13.2.pom":                          {Artifact, "maven:junit:junit@4.13.2"},
		"repo1.maven.org/maven2/a/b/c/1.0/c-1.0-sources.jar":                                        {Artifact, "maven:a.b:c@1.0"},
		"repo1.maven.org/maven2/junit/junit/maven-metadata.xml":                                     {Metadata, ""},
		"repo1.maven.org/maven2/junit/junit/4.13.2/junit-4.13.2.jar.sha1":                           {Metadata, ""},
		"repo1.maven.org/maven2/junit/junit/4.13.2/evil.jar":                                        {Unrecognised, ""},
		"crates.io/api/v1/crates/serde/1.0.200/download":                                            {Artifact, "crate:serde@1.0.200"},
		"crates.io/api/v1/crates/serde":                                                             {Metadata, ""},
		"index.crates.io/se/rd/serde":                                                               {Metadata, ""},
		"index.crates.io/config.json":                                                               {Metadata, ""},
		"index.crates.io/x/y/z/w":                                                                   {Unrecognised, ""},
		"static.crates.io/other/thing":                                                              {Unrecognised, ""},
		"registry.npmjs.org/left-pad":                                                               {Metadata, ""},
		"registry.npmjs.org/-/v1/search":                                                            {Metadata, ""},
		"registry.npmjs.org/left-pad/-/payload.bin":                                                 {Unrecognised, ""},
		"files.pythonhosted.org/packages/ab/cd/six-1.16.0.whl.metadata":                             {Metadata, ""},
		"files.pythonhosted.org/packages/ab/cd/six-1.16.0.exe":                                      {Unrecognised, ""},
		"proxy.golang.org/golang.org/x/sys/@v/v0.20.0.info":                                         {Metadata, ""},
		"proxy.golang.org/sumdb/sum.golang.org/supported":                                           {Metadata, ""},
		"proxy.golang.org/golang.org/x/sys/@v/v0.20.0.tar":                                          {Unrecognised, ""},
		"example.org/gems/rails-7.1.0.gem":                                                          {NotRegistry, ""},
		"api.github.com/repos/Laravel-Lang/lang/zipball/0123456789abcdef0123456789abcdef01234567":   {Artifact, "github:laravel-lang/lang@0123456789abcdef0123456789abcdef01234567"},
		"api.github.com/repos/a/b/tarball/v1.2.0":                                                   {Artifact, "github:a/b@v1.2.0"},
		"codeload.github.com/laravel-lang/lang/legacy.zip/0123456789abcdef0123456789abcdef01234567": {Artifact, "github:laravel-lang/lang@0123456789abcdef0123456789abcdef01234567"},
		"codeload.github.com/a/b/zip/refs/tags/v1.2.0":                                              {Artifact, "github:a/b@refs/tags/v1.2.0"},
		"codeload.github.com/a/b/other/x":                                                           {Unrecognised, ""},
		"api.github.com/repos/a/b/pulls":                                                            {NotRegistry, ""},
		"api.github.com/user":                                                                       {NotRegistry, ""},
		"repo.packagist.org/p2/laravel/framework.json":                                              {Metadata, ""},
	}
	for in, want := range cases {
		host, path, _ := strings.Cut(in, "/")
		k, ref := Classify(host, "/"+path)
		if k != want.kind || ref != want.ref {
			t.Errorf("%s: got %v %q, want %v %q", in, k, ref, want.kind, want.ref)
		}
	}
}

func TestScanPinsDigests(t *testing.T) {
	d := t.TempDir()
	sha512a := "sha512-" + strings.Repeat("A", 86) + "=="
	put(t, d, "package-lock.json", `{"lockfileVersion":3,"packages":{"node_modules/left-pad":{"version":"1.3.0","integrity":"`+sha512a+`"}}}`)
	put(t, d, "y/yarn.lock", "lodash@^4.17.21:\n  version \"4.17.21\"\n  integrity "+sha512a+"\n")
	put(t, d, "p/pnpm-lock.yaml", "packages:\n\n  is-odd@3.0.1:\n    resolution: {integrity: "+sha512a+"}\n")
	hexA := strings.Repeat("ab", 32)
	put(t, d, "requirements.txt", "six==1.16.0 \\\n    --hash=sha256:"+hexA+" \\\n    --hash=sha256:"+strings.Repeat("cd", 32)+"\nidna==3.7\n")
	put(t, d, "rs/Cargo.lock", "[[package]]\nname = \"serde\"\nversion = \"1.0.200\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \""+hexA+"\"\n")
	put(t, d, "poetry.lock", "[[package]]\nname = \"idna\"\nversion = \"3.7\"\nfiles = [\n    {file = \"idna-3.7.whl\", hash = \"sha256:"+hexA+"\"},\n]\n\n[package.dependencies]\nx = \"1\"\n")
	put(t, d, "rb/Gemfile.lock", "GEM\n  remote: https://rubygems.org/\n  specs:\n    rails (7.1.0)\n      actionpack (= 7.1.0)\n    nokogiri (1.15.4-x86_64-linux)\n\nPLATFORMS\n  x86_64-linux\n")
	put(t, d, "g/gradle.lockfile", "# comment\norg.slf4j:slf4j-api:2.0.9=compileClasspath\nempty=\n")
	pins, _ := ScanPins(d)
	raw, _ := hex.DecodeString(hexA)
	sriA := "sha256-" + base64.StdEncoding.EncodeToString(raw)
	want := map[string]string{
		"npm:left-pad@1.3.0": sha512a, "npm:lodash@4.17.21": sha512a, "npm:is-odd@3.0.1": sha512a,
		"pypi:six@1.16.0": sriA, "crate:serde@1.0.200": sriA, "pypi:idna@3.7": sriA,
	}
	for ref, dg := range want {
		if !contains(pins[ref], dg) {
			t.Errorf("%s: digests %v, want %s", ref, pins[ref], dg)
		}
	}
	if len(pins["pypi:six@1.16.0"]) != 2 {
		t.Errorf("six: %v", pins["pypi:six@1.16.0"])
	}
	for _, ref := range []string{"gem:rails@7.1.0", "gem:nokogiri@1.15.4-x86_64-linux", "maven:org.slf4j:slf4j-api@2.0.9"} {
		if _, ok := pins[ref]; !ok {
			t.Errorf("missing %s", ref)
		}
	}
	if _, ok := pins["gem:actionpack@7.1.0"]; ok {
		t.Error("a dependency constraint read as a pin")
	}
	// the file the proxy reads says the same
	back := ParsePins(FormatPins(pins))
	if len(back) != len(pins) || !contains(back["pypi:six@1.16.0"], sriA) {
		t.Errorf("round trip: %v", back)
	}
	if old := ParsePins("npm:a@1\nnpm:b@2\n"); len(old) != 2 || len(old["npm:a@1"]) != 0 {
		t.Errorf("bare refs: %v", old)
	}
}
