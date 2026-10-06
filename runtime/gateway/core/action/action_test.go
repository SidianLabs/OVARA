package action

import "testing"

func TestClosedVocabulary(t *testing.T) {
	a, err := Canonicalize("shell.exec", "echo hi")
	if err != nil || a.Type != TypeShellExec {
		t.Fatalf("known type failed: %v %+v", err, a)
	}
	// v1 audit-F5: arbitrary strings evaluated. v2 maps them to
	// raw.unknown instead of treating them as first-class types.
	a, err = Canonicalize("anything.goes", "x")
	if err != nil || a.Type != TypeRawUnknown || !a.ParseFlag {
		t.Fatalf("unknown type should map to raw.unknown+flag: %v %+v", err, a)
	}
}

func TestNetUserinfoRejected(t *testing.T) {
	// v1 corpus: https://user:pw@api.github.com evaluated; v2 rejects.
	if _, err := Canonicalize("http.request",
		"GET https://user:pw@api.github.com/x"); err == nil {
		t.Fatal("userinfo must be rejected")
	}
}

func TestNetCanonical(t *testing.T) {
	cases := map[string]string{
		"GET https://api.github.com/x":            "https://api.github.com/x",
		"https://api.github.com:443/x":            "https://api.github.com/x",
		"https://api.github.com:8443/x":           "https://api.github.com:8443/x",
		"HTTPS://API.GITHUB.COM/X":                "https://api.github.com/X",
		"http://169.254.169.254/latest":           "http://169.254.169.254/latest",
		"https://api.github.com/../a/./b":         "https://api.github.com/a/b",
		"https://api.github.com.evil.com/x":       "https://api.github.com.evil.com/x", // stays itself — host-boundary matching kills it, not mangling
	}
	for in, want := range cases {
		a, err := Canonicalize("http.request", in)
		if err != nil {
			t.Fatalf("%s: %v", in, err)
		}
		if a.Resource != want {
			t.Fatalf("%s -> %q want %q", in, a.Resource, want)
		}
	}
}

func TestNetRejects(t *testing.T) {
	for _, in := range []string{
		"", "api.github.com/x", "https:///x", "https://exa mple.com/",
	} {
		if _, err := Canonicalize("net.egress", in); err == nil {
			t.Fatalf("%q should reject", in)
		}
	}
}

func TestPathCanon(t *testing.T) {
	a, err := Canonicalize("fs.write", "/tmp/../etc/passwd")
	if err != nil || a.Resource != "/etc/passwd" {
		t.Fatalf("traversal: %v %+v", err, a)
	}
	if _, err := Canonicalize("fs.write", "rel/path"); err == nil {
		t.Fatal("relative path must reject")
	}
	if _, err := Canonicalize("fs.write", "~/x"); err == nil {
		t.Fatal("unexpanded ~ must reject")
	}
}

func TestShellCanon(t *testing.T) {
	a, err := Canonicalize("shell.exec", `echo 'a b' | grep x > /tmp/out`)
	if err != nil {
		t.Fatal(err)
	}
	if a.Resource != "echo a b | grep x >/tmp/out" {
		t.Fatalf("canon: %q", a.Resource)
	}
	if a.ParseFlag {
		t.Fatal("clean pipeline flagged")
	}
}

func TestShellFlagged(t *testing.T) {
	// substitution/globs flag — never silently flattened
	for _, cmd := range []string{
		"echo $(cat /etc/passwd)",
		"cat `which x`",
		"rm -rf $DIR",
		"ls *.go",
	} {
		a, err := Canonicalize("shell.exec", cmd)
		if err != nil {
			t.Fatalf("%s: %v", cmd, err)
		}
		if !a.ParseFlag {
			t.Fatalf("%s should flag", cmd)
		}
	}
}

func TestShellSeparators(t *testing.T) {
	a, _ := Canonicalize("shell.exec", "a && b || c ; d & e")
	want := "a && b || c ; d ; e"
	if a.Resource != want {
		t.Fatalf("got %q want %q", a.Resource, want)
	}
}
