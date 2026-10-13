package main

import (
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

// terminalUnsafe is the oracle for termSafe, written from the list of what
// must never reach a terminal rather than from termSafe's own table.
func terminalUnsafe(r rune) bool {
	switch {
	case r < 0x20 && r != '\t', r == 0x7f, r >= 0x80 && r <= 0x9f: // C0 (ESC among them), DEL, C1
		return true
	case r == '\t': // a control too; termSafe shows it escaped
		return true
	case r >= 0x202A && r <= 0x202E, r >= 0x2066 && r <= 0x2069, r == 0x200E, r == 0x200F, r == 0x061C: // bidi
		return true
	case r >= 0x200B && r <= 0x200D, r == 0x2060, r == 0xFEFF: // zero-width
		return true
	case r >= 0xE0000 && r <= 0xE007F: // tag characters
		return true
	case r == 0x2028, r == 0x2029:
		return true
	}
	return unicode.Is(unicode.Cf, r)
}

// Whatever an agent puts in a URL, a file name or a diff, what termSafe
// prints is valid UTF-8 with no escape, C1, bidi, zero-width or tag
// character, and making it safe again changes nothing.
func FuzzTermSafe(f *testing.F) {
	for _, s := range []string{
		"plain", "\x1b[2J\x1b[Hok", "\x9b31m", "a\u202eb", "x\u200by", "\U000E0041\U000E0042",
		"line\r\nnext", "lone\rcr", "\xff\xfe", "\u2066iso\u2069", "\ufeffbom", "tab\there", "",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		out := termSafe(s)
		if !utf8.ValidString(out) {
			t.Fatalf("termSafe(%q) = %q is not valid UTF-8", s, out)
		}
		for _, r := range out {
			if terminalUnsafe(r) {
				t.Fatalf("termSafe(%q) = %q keeps %U", s, out, r)
			}
		}
		if again := termSafe(out); again != out {
			t.Fatalf("not stable: %q -> %q -> %q", s, out, again)
		}
		for _, l := range strings.Split(termSafeLines(s), "\n") {
			for _, r := range l {
				if terminalUnsafe(r) {
					t.Fatalf("termSafeLines(%q) keeps %U", s, r)
				}
			}
		}
	})
}

// githubName is what GitHub allows in an owner or repository name.
func githubName(s string) bool {
	if s == "" || s == "." || s == ".." {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}

// The repository a box scopes the GitHub credential to comes from the
// project's own remote, which the agent can edit. Whatever it says, the
// result is "" or exactly owner/repo made of name characters: never a
// glob, a second path segment, userinfo or a port.
func FuzzParseGitHubRemote(f *testing.F) {
	for _, s := range []string{
		"https://github.com/acme/app.git", "git@github.com:acme/app.git", "ssh://git@github.com/acme/app.git",
		"https://x:tok@github.com/acme/app.git", "https://github.com.evil.example/acme/app",
		"https://github.com/acme/*", "https://github.com/*/*", "https://github.com/acme/app@x",
		"https://github.com/acme/app:1", "https://github.com/acme/..", "https://github.com/acme/app/extra",
		"HTTPS://GITHUB.COM/a/b", "git@github.com:a/b c", "",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, u string) {
		got := parseGitHubRemote(u)
		if got == "" {
			return
		}
		owner, repo, ok := strings.Cut(got, "/")
		if !ok || strings.Count(got, "/") != 1 || strings.ContainsAny(got, "@:*?# ") || !githubName(owner) || !githubName(repo) {
			t.Fatalf("parseGitHubRemote(%q) = %q", u, got)
		}
	})
}
