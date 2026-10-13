package main

import "testing"

func TestParseGitHubRemote(t *testing.T) {
	cases := map[string]string{
		"https://github.com/acme/app.git":          "acme/app",
		"https://github.com/acme/app":              "acme/app",
		"git@github.com:acme/app.git":              "acme/app",
		"ssh://git@github.com/acme/app.git":        "acme/app",
		"https://x:tok@github.com/acme/app.git":    "acme/app",
		"https://gitlab.com/acme/app.git":          "",
		"https://github.com/acme":                  "",
		"https://github.com/acme/app/extra":        "",
		"https://github.com.evil.example/acme/app": "",
		"": "",
	}
	for in, want := range cases {
		if got := parseGitHubRemote(in); got != want {
			t.Errorf("parseGitHubRemote(%q) = %q, want %q", in, got, want)
		}
	}
}
