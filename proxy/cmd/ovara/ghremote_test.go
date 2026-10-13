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
		// Found by FuzzParseGitHubRemote: the remote is the agent's to edit,
		// and "*" here became a credential scope over every repository.
		"https://github.com/*/*":        "",
		"https://github.com/acme/*":     "",
		"https://github.com/acme/app@x": "",
		"https://github.com/acme/app:1": "",
		"https://github.com/acme/..":    "",
		"git@github.com:acme/app x":     "",
		"https://github.com/a-b/c_d.e":  "a-b/c_d.e",
	}
	for in, want := range cases {
		if got := parseGitHubRemote(in); got != want {
			t.Errorf("parseGitHubRemote(%q) = %q, want %q", in, got, want)
		}
	}
}
