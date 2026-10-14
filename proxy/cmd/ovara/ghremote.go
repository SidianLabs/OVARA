package main

import (
	"strings"

	"ovara.proxy/internal/creds"
)

// parseGitHubRemote turns a github.com remote URL into "owner/repo":
// https://github.com/o/r(.git), git@github.com:o/r(.git),
// ssh://git@github.com/o/r(.git). Anything else gives "".
func parseGitHubRemote(u string) string {
	var path string
	switch {
	case strings.HasPrefix(u, "git@github.com:"):
		path = strings.TrimPrefix(u, "git@github.com:")
	default:
		for _, p := range []string{"https://github.com/", "http://github.com/", "ssh://git@github.com/", "git://github.com/"} {
			if strings.HasPrefix(strings.ToLower(u), p) {
				path = u[len(p):]
				break
			}
		}
		if path == "" {
			// https://user:token@github.com/o/r: the credentials are not ours to keep
			if i := strings.Index(u, "@github.com/"); i > 0 && strings.HasPrefix(u, "https://") {
				path = u[i+len("@github.com/"):]
			}
		}
	}
	path = strings.TrimSuffix(strings.TrimSuffix(path, "/"), ".git")
	owner, repo, ok := strings.Cut(path, "/")
	// The remote is in the project, which the agent can edit; what comes
	// back scopes the GitHub key, so only plain names pass ("*" would be a
	// glob over every repository).
	if !ok || !creds.RepoName(owner) || !creds.RepoName(repo) {
		return ""
	}
	return owner + "/" + repo
}
