package main

import (
	"strings"
	"testing"
)

// defaultDecision evaluates the default rules the way the gateway does
// under "most-specific" precedence (policy/store.go): '*' matches any run
// of characters, the rule with the most literal characters decides, ties
// go deny > allow > escalate. Box resources (path:, shell:) are plain
// globs there too.
func defaultDecision(action, resource string) string {
	best, bestSpec, bestRank := "", -1, -1
	rank := map[string]int{"escalate": 0, "allow": 1, "deny": 2}
	for _, r := range defaultPolicyRules() {
		if r["action_type"] != action && r["action_type"] != "*" {
			continue
		}
		pat, _ := r["resource"].(string)
		if !globMatchForTest(pat, resource) {
			continue
		}
		effect := ""
		for _, e := range []string{"allow", "deny", "escalate"} {
			if r[e] == true {
				effect = e
			}
		}
		spec := len(pat) - strings.Count(pat, "*")
		if spec > bestSpec || (spec == bestSpec && rank[effect] > bestRank) {
			best, bestSpec, bestRank = effect, spec, rank[effect]
		}
	}
	return best
}

func globMatchForTest(pattern, s string) bool {
	if pattern == "" {
		return true
	}
	parts := strings.Split(pattern, "*")
	pos := 0
	for i, p := range parts {
		if p == "" {
			continue
		}
		idx := strings.Index(s[pos:], p)
		if idx < 0 || (i == 0 && idx != 0) {
			return false
		}
		pos += idx + len(p)
	}
	last := parts[len(parts)-1]
	return last == "" || strings.HasSuffix(s, last)
}

// Files that make something run on the host or in CI stay out of a
// commit-back; files that change what agents, installs or builds do come
// back flagged; ordinary files come back.
func TestDefaultPolicy_CommitBackPaths(t *testing.T) {
	want := map[string]string{
		".claude/settings.json":           "deny",
		"pkg/.claude/settings.local.json": "deny",
		".mcp.json":                       "deny",
		"sub/.mcp.json":                   "deny",
		".cursor/rules/x.mdc":             "deny",
		".vscode/tasks.json":              "deny",
		".vscode/settings.json":           "deny",
		".husky/pre-commit":               "deny",
		".pre-commit-config.yaml":         "deny",
		".gitattributes":                  "deny",
		"docs/.gitattributes":             "deny",
		".gitmodules":                     "deny",
		".github/dependabot.yml":          "deny",
		".github/workflows/ci.yml":        "deny",
		".github/scripts/release.sh":      "deny",
		".devcontainer/devcontainer.json": "deny",
		"CLAUDE.md":                       "escalate",
		"docs/AGENTS.md":                  "escalate",
		".cursorrules":                    "escalate",
		"package.json":                    "escalate",
		"web/package-lock.json":           "escalate",
		"yarn.lock":                       "escalate",
		"Cargo.lock":                      "escalate",
		"go.sum":                          "escalate",
		"Makefile":                        "escalate",
		"build/Dockerfile":                "escalate",
		"scripts/install.sh":              "escalate",
		"src/main.go":                     "allow",
		"README.md":                       "allow",
		".vscode/extensions.json":         "allow",
	}
	for p, w := range want {
		if got := defaultDecision("fs.commit_back.path", "path:"+p); got != w {
			t.Errorf("%s: %s, want %s", p, got, w)
		}
	}
}
