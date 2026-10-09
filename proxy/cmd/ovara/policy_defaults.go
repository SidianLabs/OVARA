package main

import "net"

// defaultPolicyRules is what `ovara init` writes to policy.json. The idea,
// in one line: reading is free, writing needs a human, and a few known
// data-dump sites are blocked outright. `ovara init` sets precedence
// "most-specific": the most specific matching rule decides, ties go
// deny > allow > escalate, so the exact allows below override the
// "writes need approval" catch-alls and a catch-all deny would not. Edit policy.json freely; changes are picked up
// without a restart.
func defaultPolicyRules() []map[string]any {
	rule := func(resource, effect, desc string) map[string]any {
		r := map[string]any{"action_type": "http.request", "environment": "*", "description": desc}
		if resource != "" {
			r["resource"] = resource
		}
		r[effect] = true
		return r
	}
	fsRule := func(action, resource, effect, desc string) map[string]any {
		return map[string]any{"action_type": action, "environment": "*", "resource": resource, "description": desc, effect: true}
	}
	rules := []map[string]any{}
	// Reading is free, but only from places an agent legitimately needs:
	// package registries, code hosts and documentation. A blanket "GET *"
	// would let an agent send data to ANY server it controls (the path and
	// query of a GET carry data just as well as a POST body), so a host that
	// is not listed here pauses for approval like everything else.
	for _, h := range trustedReadHosts {
		rules = append(rules,
			rule("GET https://"+h+"/*", "allow", "Reading from "+h+" is allowed"),
			rule("HEAD https://"+h+"/*", "allow", "Reading from "+h+" is allowed"),
		)
	}
	// git clone/fetch/pull speak smart-HTTP with a POST to git-upload-pack;
	// it only reads. The host is part of the rule: a bare "*git-upload-pack"
	// would match a POST to ANY server whose path ends that way.
	for _, h := range trustedGitHosts {
		rules = append(rules, rule("POST https://"+h+"/*git-upload-pack", "allow", "git clone/fetch/pull from "+h+" is reading"))
	}
	rules = append(rules,
		// The agent must be able to talk to its own model provider.
		rule("POST https://api.anthropic.com/*", "allow", "The agent may call the Anthropic API"),
		rule("POST https://api.openai.com/*", "allow", "The agent may call the OpenAI API"),
		// `npm install` runs `npm audit` automatically: a POST that sends the
		// package names and versions being installed to the registry. It reads
		// advisories, it writes nothing, and without this rule every agent
		// `npm install` stalls for the full approval window.
		rule("POST https://registry.npmjs.org/-/npm/v1/security/advisories/bulk", "allow", "npm audit (sends package names/versions, reads advisories)"),
		rule("POST https://registry.npmjs.org/-/npm/v1/security/audits/quick", "allow", "npm audit (sends package names/versions, reads advisories)"),
		// Known places where stolen data typically gets dumped.
		rule("*://pastebin.com/*", "deny", "Blocked: paste site commonly used to leak data"),
		rule("*://transfer.sh/*", "deny", "Blocked: anonymous file drop"),
		rule("*://webhook.site/*", "deny", "Blocked: request-capture site commonly used to leak data"),
		rule("*://*.requestbin.com/*", "deny", "Blocked: request-capture site commonly used to leak data"),
		// `ovara box`: what the agent changed comes back to the real
		// repository only as a reviewed commit on a new branch. Each path is
		// checked (fs.commit_back.path) so a policy can keep the agent out of
		// what runs on the host or in CI, then the commit as a whole pauses
		// for a person who sees the diff (fs.commit_back).
		fsRule("fs.commit_back.path", "path:.github/workflows/*", "deny", "The agent may not change CI workflows without a person editing the policy"),
		fsRule("fs.commit_back.path", "path:.git/*", "deny", "The agent may not change git hooks or config"),
		fsRule("fs.commit_back.path", "path:*", "allow", "Other paths may come back for review"),
		fsRule("fs.commit_back", "commit:*", "escalate", "Changes come back to the real repository only after a person reads the diff"),
		// `ovara box` command gate: every program the agent starts is checked
		// (action_type shell, resource "shell:<command line>"). Development
		// work is free; what would make the box less of a box is refused;
		// the classic destructive commands and anything that publishes pause
		// for a person. Most-specific precedence: these beat "shell:*".
		fsRule("shell", "shell:sudo*", "deny", "No privilege changes in the box"),
		fsRule("shell", "shell:su *", "deny", "No privilege changes in the box"),
		fsRule("shell", "shell:su", "deny", "No privilege changes in the box"),
		fsRule("shell", "shell:mount*", "deny", "The box's mounts are not the agent's to change"),
		fsRule("shell", "shell:umount*", "deny", "The box's mounts are not the agent's to change"),
		fsRule("shell", "shell:nft*", "deny", "The box's network rules are not the agent's to change"),
		fsRule("shell", "shell:iptables*", "deny", "The box's network rules are not the agent's to change"),
		fsRule("shell", "shell:ip netns*", "deny", "The box's network is not the agent's to change"),
		fsRule("shell", "shell:ip link*", "deny", "The box's network is not the agent's to change"),
		fsRule("shell", "shell:ip route*", "deny", "The box's network is not the agent's to change"),
		fsRule("shell", "shell:ovara*", "deny", "The agent may not operate Ovara"),
		fsRule("shell", "shell:*rm -rf*", "escalate", "Recursive deletes pause for a person"),
		fsRule("shell", "shell:*rm -fr*", "escalate", "Recursive deletes pause for a person"),
		fsRule("shell", "shell:*git push*", "escalate", "Publishing pauses for a person (and changes come back through commit-back anyway)"),
		fsRule("shell", "shell:*mkfs*", "escalate", "Destructive: pauses for a person"),
		fsRule("shell", "shell:*dd if=*", "escalate", "Destructive: pauses for a person"),
		fsRule("shell", "shell:*", "allow", "Everything else the agent runs in the box is allowed and recorded"),
		// Anything that changes something out in the world needs a human.
		// This covers git push, opening/merging PRs, deleting branches,
		// triggering deploys and posting messages.
		rule("POST *", "escalate", "Writes need approval (git push, PRs, deploys, messages)"),
		rule("PUT *", "escalate", "Writes need approval"),
		rule("PATCH *", "escalate", "Writes need approval"),
		rule("DELETE *", "escalate", "Deletes need approval"),
		// Anything we did not think of, including reads from a host that is
		// not on the trusted list: ask.
		rule("", "escalate", "Catch-all: anything unrecognised requires approval"),
	)
	return rules
}

// isLoopbackHost reports whether a listen host is loopback-only. An empty
// host (":9443") means every interface, so it is not.
func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// trustedGitHosts may be cloned/fetched from without approval.
var trustedGitHosts = []string{"github.com", "gitlab.com", "bitbucket.org"}

// trustedReadHosts may be read from without approval: package registries,
// code hosts, and documentation. Add your own hosts in policy.json.
var trustedReadHosts = []string{
	// code hosts
	"github.com", "api.github.com", "raw.githubusercontent.com",
	"codeload.github.com", "objects.githubusercontent.com", "gitlab.com", "bitbucket.org",
	// package registries
	"pypi.org", "files.pythonhosted.org", "registry.npmjs.org", "registry.yarnpkg.com",
	"proxy.golang.org", "sum.golang.org", "index.crates.io", "static.crates.io", "crates.io",
	"rubygems.org", "repo.maven.apache.org", "repo1.maven.org", "pkg.go.dev",
	// documentation
	"docs.python.org", "go.dev", "developer.mozilla.org", "nodejs.org",
	"docs.anthropic.com", "platform.openai.com", "docs.github.com",
}
