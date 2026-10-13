package main

import (
	"net"
	"strings"
)

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
	// --- credentialed reads that are not free ---
	// Reads of api.github.com carry the user's token, so "reading is free"
	// would let the agent read whatever the token can. These reads return
	// secret material or account data rather than code, and pause; being
	// longer than the host-wide allow, they win under most-specific
	// precedence. Paths are matched as written (GitHub's are lower case).
	for _, p := range sensitiveGitHubReads {
		rules = append(rules, rule("GET https://api.github.com"+p, "escalate", "Reading this from GitHub uses your token to fetch secrets or account data: needs approval"))
	}
	// The Slack Web API is RPC: slack.com/api/<method> acts the same sent
	// as GET or POST (chat.postMessage by GET posts a message), so a GET
	// there is a call, not a read.
	rules = append(rules,
		rule("GET https://slack.com/api/*", "escalate", "Slack API call (it can change things even when sent as GET): needs approval"))
	// --- end credentialed reads that are not free ---
	// git clone/fetch/pull speak smart-HTTP with a POST to git-upload-pack;
	// it only reads. The host is part of the rule: a bare "*git-upload-pack"
	// would match a POST to ANY server whose path ends that way.
	for _, h := range trustedGitHosts {
		rules = append(rules, rule("POST https://"+h+"/*git-upload-pack", "allow", "git clone/fetch/pull from "+h+" is reading"))
	}
	rules = append(rules,
		// The agent must be able to talk to its own model provider, and only
		// that: the inference endpoints. Files, batches, fine-tunes, vector
		// stores and admin calls on the same hosts are writes and pause like
		// any other. The proxy also checks these bodies (modelgate.go) and
		// refuses features that make the provider fetch a URL for the agent.
		rule("POST https://api.anthropic.com/v1/messages", "allow", "The agent may call its model (Anthropic Messages API)"),
		rule("POST https://api.anthropic.com/v1/messages/count_tokens", "allow", "The agent may count tokens (Anthropic)"),
		rule("POST https://api.openai.com/v1/responses", "allow", "The agent may call its model (OpenAI Responses API)"),
		rule("POST https://api.openai.com/v1/chat/completions", "allow", "The agent may call its model (OpenAI Chat Completions)"),
		rule("POST https://api.openai.com/v1/embeddings", "allow", "The agent may compute embeddings (OpenAI)"),
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
	)
	// Files that make something run on the person's machine or in CI when
	// they merge, open or build the project: agent hooks and settings, MCP
	// servers, editor tasks, git hooks and filters, CI and dev containers.
	// A reviewer reading "the agent's code changes" does not expect them, so
	// they stay in the workspace unless the policy is edited. Each is
	// matched at the top and in any subdirectory.
	for _, p := range []string{
		".claude/*", ".mcp.json", ".cursor/*", ".vscode/tasks.json", ".vscode/settings.json",
		".husky/*", ".pre-commit-config.yaml", ".gitattributes", ".gitmodules",
		".github/*", ".devcontainer/*", ".devcontainer.json",
	} {
		desc := "Kept out: " + p + " can make something run on the host or in CI"
		rules = append(rules,
			fsRule("fs.commit_back.path", "path:"+p, "deny", desc),
			fsRule("fs.commit_back.path", "path:*/"+p, "deny", desc))
	}
	// Files that come back but are named to the person first ("⚠ sensitive
	// file changed"): instructions other agents follow, install and build
	// scripts, and lockfiles. Escalate on a path means exactly that in
	// `ovara box`; matching a little too much here costs only a warning.
	for _, p := range []string{
		"CLAUDE.md", "AGENTS.md", ".cursorrules", "package.json",
		"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "*.lock", "go.sum",
		"Makefile", "makefile", "Dockerfile", "Dockerfile.*", "*.dockerfile", "*.sh",
	} {
		rules = append(rules, fsRule("fs.commit_back.path", "path:*"+strings.TrimPrefix(p, "*"), "escalate", "Comes back, but flagged for the person: "+p+" changes what agents, installs or builds do"))
	}
	rules = append(rules,
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
		// The command line these match is normalised first (boxgate.PolicyLine):
		// the program's base name, rm's flags merged ("rm -r -f", "rm
		// --recursive --force" and "rm -Rf" all read "rm -rf"), git's global
		// options dropped ("git -c k=v push" reads "git push"). Every program
		// is checked on its own, so the rm or git that `sh -c "..."` starts
		// is matched as itself whatever the shell line looked like.
		fsRule("shell", "shell:*rm -rf*", "escalate", "Recursive deletes pause for a person"),
		fsRule("shell", "shell:*rm -fr*", "escalate", "Recursive deletes pause for a person"),
		fsRule("shell", "shell:rm -r*", "escalate", "Recursive deletes pause for a person"),
		fsRule("shell", "shell:*find * -delete*", "escalate", "Deleting with find pauses for a person"),
		fsRule("shell", "shell:*shred *", "escalate", "Destructive: pauses for a person"),
		fsRule("shell", "shell:*truncate -s 0*", "escalate", "Destructive: pauses for a person"),
		fsRule("shell", "shell:*git push*", "escalate", "Publishing pauses for a person (and changes come back through commit-back anyway)"),
		fsRule("shell", "shell:*mkfs*", "escalate", "Destructive: pauses for a person"),
		fsRule("shell", "shell:*dd if=*", "escalate", "Destructive: pauses for a person"),
		// An agent starting another agent with its permission checks off.
		// (The command `ovara box` itself was given to start is not paused.)
		fsRule("shell", "shell:*--dangerously-skip-permissions*", "escalate", "An agent with its permission checks turned off pauses for a person"),
		fsRule("shell", "shell:*--dangerously-bypass-approvals-and-sandbox*", "escalate", "An agent with its approvals and sandbox turned off pauses for a person"),
		fsRule("shell", "shell:*--yolo*", "escalate", "An agent with its approvals turned off pauses for a person"),
		fsRule("shell", "shell:*", "allow", "Everything else the agent runs in the box is allowed and recorded"),
		// `ovara box -profile strict`: downloading a package the project's
		// lockfiles did not pin when the box started (action_type
		// package.install, resource "npm:name@version") pauses once; an
		// approved one is allowed for the rest of the run. Allow trusted
		// packages here, e.g. "npm:@types/*".
		fsRule("package.install", "*", "escalate", "A new dependency pauses once with its name and version (strict profile)"),
		// --- proxy follow-up questions (proxy/internal/proxy) ---
		// The proxy asks these about requests the URL rules above allowed.
		// A model request that makes the provider fetch a URL or connect to
		// a server for the agent (MCP connector, web fetch/search, an image
		// by URL) pauses with the request in view; resource
		// "model:<host> <finding>".
		fsRule("model.server_feature", "*", "escalate", "A model request that makes the provider reach out for the agent pauses for a person"),
		// Allowed traffic past a host's per-minute budget pauses once;
		// approving doubles that host's allowance for the run. Resource
		// "budget:<host>"; allow a host here to never be asked about it.
		fsRule("egress.budget", "*", "escalate", "Unusually heavy traffic to one host pauses for a person"),
		// --- end proxy follow-up questions ---
		// --- per-agent questions (proxy/internal/proxy taint.go, modelbudget.go) ---
		// For a while (taint_window_minutes, default 30) after the agent
		// read content anyone can write (an issue, a PR comment, a host a
		// person approved), every write the rules above would allow pauses
		// with the source in view; resource "taint:<METHOD> <url>". Writes
		// already paused or blocked are unchanged.
		fsRule("taint.write", "*", "escalate", "A write soon after the agent read untrusted content pauses for a person"),
		// Model use past the agent's budget for the run (model_budget in
		// proxy.json) pauses once; approving doubles it. Resource
		// "model-budget:<host>".
		fsRule("model.budget", "*", "escalate", "Model use past the agent's budget for this run pauses for a person"),
		// --- end per-agent questions ---
		// --- MCP (proxy/internal/mcp; the proxy and `ovara mcp wrap`) ---
		// A server's tool definitions are what the model reads: the first
		// time a server lists its tools, and whenever a definition changes
		// or a new tool appears, a person sees them (resource
		// "mcp:<host><path> tools <n> new [<m> changed]", or
		// "mcp:stdio:<name> ..." for a wrapped stdio server). Until then
		// the agent does not see them and cannot call them.
		fsRule("mcp.tools", "*", "escalate", "New or changed MCP tool definitions pause for a person"),
		// Every call of an approved tool pauses; resource
		// "mcp:<host><path>/<tool>". Allow the tools you trust by name,
		// e.g. "mcp:mcp.example.com/mcp/search", or a whole server with
		// "mcp:mcp.example.com/mcp/*".
		fsRule("mcp.tool_call", "*", "escalate", "MCP tool calls pause for a person unless the tool is allowed by name"),
		// --- end MCP ---
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

// sensitiveGitHubReads are api.github.com paths whose GETs escalate even
// though the host is a trusted read host: secret scanning alerts, Actions,
// Dependabot, Codespaces and environment secrets and variables, the
// account's keys and e-mail addresses, org membership, gists, OAuth
// authorizations and app installation tokens.
var sensitiveGitHubReads = []string{
	"/*/secret-scanning/*",
	"/*/actions/secrets*",
	"/*/actions/variables*",
	"/*/environments/*/secrets*",
	"/*/environments/*/variables*",
	"/*/dependabot/secrets*",
	"/*/codespaces/secrets*",
	"/user/codespaces/secrets*",
	"/user/keys*",
	"/user/gpg_keys*",
	"/user/ssh_signing_keys*",
	"/user/emails*",
	"/user/public_emails*",
	"/orgs/*/members*",
	"/gists*",
	"/authorizations*",
	"/installation/*",
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
