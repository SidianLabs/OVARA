# C1 — Resource model (spec 0.1)

A decision is made about one **action**: an `action_type` and a `resource`
string. Two implementations must write the same action down the same way,
or they will decide it differently. This document fixes the forms.

## 1. Action types

Used by the reference implementation's own components:

| `action_type` | Who raises it | Resource form (§2–§4) |
|---|---|---|
| `http.request` | the proxy, for every request that leaves | `METHOD scheme://host[:port]/path[?query][ <refs>]` |
| `shell` | the box command gate, for every program the agent starts | `shell:<normalised command line>` |
| `fs.commit_back.path` | the box, per file coming back | `path:<relative path>` |
| `fs.commit_back` | the box, for the whole commit-back | `commit:<project> (<n> files, tree <12 hex>)` |
| `mcp.tools` | the MCP gate, for a tool list | `mcp:<server> tools <n> new[ <m> changed]` |
| `mcp.tool_call` | the MCP gate, per tool call | `mcp:<server>/<tool>` |
| `tool.call` | an agent framework's tool guard (SDK), per in-process tool call | `tool:<name>` |
| `tcp.connect` | the proxy's TCP gate, for a CONNECT to a port other than 443 | `tcp:<host>:<port>` |
| `package.install` | the proxy, per package download | `npm:<name>@<version>`, `pypi:<name>@<version>`, `download:<host><path>` |
| `model.server_feature` | the proxy's model gate | `model:<host> <finding>` |
| `model.budget` | the proxy, past the per-run model budget | `model-budget:<host>` |
| `egress.budget` | the proxy, past the per-host egress budget | `budget:<host>` |
| `taint.write` | the proxy, a write soon after an untrusted read | `taint:<METHOD> <url>` |

Also defined, for SDK callers of the decision API (`runtime/gateway/internal/models`):
`exec`, `git.push`, `git.pull`, `git.fetch`, `git.checkout`, `git.force_push`,
`github.push`, `github.pr`, `github.merge`, `github.delete_branch`,
`ci.deploy`, `ci.build_trigger`, `ci.approval`. Their resources are
free-form strings; they are matched as globs unless URL-shaped (§2.4).

A policy rule names an action type exactly, or every one as `*`.

## 2. URL resources (`http.request`)

### 2.1 Canonical form

```
[METHOD ]scheme://host[:port]/path[?query][ ref[,ref...]]
```

Produced by `policy.CanonicalResource`. A resource that cannot be put in
this form is **not canonical**: it matches no URL-shaped rule (§2.4), so
only a rule with an empty resource pattern can decide it.

| Part | Rule |
|---|---|
| `METHOD` | optional; letters only (`GET`, `POST`, `CONNECT`, ...), written upper-case. A token with any other character is not a method, and the resource is not canonical. |
| `scheme` | lower-case; required. |
| `host` | lower-case; trailing dots removed; must be non-empty; no `%`; **no userinfo** (`user@host` is not canonical); a host containing `:` must be an IP literal and is written in brackets (`[::1]`). |
| `port` | dropped when it is the scheme's default (`443` for https, `80` for http); otherwise kept. |
| `path` | the escaped path, cleaned (`a//b` → `a/b`); a trailing `/` is kept. A `.` or `..` segment in the **decoded** path (`..`, `%2e%2e`) makes the resource not canonical: it is refused, never normalised. |
| `query` | kept as written. The fragment is dropped. |
| `refs` | only on a git push (§2.2). |

### 2.2 Git pushes

A push (`POST .../git-receive-pack`) carries the refs it updates as a
suffix: a space, then the ref names joined by commas, each followed by
`(delete)` when the push deletes it:

```
POST https://github.com/acme/app/git-receive-pack refs/heads/main,refs/heads/old(delete)
```

A policy decides **each ref separately** (`policy.SplitRefList`): the push
gets the strictest of the per-ref answers (deny > escalate > allow), so an
allow for one ref never carries another ref with it. A push whose refs
cannot be read gets the suffix ` git-receive-pack` (unparseable) or
` git-receive-pack(truncated)` (the ref list ran past what was read), which
a policy treats as a push it cannot see inside.

### 2.3 What the proxy writes

The proxy canonicalises before asking. The host is the literal host of the
request (never a resolved address), so a decision is never made on a name
that could resolve differently later. The query is hidden from the
decision's resource only where a rule says so; by default it is part of it.

### 2.4 Matching a URL-shaped pattern

A pattern is URL-shaped when it is `scheme://...` or `METHOD scheme://...`
(the part before `://` is letters, digits, `+`, `-` or `.`). Such a pattern
is matched against the canonical form with a **host-boundary** check: a
host literal in the pattern matches that host or a proper subdomain of it
at a label boundary (`api.github.com` matches a `github.com` pattern,
`notgithub.com` and `github.com.evil.com` do not). `*` matches any run of
characters; everything else is literal. See `policy.md` §3 for how ports
and effects interact.

## 3. Command lines (`shell`)

`shell:` followed by the **policy line** of the exec
(`boxgate.PolicyLine`): the same exec in one spelling, so a rule like
`shell:*rm -rf*` or `shell:*git push*` cannot be dodged by writing the
command differently. The person approving sees the raw line, not this one.

| Rule | Example |
|---|---|
| the program is its base name | `/usr/bin/sudo id` → `sudo id` |
| an image that is `rm` is read as `rm` whatever `argv[0]` says | `exec -a tidy rm -rf /w` → `rm -rf /w` |
| git's global options before the subcommand are dropped; a `-c alias.X=...` is resolved; a `!` alias is read as the shell command it runs | `git -C /w -c alias.ship=push ship` → `git push`; `git -c alias.s='!git push --force' s` → `git push --force` |
| `rm`'s options are merged into one group with `r` and `f` first (long forms and their abbreviations included), wherever they stand | `rm x -R --force -v` → `rm -rfv x` |
| a shell's `-c` script is tidied (white space) and read as the script; the programs it starts are stopped at their own exec and judged as themselves | `bash -c "rm   -rf /tmp/x"` → `rm -rf /tmp/x` |
| runs of white space are one space | |

Not seen by normalisation, by design: a renamed copy of a program other
than `rm`, an alias defined in a git config file, a script that deletes
files itself. The exec gate's per-program stop is the containment; the
normalised line is for rules written by people.

## 4. The other forms

| Form | Details |
|---|---|
| `path:<relative path>` | relative to the workspace root, forward slashes, as the diff names it. |
| `commit:<project> (<n> files, tree <12 hex>)` | the project's directory name, the number of files coming back, the first 12 hex digits of the reviewed tree's hash. |
| `mcp:<server> tools <n> new[ <m> changed]` | `<server>` is `<host><path>` for an HTTP MCP server (`mcp.example.com/mcp`) or `stdio:<name>` for a wrapped one. |
| `mcp:<server>/<tool>` | `<tool>` is the tool name with characters outside the safe set percent-escaped (`we ird` → `we%20ird`), so a name cannot forge a path. |
| `tcp:<host>:<port>` | a connection that is not HTTPS: the host as in a URL resource (lower-case, no trailing dot, an IPv6 literal in brackets), the port always written. What flows inside is not seen; the receipts carry the bytes each way. |
| `tool:<name>` | the tool a framework is about to call in-process, its name escaped as an MCP tool's is (letters, digits, `_`, `-` and `.` kept; every other byte `%XX`). The arguments are not in the resource: the request's `metadata.proxy_context` carries their size, SHA-256 and a redacted preview, which bind the approval to the exact call. |
| `npm:<name>@<version>`, `pypi:<name>@<version>` | the package a registry download names; scoped npm names keep their `@scope/`. |
| `download:<host><path>` | a registry download that names no package. |
| `model:<host> <finding>` | `<finding>` is one of `model_request_mcp_connector`, `model_request_remote_url`, `model_request_server_tool`, `model_request_not_json`. |
| `model-budget:<host>`, `budget:<host>` | the host whose budget was passed. |
| `taint:<METHOD> <url>` | the write that followed an untrusted read, as a URL resource. |

These are matched as plain globs (§2.4 does not apply). Under most-specific
precedence an allow on them beats a deny only by literal prefix
(`policy.md` §4).

## 5. Tests that fix this contract

`runtime/gateway/internal/policy`: `TestCanonicalResource*`,
`FuzzCanonicalResource`, `FuzzMatchResource`, `FuzzMatchCanonicalResource`,
`FuzzSplitRefList`; `proxy/internal/proxy`: `FuzzParseRefUpdates`,
`FuzzParseRefUpdatesRoundTrip`, `FuzzNormalizeHost`, the git gate tests;
`proxy/internal/boxgate`: `TestPolicyLine`, `FuzzPolicyLine`;
`proxy/internal/mcp`: `TestToolCallPreviewBindsArguments` (tool names);
`sdk/python/tests/test_guard.py`, `sdk/typescript/src/__tests__/guard.test.ts`
(`tool:<name>` escaping, argument hashing); `proxy/internal/proxy`:
`TestTCPGate_*` (`tcp:<host>:<port>`).
