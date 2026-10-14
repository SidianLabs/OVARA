# Ovara

**A checkpoint for AI agents. Reading from trusted places is free, anything else needs your OK, and every decision leaves a receipt.**

You give a coding agent (Claude Code, Devin, a CI bot…) real tokens and let it
loose. One bad prompt and it force-pushes to `main`, deletes a branch, or posts
your API key to a paste site.

Ovara sits between the agent and the internet. Every request the agent makes goes
through it:

| The agent tries to… | Ovara… |
|---|---|
| read docs, install packages, clone from GitHub/GitLab/npm/PyPI… | lets it through |
| `git push`, open or merge a PR, deploy, delete something | **pauses it and asks you** |
| read from a site it has no business with | **pauses it and asks you** (a URL can carry data out just like a POST) |
| send data to a paste site or file drop | blocks it |

It also keeps your real API keys itself and attaches them to outgoing requests,
so Ovara never hands the agent a key it could leak. Every allow, pause and block
is written to a signed, tamper-evident receipt log you can verify later.

> **Status: early (v0.9, pre-release).** The core described on this page works and
> is tested. Most framework integrations
> are experimental, see [What's solid and what isn't](#whats-solid-and-what-isnt).
> The contracts another implementation would have to meet (resource model,
> policy, decision API, receipts) are written down in [`spec/`](spec/README.md)
> (0.1: what this code does, with schemas and drift tests).

---

## See it in 30 seconds

Install (downloads a prebuilt binary and verifies its SHA-256 checksum):

```bash
curl -sSL https://raw.githubusercontent.com/SidianLabs/OVARA/main/install.sh | sh    # Linux / macOS
```

```powershell
irm https://raw.githubusercontent.com/SidianLabs/OVARA/main/install.ps1 | iex       # Windows
```

Or build it yourself with Go 1.25+: `cd proxy && go build -o ovara ./cmd/ovara`.

```bash
ovara demo                         # no setup, no network, no root
```

The demo plays out a tiny story: the agent **reads** something (allowed), tries to
**deploy** (paused, then approved by a pretend human), tries to **leak data**
(blocked), and then verifies the receipt chain.

## Use it for real

```bash
ovara init mydir                 # writes keys, config, and a sensible default policy
export GITHUB_TOKEN=...            # the REAL keys go in Ovara's environment, not the agent's
export ANTHROPIC_API_KEY=...
ovara run -dir mydir             # starts the gateway and the proxy
```

On Linux there is a one-command form that also contains the agent:
`sudo ovara box ./myrepo -- claude` runs it in a network namespace, as a
separate user, with a root file system of its own (the host's system
directories read-only; nothing from home directories, `/root`, `/opt` or
`/srv`; not your original project), in a copy of the project with your keys
and secrets left out (by file name and by content: a file that looks like it
holds a key is listed and left out). It checks every command the agent runs
against the policy, limits your GitHub key to that project's repository, and
brings the agent's changes back as a branch after you have read the diff.
Tools installed under `/opt` or a home directory are not visible in the box
unless you add them with `-mount` (read-only). `-tier1-fs host` turns the
file-system isolation off; do not use it on a machine that holds secrets.
See `docs/use-cases.md` scenario 2 and `docs/box.md`.

For a stricter box, `sudo ovara box -tier 2 ./myrepo -- claude` runs the
agent in a container instead: no network interface but a relay to Ovara,
no capabilities, a read-only root, and nothing of your machine inside but
the project's copy. Build the image once with `docker build -t ovara-box
box/` and extend it with your agent. Details and limits are in
`docs/box.md` section 6.4.

Add `-profile strict` and a dependency the project's lockfiles do not pin
pauses once, by name and version, before it is downloaded. Where the lockfile
records a digest, the download is checked against it and cut off if it
differs. For a repository you are reviewing rather than your own, add
`-untrusted-lockfiles` so nothing it pins goes through unasked.

`ovara run` prints a link like `http://127.0.0.1:9090/#t=…`. Open it to get a
**local approval page**: whatever the agent is waiting on, with Approve and Deny
buttons, plus a live, integrity-checked history of what it did. The page is only
served to your own machine, and only someone holding the link's token can approve.
That token is made fresh each time `ovara run` starts and opens only this page,
never the gateway's admin API, so a link left in a log or scrollback is worth
little and stops working when Ovara stops. If the page's address is taken,
`ovara run` stops and says so; `-no-ui` runs without the page.

`ovara init` writes `policy.json` and the keys so only you can read them, and
does not print the operator token (it is in `config.json`).

Prefer the terminal? Answer from a **second terminal** instead:

```bash
ovara watch -dir mydir
```

```
┌─ approval needed ─────────────────────────────────────
│ agent wants to: push to refs/heads/main on github.com/acme/app
│ waiting:        4s   id: apr_1e448924-ef74-48
└───────────────────────────────────────────────────────
  [a]pprove  [d]eny  [s]kip >
```

Or do it all in one command: Ovara starts, your agent runs inside its
environment, and Ovara stops with it and sums up what it did.

```bash
ovara run -- opencode          # or claude, codex, or any command
```

The first run creates a deployment in `~/.ovara/run` (or uses the one in the
current directory), applies a preset for the agent it recognises (the hosts
that agent reads on its own, and its model API; writes still ask), and opens
the approval page. `ovara run -dir mydir -- claude` uses a deployment of yours.

Prefer to start the agent yourself? Give it Ovara's environment:

```bash
eval "$(ovara env -dir mydir)"                 # bash / zsh
ovara env -dir mydir -shell powershell | iex   # PowerShell
claude                                           # or any agent: it now runs through Ovara
```

`ovara env` sets the proxy address (including the agent's proxy token) and
points every common certificate setting (Node, Python, curl, git, OpenSSL) at
Ovara's certificate, so Ovara can see inside HTTPS. It pins `NO_PROXY` to
loopback, so a list inherited from your shell cannot take hosts out of Ovara
(it says which hosts it replaced). It also sets placeholder
values for `GITHUB_TOKEN`, `ANTHROPIC_API_KEY` and the rest, so tools that won't
start without a key still start. Ovara swaps in the real key on the way out.
It also unsets other secret-looking variables it finds in that shell (tokens,
cloud keys); `-keep-env` keeps them. The certificate is meant for the agent's
environment only: do not install it system-wide.

Prefer not to sit at a terminal? `ovara approvals` lists what is waiting, and
`ovara approve <id>` / `ovara deny <id>` answer one request. A paused request
is held for 10 seconds (`escalate_timeout_sec` in `proxy.json`); if you have
not answered by then the agent is told so (503 with `Retry-After` and the
approval id), the request stays on your list, and the same request sent again
runs once you approve it, once. Agents and model SDKs retry on that answer, so
approving later still works. Prefer the older behaviour, holding the request
until you answer or a timeout (504)? Set `"escalate_on_timeout": "timeout"` and
a longer `escalate_timeout_sec`. Either way an approval is used once; an
identical request after that asks again. An approval left unanswered expires
after 10 minutes and can no longer be approved, and one agent can have at most
64 waiting. What you approve is exactly what is sent: the whole body is read
before you are asked (up to 1 MB; a larger one is refused), you see its
SHA-256, and only those bytes go out.

### Short-lived keys instead of a personal token (recommended for GitHub)

A personal access token is long-lived and usually reaches every repository
you can. With a **GitHub App binding** Ovara holds the App's private key
and, per run, mints an installation token that lives one hour and is
limited to the repositories and permissions you list. That token is all
that ever goes upstream; the agent sees neither.

1. Create a GitHub App (Settings → Developer settings → GitHub Apps) with
   the permissions the agent needs, for example Contents and Pull requests
   read/write. No webhook is needed. Generate a private key.
2. Install the App on the repositories the agent may touch, and note the
   installation ID (the number at the end of the installation's settings
   URL).
3. Keep the key private to you (`chmod 600 app.pem`) and replace the
   `api.github.com` binding in `mydir/proxy.json`:

   ```json
   {"host": "api.github.com", "github_app": {
     "app_id": "${GH_APP_ID}",
     "installation_id": "${GH_APP_INSTALLATION_ID}",
     "private_key_file": "/home/me/.config/ovara/app.pem",
     "repositories": ["app"],
     "permissions": {"contents": "write", "pull_requests": "write"}
   }}
   ```

   `private_key` (for example `"${GH_APP_KEY}"`, the PEM text) can stand in
   for `private_key_file`. Repository names go without the owner.
4. `export GH_APP_ID=... GH_APP_INSTALLATION_ID=...` in Ovara's shell and
   start `ovara run`. `ovara doctor -dir mydir` checks the binding and the
   key without calling GitHub.

The same token is used for git over `github.com` (as `x-access-token`),
unless you bind `github.com` yourself. With no `repositories` listed,
`ovara run -scope-repo owner/repo`, which `ovara box` sets for the project
it boxes, limits each token to that one repository. Tokens are replaced
five minutes before they expire. If GitHub cannot issue one, the agent's
request is refused with `credential_unavailable`; it is never sent with an
old token or none.

For other APIs, an `oauth2` binding gets a Bearer token from an OAuth 2.0
token endpoint, by client credentials or by token exchange (RFC 8693):

```json
{"host": "api.example.com", "oauth2": {
  "token_url": "https://auth.example.com/oauth/token",
  "client_id": "${EXAMPLE_CLIENT_ID}", "client_secret": "${EXAMPLE_CLIENT_SECRET}",
  "scope": "read write", "audience": "https://api.example.com",
  "grant": "client_credentials"
}}
```

For `"grant": "token_exchange"`, set `"subject_token": "${...}"` (and
`subject_token_type` if it is not an access token). The client is
authenticated with HTTP Basic, or in the form with `"client_auth": "post"`.

### What did my agent do?

```bash
ovara log -dir mydir
```

```
WHEN                 OUTCOME       WHAT THE AGENT DID
2026-10-07 13:04:12  allowed       read https://pypi.org/simple/requests/
2026-10-07 13:04:20  approved      push to refs/heads/main on github.com/acme/app
2026-10-07 13:05:01  BLOCKED       send data to https://pastebin.com/api/api_post.php

1 allowed, 1 approved, 1 BLOCKED
integrity: ✓ all 3 receipts are signed and unbroken — this log has not been edited
```

Every line comes from a signed, hash-chained receipt, so if anyone edits the log
afterwards (to hide something, say), `ovara log` reports it as tampered. A
request is sent only after its receipt is on disk; if the receipt cannot be
written, the request is refused. More:

```bash
ovara log -verify-only -dir mydir                 # check the chain, exit nonzero if it fails
ovara log export -format ocsf -dir mydir         # the verified receipts for your log system (or -format jsonl)
ovara incident bundle -dir mydir -out case.tar.gz # receipts, keys, anchors and policy, verifiable offline
ovara keys rotate-receipt -dir mydir              # new receipt key (revoke-receipt, list-receipt)
```

Every run also ends with an **attestation**, `mydir/var/attestations/<run>.intoto.json`:
an in-toto statement signed with the receipt key that says who ran, under
which policy, exactly which receipts are the run's, what was approved and by
whom, which hosts were reached and how it ended (for `ovara box`, the manifest
and the commit the changes landed as). Anyone holding the bundle and the public
key can check it, with no Ovara running:

```bash
ovara attest verify -dir mydir                    # the newest run (-run ID for another; -manifest F for a box run)
ovara attest verify RUN.intoto.json -receipts receipts.jsonl -pubkey receipt_pubkey.hex -segment segment.json   # from an incident bundle
ovara attest list -dir mydir                      # every run, with its outcome (attest show prints one)
```

### Your rules live in `mydir/policy.json`

The default policy `ovara init` writes is short and readable (shown here
without the `"action_type": "http.request", "environment": "*"` every rule
carries; a rule missing them never matches, so Ovara refuses to load it):

```json
{ "resource": "GET https://pypi.org/*", "allow": true },
{ "resource": "*://pastebin.com/*",     "deny": true },
{ "resource": "POST *",                  "escalate": true }
```

Reads are allowed only from a list of hosts an agent legitimately needs (package
registries, code hosts, documentation); `ovara policy` shows the full list. A
host that is not on it pauses for approval. A `GET` that carries a request body,
a long query string, or a long path and headers (over 2 KB together) is
**refused** with an explanation (all of these can carry data out), even on a
trusted host. Allowed traffic is also metered per host: past about 600
requests or 8 MB a minute (ten times that for package registries) a person is
asked once. To trust another host, add a rule for it to `policy.json`, or
"approve and remember" on the approval page (or `ovara approve -remember`):
reads from that host until `ovara run` stops or for the project, exactly this
command for the run (the box's command gate), this MCP tool for the run. A
write is never remembered and a remembered rule is never a wildcard; each one
says who remembered it, when, and from which approval.

That is the **strict** policy profile, the default. If listing hosts is the
wrong fit (an agent that reads documentation all over the web), switch the
profile: `ovara policy profile balanced -dir mydir` lets it read from any
public host without asking and keeps everything else: each read stays
bounded, traffic stays metered per host, the distinct unlisted hosts it reads
are capped per agent and run (`open_reads` in `proxy.json`, 50 by default;
past that each further host asks once), every read leaves a receipt, and a
write soon after an untrusted read still pauses. `observe` is for a first run
on a project: reads are free, writes and tool calls are refused at once (never
held), and `ovara policy suggest` turns the run's receipts into the rules a
strict policy would need. `ovara policy profile` shows the current one;
`ovara init -profile balanced` starts with one. (`ovara box -profile
dev|strict` is a different setting: how the box treats package installs.)

An organisation can put a floor under every project: a **baseline** policy
(`policy_baseline_file` in `config.json`) that a project's `policy.json` may
only narrow. Its denies are absolute, its escalations can only be tightened
to denies, its allows stand unless the project has a rule, and every refusal
it causes says `org baseline`. Sign it (`ovara policy baseline keygen`, then
`sign`) and pin the key (`policy_baseline_pubkey`): a baseline that does not
verify stops the gateway instead of being skipped, so whoever can edit the
project's files cannot loosen the organisation's.

`allow` lets it through, `escalate` pauses it for you, `deny` blocks it. If more
than one rule matches, **the most specific one decides** (more literal
characters in its pattern; among equals deny beats allow beats escalate), so
`POST https://api.github.com/repos/acme/app/pulls` allow next to `POST *` deny
means exactly that one write. Three guards keep that from being turned around:
a deny always beats an escalate; an allow only beats a deny if it names the
host (for commands, the program) at least as precisely; and deny and
escalate rules for a host apply on every port. A git push that updates several refs is decided ref by ref and
gets the strictest answer, and an allow for refs does not cover deleting them
unless it says `(delete)`. (Policies without `"precedence": "most-specific"`
keep the older rule: any deny wins.) Anything not matched is escalated. Edit
the file; changes are picked up without a restart.

Not sure what a rule will do? Ask:

```bash
ovara policy -dir mydir        # all rules, grouped: blocked / allowed / ask me first
ovara policy test "POST https://github.com/acme/app.git/git-receive-pack refs/heads/main" -dir mydir
```

```
push to refs/heads/main on github.com/acme/app
  → ASK ME FIRST: it would pause until you approve
  because of the rule: Writes need approval (git push, PRs, deploys, messages)
```

`policy test` is a dry run against the live policy: nothing is sent and no
approval is opened.

### Behind a corporate proxy

On a network where everything leaves through a company proxy, tell Ovara in
`proxy.json` and nothing else changes:

```json
"upstream_proxy": "http://proxy.corp.example:3128",
"upstream_ca_bundle": "/etc/ssl/corp-ca.pem"
```

Ovara's own requests go through that proxy (with the credentials in the URL,
if any) and the TLS it verifies trusts the bundle besides the system roots,
which is what a TLS-inspecting proxy or an internal CA needs. The agent sees
none of it: it still talks to Ovara only, with Ovara's CA, and `ovara env`
keeps pointing it there (the agents battery runs this way in CI, `UPSTREAM=1`
in `tests/agents`). Names are then resolved by the company proxy after
policy has allowed the request; an IP literal that is not public is still
refused by Ovara. `ovara doctor` checks both settings, and warns when this
shell has a proxy in its environment that `proxy.json` does not know about.

### Secrets, flows and who decides

Three rules that look at content, not only at the URL:

- **A secret-shaped value does not leave on a rule alone.** Before an
  allowed request goes out, its query and body are scanned for private
  keys, cloud and API keys, JWTs, card numbers and your own patterns
  (`dlp.patterns` in `proxy.json`); a match pauses for a person, who sees
  the kinds and counts and never the values (`content.sensitive`). Model
  requests are not scanned unless `dlp.include_model_calls` is set.
- **What was read from here may only go there.** A flow rule
  (`flows: [{"name": "crm", "sources": ["https://crm.example.com/*"],
  "destinations": ["https://crm.example.com/*", "https://tickets.example.com/*"]}]`)
  makes every write elsewhere a question for 30 minutes after a read from
  the source, with the source and its age shown (`flow.write`); `"effect":
  "deny"` refuses instead.
- **The right people decide.** `chat.slack.routes` send approvals of a kind
  (by action type, such as `tcp.connect` or `download.file`, or by resource
  pattern, such as `* https://prod.example.com/*`) to their own channel,
  decided only by the people listed for that route.

### Approvals from Slack

When nobody is at the terminal (a CI job, a box running overnight), paused
requests can go to a Slack channel and be answered there. Make a Slack app
with a bot token (scopes `chat:write`, and `channels:history`, or
`groups:history` for a private channel), invite the bot to the channel, put
the token on one line in `mydir/var/slack.token` (owner-only; or name a
variable with `token_env`) and add to `proxy.json`:

```json
"chat": {"slack": {"channel": "C0123ABCD", "allowed_users": ["U0AAAAAAA", "U0BBBBBBB"]}}
```

`ovara run` then posts every paused request to the channel as the approval
page shows it (destination, method, size, the redacted preview, the agent)
and takes the answer from a reply in that thread: `approve` or `deny`, a
reason after a colon. Only replies from the user IDs in `allowed_users`
count; everyone else, and every bot, is ignored, and with no IDs listed the
channel is told but cannot decide. The thread records who decided, and so
does the gateway (`slack:U0AAAAAAA`). Slack is polled, so nothing of yours
has to be reachable from the internet; a corporate `upstream_proxy` is
honoured. `ovara doctor` checks the setup. Channel and user IDs are in
Slack's channel details and profiles. This is tested against a stand-in for
Slack's API, not a live workspace yet.

### In GitHub Actions

One step puts the rest of the job behind Ovara. The action builds Ovara from
its own checkout (pin a release tag once there is one):

```yaml
- uses: SidianLabs/OVARA@main
  id: ovara
  with:
    profile: balanced          # strict (default) | balanced | observe
    rules: '[{"action_type":"http.request","environment":"*","resource":"POST https://api.github.com/repos/acme/app/pulls","allow":true}]'
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}   # keys go to Ovara, never to the agent
- run: opencode run "fix the failing test"     # HTTPS_PROXY and the CA are set: this goes through Ovara
- run: printf 'HTTPS_PROXY=\nHTTP_PROXY=\nhttps_proxy=\nhttp_proxy=\n' >> "$GITHUB_ENV"   # the rest of the job leaves Ovara (see below)
  if: always()
- uses: actions/upload-artifact@v4
  if: always()
  with:
    name: ovara-evidence
    path: |
      ${{ steps.ovara.outputs.dir }}/var/receipts.jsonl
      ${{ steps.ovara.outputs.dir }}/var/receipt_pubkey.hex
```

Every later step inherits Ovara's environment: its requests go through Ovara,
the real keys stay with Ovara (the steps see placeholders, and other
secret-looking variables are emptied), a request without a rule is held for
`hold-seconds` (10) and then told to retry (503), and when the job ends the
action's post step stops Ovara and writes the verified receipts to the job
summary, with the rules an `observe` run would have needed. Inputs: `profile`,
`rules` (a JSON array put in front of the policy), `policy` (a whole
`policy.json`), `hold-seconds`, `binary`; `slack-channel` and `slack-approvers`
send the job's paused requests to Slack (see above; the bot token goes in
the step's `env:` as `OVARA_SLACK_TOKEN`, and `hold-seconds` should then be
long enough for a person to answer). `.github/workflows/action.yml` runs it
against this repository on every change.

Everything after the step goes through Ovara, first-party actions included:
`upload-artifact` or `cache` would have their uploads to GitHub's services
held like any other write without a rule. Nothing of the agent's happens in
such a step, so take the rest of the job back out of Ovara first, as above:
one step writes empty `HTTPS_PROXY`, `HTTP_PROXY`, `https_proxy` and
`http_proxy` to `$GITHUB_ENV`. (Not in the step's own `env:`: the workflow
parser reads names without case, so the upper and lower spellings count as
one name given twice and the whole file is refused.) Or allow those hosts in
`rules` if you want them receipted.

### Several agents, and stopping one

`ovara status -dir mydir` is the deployment at a glance: the profile and policy
hash in force, whether an organisation baseline is set, the state of the
record, and for every agent whether it is active or stopped, how many requests
wait on a person, what it last did and how its last run ended (`-json` for a
dashboard).

Give each agent its own proxy token, so the log and every approval say
which agent it was, and you can stop one without stopping the rest:

```bash
ovara agent add reviewer -dir mydir              # or: ovara init mydir -agents reviewer,ci
eval "$(ovara env -dir mydir -agent reviewer)"   # this shell runs as "reviewer"
ovara agent list -dir mydir

ovara kill -agent reviewer -dir mydir            # stop it now (every agent without -agent)
ovara agent restore reviewer -dir mydir          # let it back in
```

Tokens live in `proxy.json` (owner-only) and are never printed; a running
Ovara picks up added and removed agents within a second. The original
`agent_token` keeps working as the agent `default`. A stopped agent's
requests are refused within a second ("this agent was stopped by its
operator"), what it was waiting on is denied, and it stays stopped after a
restart until you restore it.

An agent can be narrowed beyond the policy, and act for someone:

```bash
ovara agent add support -dir mydir -for alice@example.com \
    -allow 'GET https://api.example.com/*' -allow 'tcp:db.internal:5432'
ovara agent add triage -dir mydir -parent support -allow 'GET https://api.example.com/tickets/*'
```

A scoped agent acts only on what its `-allow` patterns name (the resource
as policy sees it: `METHOD url`, `tcp:host:port`); anything else is
refused before policy is asked, with a receipt (`agent_scope`). A sub-agent's
list must fit inside its parent's, so delegation can only narrow, and
stopping the parent stops its sub-agents. `-for` is shown with every
approval and recorded in every receipt of that agent's requests ("for:
alice@example.com"); it names, it never decides.

### Untrusted content and model spend

An agent that has just read something anyone can write (a GitHub or GitLab
issue, a pull request comment, a discussion, a page you approved from an
untrusted host) may be following instructions hidden in it. For 30 minutes
after such a read, every write the policy would normally let through
pauses, and the approval says what the agent read and how long ago. Writes
that already pause are unchanged, and the agent can keep talking to its
model. Tune or turn it off in `proxy.json`:

```json
"taint": { "on": true, "taint_window_minutes": 30 },
"model_budget": { "requests": 2000, "input_tokens": 50000000, "output_tokens": 10000000 }
```

`model_budget` caps model use per agent for the run: requests, and the
tokens the provider reports. Past it you are asked once; approving doubles
the allowance.

### MCP servers

An MCP server's tool descriptions are text the model reads and follows, and a
server can change them after you started trusting it. Ovara reads MCP traffic
(JSON-RPC 2.0) that goes through it:

- **Tool definitions are pinned.** The first time a server lists its tools,
  and whenever a definition changes or a new tool appears, a person sees the
  definitions (old and new side by side for a change) before the agent does.
  Hidden Unicode, instruction-like wording ("do not tell the user",
  `<IMPORTANT>`), mentions of other servers' tools and very long descriptions
  are flagged. A refused list never reaches the agent. Pins are kept in
  `var/mcp_pins.json`.
- **Every tool call is a question** (`mcp.tool_call`, resource
  `mcp:<host><path>/<tool>`) with its arguments shown, masked where they look
  like secrets. A tool whose definition was never approved is refused. Allow
  the tools you trust in `policy.json`:

```json
{ "action_type": "mcp.tool_call", "environment": "*", "resource": "mcp:mcp.example.com/mcp/search", "allow": true }
```

Remote servers are covered when the agent reaches them through the proxy
(Streamable HTTP, and the older HTTP+SSE transport). The policy must allow the
server's URL first: that `POST` pauses like any other write until a rule allows
it. For a **stdio** server, point the agent's MCP configuration at the wrapper
instead of the server:

```json
{ "mcpServers": { "files": {
    "command": "ovara",
    "args": ["mcp", "wrap", "-dir", "/srv/ovara", "-name", "files", "--", "npx", "-y", "@modelcontextprotocol/server-filesystem", "/work"] } } }
```

The wrapper means something only when it runs as a user the agent cannot act
as. An agent that can read the deployment directory, edit the pins or start
the server without the wrapper is not stopped by it. A stdio server that is
not wrapped is invisible to Ovara, and WebSocket transports are not
supported.

### APIs whose verb is in the body

A URL rule cannot tell a GraphQL query from a mutation, an AWS
`DescribeInstances` from a `TerminateInstances`, or a JSON-RPC getter from a
`sendTransaction`: they all go to the same POST. Once a rule allows the
POST, Ovara reads the body for the operation and decides it on its own:
reads pass and are named in the receipt; writes pause with the operation,
its variables (secrets masked) and the body hash in front of the person,
unless a rule names them:

```json
{ "action_type": "graphql.operation", "environment": "*", "resource": "graphql:api.github.com/graphql/mutation:AddComment", "allow": true }
{ "action_type": "aws.action", "environment": "*", "resource": "aws:dynamodb:PutItem", "allow": true }
{ "action_type": "jsonrpc.call", "environment": "*", "resource": "jsonrpc:node.example.com/rpc/eth_send*", "escalate": true }
```

`ovara policy suggest` proposes these from a run's held operations. The
read heuristics go by name (`Describe`, `List`, `Get`, a GraphQL `query`);
reads of secrets, parameters and tokens are not reads. `api_gate: false`
in `proxy.json` turns the gate off.

### Browser agents

A browser agent's writes are form posts, and what it fetches may be an
installer. Point the browser at Ovara like any other tool (`ovara env`
prints the proxy; Chromium takes `--proxy-server` and must trust the
interception CA, Playwright its `proxy` option) and a form post pauses like
any write, shown field by field with the page it was on, passwords and
credential-shaped values masked, uploads named with their type and size.
An executable or installer coming back on an allowed read is held and
asked about before the agent gets it (`download.file`). A site's session
cookie can be a credential binding (`"headers": {"Cookie": "..."}`): the
agent is logged in without ever holding the login. `docs/use-cases.md` §8.

### Any agent, any framework

The proxy sees what leaves over the network. What a framework's tools do
in-process (send an email through a library, delete a file, run a query) it
cannot see. The SDKs' **tool guard** closes that gap: wrap a tool and every
call is decided by the gateway before it runs, held for a person like any
other action, refused when policy says so, and reported when it is done.

```python
from ovara_sdk import ToolGuard
guard = ToolGuard("http://127.0.0.1:8080", api_key=AGENT_TOKEN, agent="support-bot")

@guard.tool("send_email")
def send_email(to: str, subject: str, body: str) -> str: ...
```

The person asked sees the tool, the size and hash of its arguments and a
preview with secret-looking values masked, in the CLI, the approval page or
Slack like everything else; the approval is bound to those exact arguments.
Rules name the tool (`"action_type": "tool.call"`, `"resource":
"tool:send_email"`); an unlisted tool pauses under `strict` and `balanced`
and is refused under `observe`. `createToolGuard` is the same in
TypeScript. `docs/use-cases.md` §5 has the LangChain and async forms, and
`tests/agents/harness.py` is a complete harness run in CI.

## How strong is the protection?

Be clear about what you are buying. Every promise, the mode it holds in and
the test that checks it is listed in [`docs/GUARANTEES.md`](docs/GUARANTEES.md),
together with what is *not* guaranteed. That file is the reference: a claim on
this page that goes further than it is a mistake.

- **Cooperative mode (what you get with `ovara env`).** Ovara controls every
  request that goes through it. A program that ignores the proxy setting can still
  reach the internet directly. This happens by accident too: Node's built-in
  `fetch()` ignores `HTTPS_PROXY` unless `NODE_USE_ENV_PROXY=1` is set, and any
  host on a `NO_PROXY` list from your shell is contacted directly; `ovara env`
  deals with both for you. So this mode stops a well-meaning agent from making
  mistakes, but it does not stop a determined, hostile one. Check `ovara log` to
  confirm your agent's traffic is actually showing up.
- **Enforced mode (`ovara run --boundary netns` or `--boundary docker`, Linux, needs root).**
  The agent runs somewhere with **no route to the internet except through Ovara**,
  so there is nothing to ignore. This is the setup to use when you do not fully
  trust the agent. See [`proxy/DEPLOYMENT.md`](proxy/DEPLOYMENT.md).
  Run the agent as a normal user inside it. Root in the boundary can remove the
  firewall rules.
- **Keys.** Credentials are only injected over HTTPS, and only on requests
  that match the binding's host, port, paths and methods. Ovara never hands
  the agent a key, but in cooperative mode the agent runs as you: it can
  read any key you left in your own files. For GitHub, prefer a GitHub App
  binding, which sends only short-lived tokens limited to the repository
  (see above); otherwise use a fine-grained token scoped to one repository.
  Never bind a key to a host that echoes requests back.
- **Plain HTTP and other protocols.** A connection that is not HTTPS (a
  database, mail, SSH) is decided, counted and receipted as an opaque
  tunnel (`tcp.connect`), not read: nothing inside it is inspected and no
  credential is injected into it.
- **The model API.** The agent may call its model's inference endpoint without
  asking (it has to). The proxy reads those requests and refuses features that
  would make the provider fetch a URL or connect to a server for the agent
  (MCP connectors, web fetch and search tools, images or documents by URL):
  those pause for approval. Other endpoints on the same hosts (files,
  batches) pause too.
- **What is checked is what is sent.** A model or MCP body that Ovara reads
  as JSON is forwarded in a canonical encoding of what it read (members
  sorted, numbers as written), not as the agent wrote it, so a provider or
  server cannot read something the check did not. Bodies with duplicate
  member names are refused. The `body_sha256` you approve is the hash of
  those canonical bytes.

Honest limits: whoever steals Ovara's signing key can forge receipts. Once you
revoke the key (`ovara keys revoke-receipt`), receipts dated after the
revocation are rejected, but backdated forgeries still verify. Hardware-backed
key protection (KMS/HSM) is not built yet. See [`SECURITY.md`](SECURITY.md) and
[`docs/OVARA_2.1_SECURITY_DECISIONS.md`](docs/OVARA_2.1_SECURITY_DECISIONS.md).

## What's solid and what isn't

| Part | Where | State |
|---|---|---|
| Gateway: policy, approvals, signed receipts, revocation | [`runtime/gateway`](runtime/gateway) | **Tested core.** Heavily tested, including adversarial suites |
| Proxy and the `ovara` command (`init`, `run`, `watch`, `demo`, `doctor`) | [`proxy`](proxy) | **Works.** Runs on Linux, macOS and Windows |
| Enforced network boundary | [`proxy/scripts`](proxy/scripts) | Linux only |
| `ovara box` (tier 1 and 2, command gate, commit-back, strict installs) | [`proxy/cmd/ovara`](proxy/cmd/ovara), [`docs/box.md`](docs/box.md) | **Works, Linux only, needs root.** Tested end to end in CI with three real agents. Not yet reviewed by an outside party, and no macOS/Windows version; see [`docs/GUARANTEES.md`](docs/GUARANTEES.md) for what it does and does not hold |
| TypeScript and Python SDKs | [`sdk`](sdk) | Working clients for the gateway API, not yet published to npm/PyPI |
| MCP/OpenAI integrations | `integrations` | **Experimental.** Partly built and not connected to the gateway yet; do not rely on them |
| Cloud control plane, admin dashboard, SSO, compliance | — | **Removed.** They could not talk to the gateway; see [`docs/decisions/cloud-control-plane.md`](docs/decisions/cloud-control-plane.md) |

## Where to go next

- **How it works, in depth:** [`docs/overview-full.md`](docs/overview-full.md) (the long-form overview with the architecture, primitives and API)
- **Deploying it:** [`proxy/DEPLOYMENT.md`](proxy/DEPLOYMENT.md) and [`docs/deployment.md`](docs/deployment.md)
- **Using the gateway API directly:** [`docs/api`](docs/api)
- **Where it fits (laptop, sandbox, CI, your own harness) and what is verified:** [`docs/use-cases.md`](docs/use-cases.md)
- **What Ovara guarantees, mode by mode, with the tests:** [`docs/GUARANTEES.md`](docs/GUARANTEES.md)
- **What Ovara does and does not protect against:** [`docs/threat-model.md`](docs/threat-model.md)
- **Where this is going (the plan for a sandbox standard, with the roadmap and its status):** [`docs/architecture/sandbox-standard.md`](docs/architecture/sandbox-standard.md)
- **Security model and reporting a vulnerability:** [`SECURITY.md`](SECURITY.md)
- **Contributing:** [`CONTRIBUTING.md`](CONTRIBUTING.md)

Apache 2.0. Copyright 2026 SidianLabs.
