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

Then start your agent from a shell that routes it through Ovara:

```bash
eval "$(ovara env -dir mydir)"                 # bash / zsh
ovara env -dir mydir -shell powershell | iex   # PowerShell
claude                                           # or any agent: it now runs through Ovara
```

`ovara env` sets the proxy address (including the agent's proxy token) and
points every common certificate setting (Node, Python, curl, git, OpenSSL) at
Ovara's certificate, so Ovara can see inside HTTPS. It also sets placeholder
values for `GITHUB_TOKEN`, `ANTHROPIC_API_KEY` and the rest, so tools that won't
start without a key still start. Ovara swaps in the real key on the way out.
It also unsets other secret-looking variables it finds in that shell (tokens,
cloud keys); `-keep-env` keeps them. The certificate is meant for the agent's
environment only: do not install it system-wide.

Prefer not to sit at a terminal? `ovara approvals` lists what is waiting, and
`ovara approve <id>` / `ovara deny <id>` answer one request. A paused request
waits 60 seconds (`escalate_timeout_sec` in `proxy.json`); after that the agent
gets a timeout and can simply retry. An approval left unanswered expires after
10 minutes and can no longer be approved, and one agent can have at most 64
waiting. What you approve is exactly what is sent: the whole body is read
before you are asked (up to 1 MB; a larger one is refused), you see its
SHA-256, and only those bytes go out.

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
asked once. To trust another host, add a rule for it to `policy.json`, or use
"approve and trust this host for reads" on the approval page, which lasts until
`ovara run` stops.

`allow` lets it through, `escalate` pauses it for you, `deny` blocks it. If more
than one rule matches, **the most specific one decides** (more literal
characters in its pattern; among equals deny beats allow beats escalate), so
`POST https://api.github.com/repos/acme/app/pulls` allow next to `POST *` deny
means exactly that one write. Three guards keep that from being turned around:
a deny always beats an escalate; an allow only beats a deny if it names the
host at least as precisely; and deny and escalate rules for a host apply on
every port. A git push that updates several refs is decided ref by ref and
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

### Several agents, and stopping one

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

## How strong is the protection?

Be clear about what you are buying. Every promise, the mode it holds in and
the test that checks it is listed in [`docs/GUARANTEES.md`](docs/GUARANTEES.md),
together with what is *not* guaranteed. That file is the reference: a claim on
this page that goes further than it is a mistake.

- **Cooperative mode (what you get with `ovara env`).** Ovara controls every
  request that goes through it. A program that ignores the proxy setting can still
  reach the internet directly. This happens by accident too: Node's built-in
  `fetch()` ignores `HTTPS_PROXY` unless `NODE_USE_ENV_PROXY=1` is set, which
  `ovara env` does for you. So this mode stops a well-meaning agent from making
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
  read any key you left in your own files. Prefer fine-grained tokens scoped
  to one repository, and never bind a key to a host that echoes requests
  back.
- **Plain HTTP and other protocols.** Coverage of non-HTTP protocols is
  uneven.
- **The model API.** The agent may call its model's inference endpoint without
  asking (it has to). The proxy reads those requests and refuses features that
  would make the provider fetch a URL or connect to a server for the agent
  (MCP connectors, web fetch and search tools, images or documents by URL):
  those pause for approval. Other endpoints on the same hosts (files,
  batches) pause too.

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
- **Security model and reporting a vulnerability:** [`SECURITY.md`](SECURITY.md)
- **Contributing:** [`CONTRIBUTING.md`](CONTRIBUTING.md)

Apache 2.0. Copyright 2026 SidianLabs.
