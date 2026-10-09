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
so the agent never holds a key it could leak. Every allow, pause and block is
written to a signed, tamper-evident receipt log you can verify later.

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

`ovara run` prints a link like `http://127.0.0.1:9090/#t=…`. Open it to get a
**local approval page**: whatever the agent is waiting on, with Approve and Deny
buttons, plus a live, integrity-checked history of what it did. The page is only
served to your own machine, and only someone holding the link's token can approve.
That token is made fresh each time `ovara run` starts and opens only this page,
never the gateway's admin API, so a link left in a log or scrollback is worth
little and stops working when Ovara stops.

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

Prefer not to sit at a terminal? `ovara approvals` lists what is waiting, and
`ovara approve <id>` / `ovara deny <id>` answer one request. A paused request
waits 60 seconds (`escalate_timeout_sec` in `proxy.json`); after that the agent
gets a timeout and can simply retry.

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
afterwards (to hide something, say), `ovara log` reports it as tampered.

### Your rules live in `mydir/policy.json`

The default policy `ovara init` writes is short and readable:

```json
{ "resource": "GET https://pypi.org/*", "allow": true },
{ "resource": "*://pastebin.com/*",     "deny": true },
{ "resource": "POST *",                  "escalate": true }
```

Reads are allowed only from a list of hosts an agent legitimately needs (package
registries, code hosts, documentation); `ovara policy` shows the full list. A
host that is not on it pauses for approval. A `GET` that carries a request body
or a very long query string is **refused** with an explanation (the path and
query of a read can carry data out), even on a trusted host. To trust another
host, add a rule for it to `policy.json`.

`allow` lets it through, `escalate` pauses it for you, `deny` blocks it. If more
than one rule matches, **deny beats allow, and allow beats escalate**. Anything not
matched is escalated. Edit the file; changes are picked up without a restart.

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

## How strong is the protection?

Be clear about what you are buying:

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
- **Plain HTTP and other protocols.** Credentials are only injected over HTTPS.
  Coverage of non-HTTP protocols is uneven.

Honest limits: whoever steals Ovara's signing key can forge receipts. Once you
revoke the key, receipts dated after the revocation are rejected, but backdated
forgeries still verify. Hardware-backed key protection (KMS/HSM) is not built yet. See [`SECURITY.md`](SECURITY.md) and
[`docs/OVARA_2.1_SECURITY_DECISIONS.md`](docs/OVARA_2.1_SECURITY_DECISIONS.md).

## What's solid and what isn't

| Part | Where | State |
|---|---|---|
| Gateway: policy, approvals, signed receipts, revocation | [`runtime/gateway`](runtime/gateway) | **Tested core.** Heavily tested, including adversarial suites |
| Proxy and the `ovara` command (`init`, `run`, `watch`, `demo`, `doctor`) | [`proxy`](proxy) | **Works.** Runs on Linux, macOS and Windows |
| Enforced network boundary | [`proxy/scripts`](proxy/scripts) | Linux only |
| TypeScript and Python SDKs | [`sdk`](sdk) | Working clients for the gateway API, not yet published to npm/PyPI |
| MCP/OpenAI integrations, policy compiler | `integrations`, `policy` | **Experimental.** Partly built and not connected to the gateway yet; do not rely on them |
| Cloud control plane, admin dashboard, SSO, compliance | — | **Removed.** They could not talk to the gateway; see [`docs/decisions/cloud-control-plane.md`](docs/decisions/cloud-control-plane.md) |

## Where to go next

- **How it works, in depth:** [`docs/overview-full.md`](docs/overview-full.md) (the long-form overview with the architecture, primitives and API)
- **Deploying it:** [`proxy/DEPLOYMENT.md`](proxy/DEPLOYMENT.md) and [`docs/deployment.md`](docs/deployment.md)
- **Using the gateway API directly:** [`docs/api`](docs/api)
- **Where it fits (laptop, sandbox, CI, your own harness) and what is verified:** [`docs/use-cases.md`](docs/use-cases.md)
- **What Ovara does and does not protect against:** [`docs/threat-model.md`](docs/threat-model.md)
- **Security model and reporting a vulnerability:** [`SECURITY.md`](SECURITY.md)
- **Contributing:** [`CONTRIBUTING.md`](CONTRIBUTING.md)

Apache 2.0. Copyright 2026 SidianLabs.
