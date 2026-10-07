# Ovara

**A checkpoint for AI agents. Reading is free, changing things needs your OK, and every decision leaves a receipt.**

You give a coding agent (Claude Code, Devin, a CI bot…) real tokens and let it
loose. One bad prompt and it force-pushes to `main`, deletes a branch, or posts
your API key to a paste site.

Ovara sits between the agent and the internet. Every request the agent makes goes
through it:

| The agent tries to… | Ovara… |
|---|---|
| read docs, install packages, `GET` an API | lets it through |
| `git push`, open or merge a PR, deploy, delete something | **pauses it and asks you** |
| send data to a paste site or file drop | blocks it |

It also keeps your real API keys itself and attaches them to outgoing requests,
so the agent never holds a key it could leak. Every allow, pause and block is
written to a signed, tamper-evident receipt log you can verify later.

> **Status: early (v0.9, pre-release).** The core described on this page works and
> is tested. The surrounding products (cloud control plane, dashboard, most
> framework integrations) are experimental, see [What's solid and what isn't](#whats-solid-and-what-isnt).

---

## See it in 30 seconds

```bash
git clone https://github.com/SidianLabs/OVARA.git
cd OVARA/proxy
go build -o ovara ./cmd/ovara      # needs Go 1.25+, works on Linux, macOS and Windows
./ovara demo                       # no setup, no network, no root
```

The demo plays out a tiny story: the agent **reads** something (allowed), tries to
**deploy** (paused, then approved by a pretend human), tries to **leak data**
(blocked), and then verifies the receipt chain.

## Use it for real

```bash
./ovara init mydir                 # writes keys, config, and a sensible default policy
export GITHUB_TOKEN=...            # the REAL keys go in Ovara's environment, not the agent's
export ANTHROPIC_API_KEY=...
./ovara run -dir mydir             # starts the gateway and the proxy
```

In a **second terminal**, answer what the agent asks to do:

```bash
./ovara watch -dir mydir
```

```
┌─ approval needed ─────────────────────────────────────
│ agent wants to: push to refs/heads/main on github.com/acme/app
│ waiting:        4s   id: apr_1e448924-ef74-48
└───────────────────────────────────────────────────────
  [a]pprove  [d]eny  [s]kip >
```

Then point your agent at the proxy and have it trust Ovara's certificate (Ovara
generates one so it can see inside HTTPS requests):

```bash
export HTTPS_PROXY=http://localhost:9443
export SSL_CERT_FILE=mydir/var/ca.pem
```

Prefer not to sit at a terminal? `ovara approvals` lists what is waiting, and
`ovara approve <id>` / `ovara deny <id>` answer one request.

### Your rules live in `mydir/policy.json`

The default policy `ovara init` writes is short and readable:

```json
{ "resource": "GET *",       "allow": true },
{ "resource": "*://pastebin.com/*", "deny": true },
{ "resource": "POST *",      "escalate": true }
```

`allow` lets it through, `escalate` pauses it for you, `deny` blocks it. If more
than one rule matches, **deny beats allow, and allow beats escalate**. Anything not
matched is escalated. Edit the file; changes are picked up without a restart.

## How strong is the protection?

Be clear about what you are buying:

- **Cooperative mode (what you get by just setting `HTTPS_PROXY`).** Ovara
  controls every request that goes through it. A program that ignores the proxy
  setting can still reach the internet directly, so this stops a well-meaning agent
  from making mistakes. It does not stop a determined, hostile one.
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
| Cloud control plane, dashboard, SSO, compliance, MCP/OpenAI integrations, standalone services | `cloud`, `apps`, `enterprise`, `integrations`, `services`, `policy` | **Experimental.** Partly built and not connected to the gateway yet; do not rely on them |

## Where to go next

- **How it works, in depth:** [`docs/overview-full.md`](docs/overview-full.md) (the long-form overview with the architecture, primitives and API)
- **Deploying it:** [`proxy/DEPLOYMENT.md`](proxy/DEPLOYMENT.md) and [`docs/deployment.md`](docs/deployment.md)
- **Using the gateway API directly:** [`docs/api`](docs/api)
- **Security model and reporting a vulnerability:** [`SECURITY.md`](SECURITY.md)
- **Contributing:** [`CONTRIBUTING.md`](CONTRIBUTING.md)

Apache 2.0. Copyright 2026 SidianLabs.
