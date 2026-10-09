# Where Ovara fits

Ovara sits between an agent and the network. What that is worth depends on one
question: **can the agent get to the internet without going through it?**
Everything below is organised around that. Each scenario says what is
verified, what is not, and what you must do yourself.

Labels used here:

- **Tested** — covered by `tests/scenarios` or `tests/boundary` against the real
  binary on Linux.
- **Mechanism tested** — the pieces it depends on are tested; the exact
  combination (a particular agent product, a particular sandbox vendor) is not.
- **Not tested** — it should work from how the pieces behave, but nobody has
  run it.

## Pick your setup

| You run the agent… | Mode | Stops a hostile agent? | Effort |
|---|---|---|---|
| in your own terminal, on your laptop | cooperative (`ovara env`) | no, only mistakes | minutes |
| in a container/VM on a Linux host you control | enforced (`--boundary`) | yes, if run as non-root | an hour |
| inside a vendor's hosted sandbox | cooperative, unless the vendor lets you force egress through a proxy | only if egress is forced | depends |
| unattended, in CI | cooperative, with an explicit policy | no | an hour |

## 1. A coding agent on your laptop  — *tested (mechanisms)*

The everyday case: Claude Code, Codex, Aider, a Cursor terminal, a script of
your own. You want reads to be free, a human to sign off on anything that
changes the world, and your keys kept out of the agent.

```bash
ovara init ~/ovara && ovara run -dir ~/ovara      # keep this running
eval "$(ovara env -dir ~/ovara)"                  # in the shell that starts the agent
claude                                            # or any agent
```

What you get, verified with `pip`, `npm`, `git clone`, Node `fetch()`, Python
`requests` and `curl`: package installs and docs just work; a `git push`, a
POST to an unknown host, or a delete pauses and shows you the URL, the query
string and the first bytes of the body (credentials masked); the real API key
never appears in the agent's environment, and if a response echoes it back it
is scrubbed; every decision is a signed receipt (`ovara log`).

What it does **not** give you here: containment. A program that ignores the
proxy settings goes straight out, and an agent running as your own user can read
Ovara's keys and edit `policy.json`. Treat this mode as a seatbelt against
mistakes and runaway tool use. `ovara log` tells you whether the traffic you
expected is actually passing through.

**opencode is tested for real** (`tests/agents/opencode.sh`, driven by a scripted
stand-in for the model so no API key is needed): through Ovara it installed its
own provider packages, and its bash tool ran `pip`, `git clone` and `npm install`
normally, was stopped at the paste site and the capture site, timed out on an
unapproved POST, and never saw the real key. Every attempt to evade the *policy*
through the proxy (trailing-dot and uppercase hosts, `user@host` URLs, odd ports,
decimal and IPv6 loopback, plain http, a mismatched Host header, method override,
a raw smuggled request line) was refused. Attempts to evade the *proxy*
(`curl --noproxy`, unsetting the proxy variables, Node `fetch` without the proxy,
raw TCP, `git` without the proxy) **did get out in this cooperative mode**, which
is exactly the limit described above, and were all blocked in enforced mode.
opencode also contacts `models.opencode.ai` on its own; Ovara pauses that as an
unknown host, which is harmless but visible in `ovara log`.

*Not tested:* other agent products (Claude Code, Codex, Aider). Their proxy and
certificate handling varies; if one ignores `HTTPS_PROXY` you will see it as
missing entries in `ovara log`.

## 2. An agent in a container or VM you control  — *tested (netns); docker mode scripted*

This is the setup to use when you do not fully trust the agent: an untrusted
tool, a model you are evaluating, a long unattended run.

The agent runs in a network that has **no route to the internet except to
Ovara**, so there is nothing for it to ignore. Run the agent as an unprivileged
user that is not the user running Ovara, in a directory it cannot read.

```bash
sudo ovara run -dir ~/ovara --boundary netns     # or: --boundary docker
# run the agent inside it as a separate user (the command is printed)
```

Verified on Linux (`tests/boundary`, and the 25-check suite in
`tests/redteam/boundary`, which also confirms the proxy path itself works so the
"denied" results are real refusals): only the proxy port is reachable from inside
the boundary; other host ports, ssh, the metadata address and direct internet
connections are dropped; IPv6 and ICMP are off; an agent without network
capabilities cannot flush the firewall or add routes; and
an agent running as a different unprivileged user cannot read the keys, edit the
policy, forge or delete receipts, approve its own requests (the proxy token does
not open the approvals API), or stop the process (`tests/redteam/separate-user`).

Still yours to ensure: the agent is not root inside the boundary (root can
remove the firewall rules), and nothing else gives it a way out (a second
proxy, a mounted socket). Linux only; Windows and macOS have no enforced mode.

## 3. A hosted agent sandbox (E2B, Daytona, Modal, Codespaces, …)  — *not tested*

Ovara is not something you install inside someone else's sandbox and trust: an
agent in the sandbox can see and modify it. The pattern that works is the same
as scenario 2, with Ovara **outside**: run it on a host or sidecar you control,
and configure the sandbox so its only egress is that proxy (most providers
accept an HTTP(S) proxy setting and a custom CA).

If the provider cannot force egress through your proxy, you are in cooperative
mode, whatever the setup looks like. Ask the provider specifically whether the
agent can open outbound connections that bypass a configured proxy.

## 4. A bot or agent in CI  — *not tested*

Nobody is there to click Approve. An unanswered approval times out (HTTP 504)
rather than passing, which is safe but means a default policy will fail the job
the first time the agent does something that needs approval. So write the
policy you actually want and leave nothing to a human:

- allow exactly the hosts the job needs (`GET https://registry.npmjs.org/*`, …),
- allow the specific write you expect (`POST https://api.github.com/repos/acme/app/pulls`),
- deny or leave everything else to time out.

Run Ovara in the same job as a background step and export the agent
environment from `ovara env`. This is cooperative mode: it limits what an agent
does by mistake, not what a compromised job can do.

## 5. Your own agent or agentic harness  — *mechanism tested*

For an agent loop you wrote (LangChain, an MCP client, a custom tool-calling
loop), there are two layers, and they cover different things:

- **Network calls** — anything your tools do over HTTP(S) can be routed through
  the proxy with the environment `ovara env` prints. No code changes. This
  covers API calls, package installs, `git` over HTTPS, web fetches.
- **Actions that are not network calls** — deleting local files, running a
  shell command. The proxy cannot see these. If you want them gated, call the
  gateway's decision API from your harness before executing
  (`POST /v1/runtime/check` with `action_type` `shell`, `exec`, …) and obey the
  answer. The TypeScript and Python clients in `sdk/` wrap this; they are not
  published to npm or PyPI yet.

The second layer is integration work you do yourself; Ovara will decide and
record, but only if your harness asks and honours the answer.

## 6. Evaluating or red-teaming an untrusted agent  — *tested (boundary)*

Running benchmark agents, or agents you do not trust, is the strongest fit:
use scenario 2 so the boundary does not depend on the agent cooperating, keep
the receipts as the record of what it tried, and expect a hostile agent to try.
The receipt log is signed and hash-chained, but without an off-host anchor
(`gateway_anchor_url`) whoever can write the Ovara directory can rewrite it, so
keep that directory out of the agent's reach.

## 7. Keeping keys out of the agent  — *tested*

Independent of the rest: put the real keys in Ovara's environment only
(`GITHUB_TOKEN`, `ANTHROPIC_API_KEY`, …, bound to hosts in `proxy.json`). The
agent gets placeholders, so a prompt injection that says "print your
environment" or "send your key to this URL" has nothing real to send. Verified:
the key is absent from the agent's environment, the upstream receives it, and a
reflected copy in a response is replaced with `[REDACTED]`. Keys are only
injected over HTTPS.

## What Ovara is not for

- **Non-HTTP traffic.** SSH, database protocols and raw TCP are invisible to the
  proxy. In enforced mode they are blocked (no route); in cooperative mode they
  are simply not seen. HTTP/2-only services, gRPC and WebSockets are not
  supported through the interception.
- **Stopping prompt injection.** It limits the damage an injected agent can do
  (it cannot push without you, cannot send to unknown hosts, never held your
  keys). It does not stop the agent being talked into trying.
- **What an allowed host can do.** Reads from a trusted host are free, so an
  agent with an account on that host (a gist, an issue comment) can still move
  data through it. The policy limits *where*, not *what*.
- **A root or same-user agent.** See scenario 2; that is a deployment
  requirement, not something Ovara can enforce for you.

See [`threat-model.md`](threat-model.md) for the full list of what holds in each
mode.
