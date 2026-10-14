# Where Ovara fits

Ovara sits between an agent and the network. What that is worth depends on one
question: **can the agent get to the internet without going through it?**
Everything below is organised around that. Each scenario says what is
verified, what is not, and what you must do yourself.

Labels used here:

- **Tested** — covered by `tests/scenarios`, `tests/agents`, `tests/redteam` or
  `tests/boundary` against the real binary on Linux.
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

**opencode, Anthropic's agent CLI and Codex CLI are tested for real** (`tests/agents`,
`tests/agents/run.sh coop|enforced opencode|anthropic|codex`). Each agent is
installed from npm and driven by a scripted stand-in for its model API
(OpenAI chat-completions for opencode, the Anthropic Messages API for
Anthropic's agent CLI, the OpenAI Responses API for Codex), so no API key is needed but every
command runs through the agent's own shell tool and network stack. The same 27
commands run for each agent:

- normal work: `pip`/`curl` reads from pypi.org, `git clone`, `npm install`
  (with its audit POST) all work;
- stopped: the paste site and the capture site (403), a GET carrying a body
  (403), an unapproved POST (paused, then 504); the real key is never in the
  agent's environment;
- every attempt to evade the *policy* through the proxy is refused:
  trailing-dot and uppercase hosts, `user@host` URLs, odd ports, decimal and
  IPv6-mapped loopback, plain http, method override, `..` paths, a raw smuggled
  request line; a mismatched Host header only reaches the URL's own host; no
  request to a blocked site is ever *allowed* in the receipts, and the receipt
  chain verifies;
- attempts to evade the *proxy* (`curl --noproxy`, unsetting the proxy
  variables, Python and Node without the proxy, raw TCP, direct DNS, `git`
  without the proxy) **do get out in this cooperative mode**, which is exactly
  the limit described above. In enforced mode (scenario 2) all seven are
  blocked.

Results on GitHub's runners (2026-10-09, PR #39): for each of the three
agents, cooperative mode 21 passed, 0 failed, 8 informational (the seven
proxy-evasion attempts that get out, plus one judged by receipts); enforced
mode and `ovara box` 28 passed, 0 failed.
The agents' own traffic is visible in `ovara log`: opencode fetches
`models.opencode.ai` and installs provider packages from npm; Codex contacts
`chatgpt.com` and posts to `ab.chatgpt.com`; Anthropic's agent CLI, with its
nonessential traffic switched off, sent nothing of its own. Unknown
hosts are paused, which is harmless but shows up as approvals to answer or
let time out.

*Not tested:* Aider (it proposes shell commands and asks before running them,
so the scripted battery needs a different driver), Cursor, and agents that are
not installed from npm. If an agent ignores `HTTPS_PROXY` you
will see it as missing entries in `ovara log`.

## 2. An agent in a container or VM you control  — *tested (netns, docker, `ovara box` tiers 1 and 2)*

*In Kubernetes, run Ovara as a sidecar: `deploy/kubernetes/` (a documented
recipe with manifests, not yet run in CI).*

This is the setup to use when you do not fully trust the agent: an untrusted
tool, a model you are evaluating, a long unattended run.

The agent runs in a network that has **no route to the internet except to
Ovara**, so there is nothing for it to ignore. Run the agent as an unprivileged
user that is not the user running Ovara, in a directory it cannot read.

```bash
sudo ovara box ./myrepo -- claude        # one command: copy, box, agent, review
```

`ovara box` does the whole setup: it copies the project into a workspace
(history kept; `.env`, keys, certificates and files whose content looks like
a key left out), starts Ovara with the namespace boundary, runs the agent
inside as an unprivileged user with a fresh home, a root file system of its
own and no keys, and when the agent exits brings its changes back as a
commit on a new `ovara/box-<run>` branch of your repository, after you have
read the diff. Paths the policy keeps out (`.github/workflows/*` by default)
never come back. Your working tree is not touched. Or do it by hand:

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
Real agents (opencode, Anthropic's agent CLI, Codex CLI) run inside the boundary as an
unprivileged user with the same 27 commands as scenario 1: normal work goes
through, and all seven proxy-evasion attempts that succeed in cooperative mode
are blocked (`tests/agents/run.sh enforced <agent>` and, through `ovara box`,
`tests/agents/run.sh box <agent>`: 28 passed, 0 failed for each). `tests/box`
checks the box itself: the agent sees no `.env`, no keys, no committed
certificate; it cannot read Ovara's directory; `git push` from inside goes
nowhere; its edits, new files, deletions and own commits come back on the
branch, a workflow edit does not, a committed secret is never deleted, and
the host's HEAD, branch and working tree are unchanged.

The box also checks every command the agent runs: each program is stopped
as it starts and matched against the policy (`shell:` rules). By default
development work runs freely and is counted, `sudo`, `mount`, firewall and
namespace changes are refused before they run, and `rm -rf`, `git push`,
`mkfs` and `dd` pause for you. The real agents ran their whole battery under
the gate (94 to 508 commands each) with nothing wrongly refused.

Also built: the container tier (`-tier 2`: no network interface but
loopback, no capabilities, a read-only root, nothing of your machine inside
but the project's copy) and strict installs (`-profile strict`: a new
dependency pauses once, by name and version, and pinned downloads are checked
against the lockfile's digests). Tier 1 now has a root file system of its
own too; `-tier1-fs host` is the old, unsafe behaviour. Not yet in `ovara
box`: macOS/Windows, and a profile that pauses on every command not on a
list. What each tier holds is in [`GUARANTEES.md`](GUARANTEES.md).

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

## 4. A bot or agent in CI  — *tested*

Nobody is there to click Approve. An unanswered approval never passes: after
the hold the agent is told to retry later (HTTP 503 with `Retry-After`; the
`escalate_on_timeout` setting in `proxy.json`), which is safe but means a
default policy will fail the job the first time the agent does something that
needs approval. So write the policy you actually want and leave nothing to a
human:

- allow exactly the hosts the job reads from (the defaults cover the package
  registries and code hosts; add `GET https://your.artifacts.host/*` …),
- allow the specific write you expect
  (`POST https://api.github.com/repos/acme/app/pulls`),
- deny the places you never want reached (`*://pastebin.com/*`, …),
- keep `escalate_timeout_sec` in `proxy.json` short (new deployments hold for
  10 seconds), because every other write waits that long and then gets 503.

"Allow this one write, deny every other write" is the natural CI policy:
`POST https://api.github.com/repos/acme/app/pulls` allow next to `POST *`
deny. With `"precedence": "most-specific"` (what `ovara init` writes) the
exact rule decides and every other write is refused at once. In an older
policy file without that field any deny wins, so the catch-all would also
block the allowed write; add the field, or keep the catch-all as an
escalation with a short timeout.

In GitHub Actions, `uses: SidianLabs/OVARA@main` does all of this in one step
(README, "In GitHub Actions"). By hand:
run Ovara in the same job as a background step (`ovara run -dir d -ui off &`,
wait for the proxy port, `eval "$(ovara env -dir d)"`). It stops on SIGTERM
when the job ends. This is cooperative mode: it limits what an agent does by
mistake, not what a compromised job can do.

Verified by `tests/scenarios/run.sh ci-bot` against the real binary: allowed
reads pass; an unapproved write and a read from an unlisted host are held for
the configured timeout and then told to retry (503), and their approvals stay
open for a person (approving one makes the job's retry run); under the
`balanced` profile the unlisted read goes through and the write still waits,
under `observe` the write is refused at once and `ovara policy suggest`
proposes rules from the receipts; the one allowed
write passes while a different write to the same host still stops; a dump site
is refused at once; a catch-all deny refuses instantly but also blocks the
allowed write; every decision is in the receipts, the chain verifies, and
`ovara run` exits on SIGTERM with the record intact.

If someone can be reached, approvals from Slack (README, *Approvals from
Slack*; `slack-channel` on the action) post each paused request to a channel
and take the answer from its thread, from the listed people only; with a
hold long enough the job waits for them.

## 5. Your own agent or agentic harness  — *mechanism tested*

For an agent loop you wrote (LangChain, an MCP client, a custom tool-calling
loop), there are two layers, and they cover different things:

- **Network calls** — anything your tools do over HTTP(S) can be routed through
  the proxy with the environment `ovara env` prints. No code changes. This
  covers API calls, package installs, `git` over HTTPS, web fetches.
- **Actions that are not network calls** — the functions your tools run
  in-process: sending an email through a library, deleting local files,
  running a query, a shell command. The proxy cannot see these. Wrap each
  tool with the SDK's **tool guard** and it is decided by the gateway before
  it runs, held for a person like any other action (who sees the tool, the
  arguments' hash and a preview with secrets masked), refused when policy
  says so, and reported when it is done:

  ```python
  from ovara_sdk import ToolGuard
  guard = ToolGuard("http://127.0.0.1:8080", api_key=AGENT_TOKEN, agent="support-bot")

  @guard.tool("send_email")
  def send_email(to: str, subject: str, body: str) -> str: ...

  tool = StructuredTool.from_function(guard.wrap(delete_file, "delete_file"))  # LangChain
  ```

  ```ts
  const guard = createToolGuard({ baseUrl, apiKey: AGENT_TOKEN, agent: "support-bot" });
  const sendEmail = guard.wrap("send_email", async (to: string, body: string) => { ... });
  ```

  A denied call raises `ToolDenied` and the function never runs; a held call
  waits for the answer (`wait_seconds`, 0 to fail fast and retry later with
  the approval id). Rules name the tool: `{"action_type": "tool.call",
  "resource": "tool:send_email", "escalate": true}`. The raw decision API
  (`POST /v1/runtime/check`, `/v1/runtime/outcome`) is there for a harness
  that wants to do this itself. The SDKs are not published to npm or PyPI
  yet: install them from `sdk/`.

The second layer is code inside your agent: Ovara decides and records, but
only the calls that go through the guard. `tests/agents/harness.py` is a
complete example, run in CI against a real gateway.

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

## 8. A browser or computer-use agent  — *mechanism tested*

A browser agent acts through pages: its writes are form posts and fetches,
its reads are navigations. Everything goes over HTTP(S), so it is a client
like any other, once the browser is pointed at Ovara and trusts its CA:

```sh
eval "$(ovara env -dir mydir)"            # HTTPS_PROXY and the CA path
chromium --proxy-server="$HTTPS_PROXY" --proxy-bypass-list="<-loopback>" ...
```

Chromium reads the system (NSS) store on Linux (`certutil -d sql:$HOME/.pki/nssdb -A -t C -n ovara -i "$SSL_CERT_FILE"`);
Playwright takes `proxy: { server }` and, under `ovara run`, `NODE_EXTRA_CA_CERTS`
is already set for Node. What changes for the person:

- **A form post** pauses like any write and is shown field by field, with the
  page it was submitted from (the Referer, without its query); a password or
  credential-shaped field is masked, an uploaded file is named with its type
  and size. The body hash still binds the approval to exactly those bytes.
- **An executable or installer** coming back on an allowed read (`.exe`,
  `.dmg`, `.sh`, `.msi`, ... by name or media type) is held and asked about
  before the browser gets it (`download.file` on `download:<host><path>`).
  Archives and documents are not asked about.
- **Logins stay out of the agent.** A site's session cookie, or an API
  token a site takes in a header, is a credential binding
  (`{"host": "app.example.com", "headers": {"Cookie": "session=${APP_SESSION}"}}`):
  the agent's own cookie is dropped on that host and the real one attached
  upstream of it, and it is scrubbed from what comes back.
- **A GraphQL mutation** behind a page's API, or a JSON-RPC method, is
  decided by the operation (§5 of the README: APIs whose verb is in the
  body), not only by its URL.

What it does not do yet: show the page's title or a screenshot (only its
URL), fill a password into a form from a binding, or decide a write a site
makes through a GET or a WebSocket. A browser that does not go through the
proxy (its own proxy settings, QUIC) is not seen; the box boundary stops
it from going elsewhere.

## What Ovara is not for

- **Reading non-HTTP traffic.** SSH, database protocols and raw TCP that go
  through the proxy (a CONNECT to a port other than 443) are decided as
  `tcp.connect` on `tcp:<host>:<port>`, held or refused like any action,
  and an open tunnel is counted and receipted, but nothing inside it is
  read and no credential is injected into it. Around the proxy such traffic
  is invisible: in enforced mode it is blocked (no route), in cooperative
  mode simply not seen. HTTP/2-only services and WebSockets are not
  supported through the interception; gRPC only as such a tunnel.
- **Stopping prompt injection.** It limits the damage an injected agent can do
  (it cannot push without you, cannot send to unknown hosts, never held your
  keys, and for a while after it reads an issue, a PR comment or another
  untrusted source, even writes the policy allows wait for you). It does not
  stop the agent being talked into trying.
- **What an allowed host can do.** Reads from a trusted host are free, so an
  agent with an account on that host (a gist, an issue comment) can still move
  data through it. The policy limits *where*, not *what*.
- **A root or same-user agent.** See scenario 2; that is a deployment
  requirement, not something Ovara can enforce for you.

See [`threat-model.md`](threat-model.md) for the full list of what holds in each
mode.
