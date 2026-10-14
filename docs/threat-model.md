# Threat model

What Ovara protects against, what it does not, and what you must do for the
protection to be real. This is the document to read before trusting Ovara
with anything you care about. It describes the code as it is, not as it is
planned to be. Each promise below, with the mode it holds in and the test
that checks it, is listed in [`GUARANTEES.md`](GUARANTEES.md).

## What Ovara is

A checkpoint on the network path between an AI agent and the internet. The
agent's requests go through a proxy; the proxy asks a policy engine (the
gateway) to **allow**, **escalate** (pause for a human), or **deny** each one;
real API keys are attached by the proxy so the agent never holds them; every
decision is written to a signed, hash-chained receipt log.

## What it can stop

| Threat | Mitigation | Holds when |
|---|---|---|
| A well-meaning agent makes a destructive call (`git push` to `main`, delete a branch, deploy) | Writes escalate to a human | The agent's traffic goes through the proxy |
| The agent leaks a secret it was given | The agent never holds your real keys; they are added upstream of it. `ovara env` also unsets other secret-looking variables in the shell it sets up (`-keep-env` to keep them) | You gave Ovara the keys, not the agent, and the agent does not run as your user with your files (see below) |
| A key used for more than it was meant for | A credential binding names a host and, optionally, a port (443 if none), paths and methods; the key goes only with requests that match. `ovara box` limits the GitHub key to the project's own repository. Reads of secrets, keys, emails and org members on the GitHub API pause by default, and a Slack API call is treated as a call even when it is a GET | The binding is scoped (`ovara box` does this for GitHub) |
| A long-lived key with wide reach is misused or leaks through an upstream that keeps or echoes what it receives | A brokered binding (`github_app`, `oauth2`) keeps the long-lived secret in Ovara and sends only a token minted per run: a GitHub installation token lives an hour and is limited to the listed repositories and permissions (to the project's repository under `ovara box`); OAuth tokens come from client credentials or token exchange. No token, no request: a failed mint refuses the request instead of sending it bare or with an old token | A brokered binding is configured instead of a static personal token |
| A reflected secret (a debug endpoint echoes the Authorization header) | Injected values and the bare token are scrubbed from response headers, header names, body and trailers, also in hex, base64 and case-changed spellings; signed URL parameters (`X-Amz-Signature`, `token=`, …) are redacted from credentialed responses; encoded or ranged responses on credentialed requests are refused | The request was credentialed, and the body is text (see below) |
| The agent reads private data and sends it to a server it controls | Reads are allowed only from a short list of trusted hosts; any other host pauses for approval; a read carrying a body, a long query, or more than 2 KB of path, query and headers is refused | The default policy is kept |
| Data smuggled in a host name (DNS exfiltration) | A host name is not resolved until policy has approved a request to it; inside the boundary, DNS is off unless you turn it on | Always |
| The agent sends data out through its own model API (an MCP connector, a web-fetch tool, an image "by URL" that the provider fetches) | Only the inference endpoints are allowed by default, and the proxy reads every model request body and pauses requests that use those features (`model_gate`) | The default policy is kept, and `model_gate` is on |
| An MCP server changes a tool's description after you trusted it (rug pull), hides instructions in it (tool poisoning), or describes another server's tools (shadowing) | Tool definitions are pinned per server; the first list, a new tool and a changed definition are shown to a person (old and new side by side, hidden characters and instruction-like wording flagged) before the agent sees them, and a refused list never reaches it | The server is reached through the proxy over HTTP, or a stdio server is started through `ovara mcp wrap` running as a user the agent cannot act as; `mcp_gate` is on |
| The agent opens a connection that is not HTTPS (a database, a mail server, SSH, a message broker) to move data or act where the proxy cannot read | A CONNECT to a port other than 443 is decided as `tcp.connect` on `tcp:<host>:<port>` before anything is dialled (paused by default; what the port suggests and that the tunnel is opaque are shown); an open tunnel's bytes each way are counted against the host's egress budget and receipted, and a stopped agent's tunnel is cut | `tcp_gate` is on (the default) and the agent's traffic goes through the proxy; the boundary drops what goes around it |
| The agent writes through an API whose verb is in the body: a GraphQL mutation at the endpoint its queries use, an AWS `DeleteTable` or `TerminateInstances` on the host its reads go to, a JSON-RPC `sendTransaction` | Once a URL rule allows the POST, the operation in the body is decided as an action of its own (`graphql.operation`, `aws.action`, `jsonrpc.call`): reads pass and are named in the receipt, writes pause by default with the operation, its variables (masked) and the body hash shown; an encoded body the gate cannot read is refused rather than sent unchecked | `api_gate` is on (the default); the read heuristics are names, not semantics |
| A browser agent submits a form it should not (a purchase, a password change, a message), or fetches an installer | A form POST pauses like any write, listed field by field with the page it was on, passwords and credential-shaped values masked, uploads named with type and size; an executable or installer coming back on an allowed read is held and asked about before the agent gets it (`download.file`) | The browser goes through the proxy and trusts its CA; the form is a plain POST (a site that writes through a GET is a read to policy) |
| The agent calls an MCP tool it should not (send an email, delete a repository) | Every tool call is decided by policy (`mcp.tool_call`, paused by default) with its arguments shown; a tool whose definition was never approved is refused | Same |
| A framework's own tool, run in-process (a mail library, a database driver, a file delete), does something it should not: the proxy never sees it | With the SDK tool guard around the tool, every call is decided by policy (`tool.call`, paused by default) with the arguments' hash and a masked preview shown, claimed once when approved, and its outcome reported; a report for a denied decision is kept as a security event | The tool is wrapped with the guard (code inside the agent: it binds an author who uses it, not one who removes it) |
| The agent adds its own credential (an account it controls) next to the one Ovara injects | On a host Ovara holds a key for, the agent's own credential headers are removed before the real one is attached, and the real one is set after hop-by-hop headers are stripped | Always |
| Instructions hidden in content the agent reads (an issue, a PR comment, a page from a host a person let it read) that make it write somewhere it may write | For 30 minutes after such a read, every write the policy would allow on its own pauses, with the source and its age in the approval (`taint.write`); receipts name the source | `taint` is on and the content is recognised as untrusted (see What it cannot stop) |
| A runaway or hijacked agent burning model spend | Model requests and the tokens their responses report are counted per agent for the run; past the allowance a person is asked once (`model.budget`) | `model_budget` is on |
| Not knowing which of several agents did something, or having to stop all of them to stop one | Each agent can have its own proxy token (`ovara agent add`); receipts and approvals carry its name; `ovara kill -agent NAME` refuses its requests within a second and denies what it is waiting on | Agents use their own tokens and do not run as the same user |
| A large volume of data through hosts the policy allows | Allowed traffic is metered per host (about 600 requests or 8 MB a minute by default, more for package registries); past that a person is asked once | The default `egress_budget` is kept |
| Data in host names: one new host per read, under a profile that allows reads from any host | The distinct unlisted hosts an agent reads are capped per run (50 by default); past that each further host is asked about once | The `balanced` or `observe` profile with the default `open_reads` |
| Edits to the log after the fact | Receipts are Ed25519-signed and hash-chained; `ovara log` and `ovara doctor` verify the chain, the key history and the anchors written as it grew, so a log that was cut short, or cut and continued, fails and is not appended to | The signing key, the log and the local anchors are not all under the agent's control (see below) |
| A request that leaves no trace | A request goes upstream only after its attempt receipt is on disk; if it cannot be written, the request is refused. The gateway turns an allow it cannot record into a deny | Always (unless `fail_open` is set) |
| A request held for approval is changed after the person looked at it | The whole body is read before asking (up to 1 MB; a larger one is refused) and only those bytes are forwarded; approvals expire after 10 minutes and one agent can have at most 64 waiting | Always |
| An answer from the wrong person in a chat channel, or from a bot | A thread reply decides only when it comes from a Slack user ID in `chat.slack.allowed_users`; bots and everyone else are ignored; the thread shows the same evidence as the approval page and records who decided | Approvals from Slack are set up with `allowed_users`; who can read the channel is the workspace's business |
| A push that also updates a protected branch, a deny rule dodged with a port or an escalate rule outranking a deny | Pushes are decided ref by ref; deny and escalate host rules apply on every port; a deny always beats an escalate | The policy uses most-specific precedence (what `ovara init` writes) |
| A rule that silently never matches | A rule without `action_type` or `environment`, or with conditions the gateway does not evaluate, stops the policy from loading | Always |
| A project loosening the organisation's policy (a rule added to its own `policy.json`, by a person or by an agent that can edit it) | An organisation baseline the project policy may only narrow: its denies are absolute, its escalations can only become denies, and every refusal it causes says `org baseline`. Signed; the gateway refuses to start when the signature does not verify | `policy_baseline_file` and `policy_baseline_pubkey` are set in the gateway's `config.json` |
| `ovara box`: the agent reads the host's files or the original project | Tier 1 gives the agent a root file system of its own: system directories read-only, the workspace, a fresh home, and nothing from `/home`, `/root`, `/srv`, `/opt`, `/mnt` or `/var`; other users' processes are hidden. Tier 2 is a container with nothing of the host mounted | `ovara box` without `-tier1-fs host` |
| `ovara box`: secrets in the project copy | Files with secret-looking names, and files whose content looks like a key or token, are left out of the copy and listed | `ovara box` |
| `ovara box` commit-back bringing back agent config, hooks or files hidden from review | Agent config, CI and hook paths are kept out by default; sensitive files are flagged; binary files stay out; a cut diff says what it leaves out; the branch is exactly the tree that was reviewed, built in a repository the agent never touched | `ovara box` is used |
| `ovara box -profile strict`: a package that is not what the lockfile pinned | A new dependency pauses once by name and version; an unrecognised download from a registry pauses; a download whose lockfile names a digest is checked as it streams and cut off if it differs | `-profile strict`, and the lockfile is yours (`-untrusted-lockfiles` otherwise) |
| A crash re-running an approved action | The "executing" claim is written to disk before the action runs; if that write fails the action is refused; an action interrupted by a crash is marked "outcome unknown" and never retried automatically | Always |
| Silent loss of approvals/receipts after tampering | A configured store that cannot be opened stops startup instead of starting empty | Always |

## What it cannot stop

- **An agent that does not use the proxy.** In *cooperative* mode (`ovara env`)
  the agent is only *asked* to use the proxy through environment variables.
  A hostile or buggy program can ignore them, and some do by accident (Node's
  `fetch()` ignores `HTTPS_PROXY` unless `NODE_USE_ENV_PROXY=1`). Check
  `ovara log` to confirm the traffic you expect is showing up.
- **An agent running as the same OS user as Ovara.** It can read Ovara's
  environment and files: the real API keys (via `/proc/<pid>/environ`), the
  policy (which reloads live), the signing key, the operator token. It can
  edit the policy to allow everything, re-sign a rewritten log, or approve its
  own requests. Run the agent as a **different user**. In cooperative mode
  the agent also runs with your user's files: "never holds a key" means
  Ovara does not hand it one, not that it cannot find one you left on disk.
- **An agent with another way out.** Without a network boundary, anything the
  agent can reach directly (a second proxy, a mounted socket, another process)
  is outside Ovara.
- **Approving the wrong thing.** What is approved is exactly what is sent:
  the whole body (up to 1 MB; 256 MB for a git push) is read before the
  person is asked, its SHA-256 is shown, and only those bytes are forwarded.
  The screen shows the method, the URL with its registrable domain and
  whether that host is trusted, the request headers, the query and the first
  400 bytes of a text body. Credential-shaped values and encoded blobs are
  masked but flagged with their size; bodies that cannot be shown (binary,
  compressed, multipart) are named as such. What a person cannot judge from
  that (the meaning of 400 bytes of a 1 MB upload) is still on them.
- **Data moved through a trusted read host.** Reads from the trusted hosts are
  free. Their query, path and headers are capped (512 bytes of query, 2 KB in
  all) and the number and size of requests to each host are metered, so the
  channel is narrow and slow, but an agent that controls an account on a
  trusted host can still use it. The policy limits *where*, not *what* (see
  below).
- **Derived credentials in binary bodies.** Signed URL parameters are
  redacted from text responses (JSON, XML, HTML, …). A signature inside a
  binary or unusual body type passes through. Do not bind a key to a host
  that reflects request data back.
- **`ovara box` tier 1 limits.** Tier 1 shares the host's kernel and has no
  PID namespace: the agent sees its own processes and can signal host
  processes of its own user only. `-tier1-fs host` turns the file-system
  isolation off and lets the agent read whatever its user can read on the
  host, including the original project; it is unsafe on a machine that
  holds secrets. Tools installed under `/opt` or a home directory are not
  visible unless you add them with `-mount` (read-only).
- **Commands the box's rules do not recognise.** Every command is seen and
  checked, but the default rules match command lines. An interpreter
  one-liner, a renamed copy of a binary or a script that deletes files
  itself is not caught by the `rm` rule. The network and file boundaries
  do not depend on these rules.
- **A stolen signing key.** Whoever holds the receipt or gateway key can forge
  receipts. Revoking the key makes later-dated forgeries fail, not backdated
  ones. Keys are files, not hardware-backed.
- **Rewriting the log and its local anchors together.** The local anchors
  (`var/anchors.jsonl`) catch a log that was cut or edited on its own, but
  they sit next to it. Only an off-host anchor (`gateway_anchor_mode` with
  `gateway_anchor_url`) survives someone who can write both. `ovara doctor`
  warns when it is off.
- **Untrusted content Ovara cannot recognise.** The taint rule marks an
  agent only after reads it can classify: approved reads, hosts trusted
  from an approval prompt, the `untrusted_reads` patterns (issues, pull
  request comments, discussions) and provider-side fetches. A README, a
  commit message or a file on a trusted host can carry instructions too,
  and does not mark the agent. The rule asks; it does not decide.
- **MCP outside Ovara's view, and what a pin cannot see.** A stdio MCP
  server that is not started through `ovara mcp wrap` never touches Ovara,
  and WebSocket transports are not supported. A pin covers what a server
  says a tool does, not what the server does when it is called; only tool
  lists and tool calls are checked, not resources or prompts. The warnings
  on a definition are hints, not detection.
- **Non-HTTP protocols.** Only HTTP and HTTPS through the proxy are inspected.
  A CONNECT to another port is decided and counted as an opaque tunnel
  (`tcp.connect`), never read: data inside it is not seen, and credentials
  are not injected into it. HTTP/2 and WebSockets are not supported through
  the interception, and gRPC only as such a tunnel.

## Modes

| | Cooperative (`ovara env`) | Enforced (`ovara run --boundary netns\|docker`, Linux) | `ovara box` tier 1 (Linux) | `ovara box` tier 2 (Linux) |
|---|---|---|---|---|
| Stops mistakes by a cooperating agent | yes | yes | yes | yes |
| Stops an agent that ignores the proxy | **no** | yes: no route except through Ovara | yes | yes: no interface but loopback |
| Agent can read Ovara's keys and policy | yes if same user | only if it runs as the same user; run it as another | no (separate user, own root) | no (nothing of the host mounted) |
| Agent can read the host's other files | yes | whatever its user may read | no (unless `-tier1-fs host`) | no |
| Every command checked | no | no | yes | yes |
| Platforms | Linux, macOS, Windows | Linux, root to set up | Linux, root | Linux, root, Docker |

On Windows and macOS only cooperative mode exists today. There, the
protection is "stops mistakes", and you should treat it that way.

## Assumptions you must make true

1. The agent runs as a different OS user than Ovara, with no read access to
   Ovara's directory. (`ovara doctor` checks file permissions, not users.)
   `ovara box` does this for you; in tier 1 the agent also gets its own
   root file system, unless you pass `-tier1-fs host`.
2. In enforced mode, the agent is not root inside the boundary.
3. The real API keys are given to Ovara's environment only.
4. `policy.json`, the keys, the logs and the stores are owner-only. Ovara
   writes them that way, and `ovara doctor` checks them on Linux and macOS.
5. For tamper-evidence that survives a compromised host, an anchor is
   configured somewhere the agent's user cannot write.
6. The interception CA is trusted only in the agent's environment, not
   system-wide on a machine you use for other things. It lives 30 days and
   is replaced when `ovara run` starts.

## The policy is part of the trust boundary

The default policy trusts a fixed list of hosts for reads (package registries,
code hosts, documentation). Anything you add to that list widens what an agent
can send out without asking. Reading `https://github.com/<anything>` is
allowed, so an agent can still move data through a URL on a trusted host if it
controls an account there; the policy limits *where*, not *what*.

## Reporting a vulnerability

See [`SECURITY.md`](../SECURITY.md).
