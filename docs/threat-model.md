# Threat model

What Ovara protects against, what it does not, and what you must do for the
protection to be real. This is the document to read before trusting Ovara
with anything you care about. It describes the code as it is, not as it is
planned to be.

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
| The agent leaks a secret it was given | The agent never holds your real keys; they are added upstream of it | You gave Ovara the keys, not the agent |
| A reflected secret (a debug endpoint echoes the Authorization header) | Injected values and the bare token are scrubbed from response headers, body and trailers; encoded or ranged responses on credentialed requests are refused | The request was credentialed |
| The agent reads private data and sends it to a server it controls | Reads are allowed only from a short list of trusted hosts; any other host pauses for approval; a read carrying a body or a long query is refused | The default policy is kept |
| Data smuggled in a host name (DNS exfiltration) | A host name is not resolved until policy has approved a request to it | Always |
| The agent sends data out through its own model API (an MCP connector, a web-fetch tool, an image "by URL" that the provider fetches) | Only the inference endpoints are allowed by default, and the proxy reads every model request body and refuses those features (`model_gate`) | The default policy is kept, and `model_gate` is on |
| The agent adds its own credential (an account it controls) next to the one Ovara injects | On a host Ovara holds a key for, the agent's own credential headers are removed before the real one is attached | Always |
| Edits to the log after the fact | Receipts are Ed25519-signed and hash-chained; `ovara log` and `ovara doctor` verify the chain and check it against the anchors written as it grew, so a log that was cut short, or cut and continued, fails | The signing key, the log and the local anchors are not all under the agent's control (see below) |
| A request held for approval is changed after the person looked at it | The whole body is read before asking and only those bytes are forwarded; approvals expire after 10 minutes and one agent can have at most 64 waiting | Always |
| A push that also updates a protected branch, a deny rule dodged with a port or an escalate rule outranking a deny | Pushes are decided ref by ref; deny and escalate host rules apply on every port; a deny always beats an escalate | The policy uses most-specific precedence (what `ovara init` writes) |
| `ovara box` commit-back bringing back agent config, hooks or files hidden from review | Agent config, CI and hook paths are kept out by default; sensitive files are flagged; binary files stay out; a cut diff says what it leaves out; the branch is exactly the tree that was reviewed, built in a repository the agent never touched | `ovara box` is used |
| A crash re-running an approved action | The "executing" claim is written to disk before the action runs; if that write fails the action is refused | Always |
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
  own requests. Run the agent as a **different user**.
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
- **`ovara box` tier 1 and the file system.** Tier 1 gives the agent its own
  user and network namespace, not its own file system: it can read any file
  that user can read, including the original project. Use tier 2 when that
  matters.
- **A stolen signing key.** Whoever holds the receipt or gateway key can forge
  receipts. Revoking the key makes later-dated forgeries fail, not backdated
  ones. Keys are files, not hardware-backed.
- **Rewriting the log and its local anchors together.** The local anchors
  (`var/anchors.jsonl`) catch a log that was cut or edited on its own, but
  they sit next to it. Only an off-host anchor (`gateway_anchor_mode` with
  `gateway_anchor_url`) survives someone who can write both. `ovara doctor`
  warns when it is off.
- **Non-HTTP protocols.** Only HTTP and HTTPS through the proxy are inspected.
  CONNECT is limited to port 443; HTTP/2, gRPC and WebSockets are not
  supported through the interception.

## Modes

| | Cooperative (`ovara env`) | Enforced (`ovara run --boundary netns\|docker`, Linux) |
|---|---|---|
| Stops mistakes by a cooperating agent | yes | yes |
| Stops an agent that ignores the proxy | **no** | yes: no route except through Ovara |
| Agent can read Ovara's keys and policy | yes if same user | only if it runs as the same user; run it as another |
| Platforms | Linux, macOS, Windows | Linux, root to set up |

On Windows and macOS only cooperative mode exists today. There, the
protection is "stops mistakes", and you should treat it that way.

## Assumptions you must make true

1. The agent runs as a different OS user than Ovara, with no read access to
   Ovara's directory. (`ovara doctor` checks file permissions, not users.)
2. In enforced mode, the agent is not root inside the boundary.
3. The real API keys are given to Ovara's environment only.
4. `policy.json` and the keys are owner-only (`ovara doctor` verifies this on
   Linux and macOS).
5. For tamper-evidence that survives a compromised host, an anchor is
   configured somewhere the agent's user cannot write.

## The policy is part of the trust boundary

The default policy trusts a fixed list of hosts for reads (package registries,
code hosts, documentation). Anything you add to that list widens what an agent
can send out without asking. Reading `https://github.com/<anything>` is
allowed, so an agent can still move data through a URL on a trusted host if it
controls an account there; the policy limits *where*, not *what*.

## Reporting a vulnerability

See [`SECURITY.md`](../SECURITY.md).
