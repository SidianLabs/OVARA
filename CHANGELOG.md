# Changelog

All notable changes to Ovara are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Focus: make the product usable and understandable for people running coding
agents, and fix correctness bugs found in an in-depth review.

### Changed: the box refuses the kernel entry points an agent has no use for

- Every box now runs the agent under one seccomp filter (tier 1, tier 2 and
  the VM box; tier 2 had none of its own, only Docker's default profile). It
  refuses new user, network and mount namespaces and the mount family,
  `io_uring`, `bpf`, `userfaultfd`, the key store, `perf_event_open`, kexec and
  module loading, the socket families `AF_ALG`, `AF_RDS`, `AF_KEY`,
  `AF_PACKET`, `AF_TIPC` and `AF_VSOCK`, four netlink protocols, the
  ptrace-class calls and foreign ABIs. It fails closed. The list, the answers
  and what real tools lose are in `docs/box.md` section 8.3. A tool that needs
  a refused facility now fails: a debugger gets `EPERM`, AddressSanitizer's
  leak check exits 1 unless `ASAN_OPTIONS=detect_leaks=0`, Chromium needs
  `--no-sandbox`, an agent's own bubblewrap sandbox cannot start (it runs
  without it, inside the box), and 32-bit programs cannot run.
- New launcher flags `-allow-user-namespaces` and `-allow-debuggers` lift the
  parts of the filter some tools need. They are flags only (not in the run
  manifest, events or attestation yet); a run started with either prints a
  note saying so.
- A tier 2 box starts the agent through the `ovara` binary as the agent's own
  user, so that binary must be readable and executable by everyone
  (`install.sh` now installs it `0755`); `ovara box` says so before starting
  if it is not.
- The docs no longer say the command gate's checked arguments cannot be
  changed. The filter removes the ptrace-class routes between box processes;
  closing the rest is on the roadmap.

### Fixed: `ovara box` on a terminal

- An interactive box hung. The agent (tier 1) or the docker client that runs
  it (tier 2) ran in a process group of its own, which on a terminal is a
  background group: its first read of the terminal stopped it, so an agent
  run with `ovara box ./repo -- <agent>`, the documented way in, sat at a
  prompt that never got a key. Piped runs, which is all CI did, were fine.
  Now the agent takes the terminal for as long as it runs, as a shell does
  for a foreground job: what you type reaches it, and Ctrl-C goes to the
  agent as it would without Ovara (it used to go to `ovara box`, which sent
  the agent SIGTERM). `ovara box` takes the terminal back when the agent is
  done. A run that is not on a terminal, or that `ovara box` itself is not in
  the foreground of, is unchanged.

### Added: short-lived credentials

- A credential binding can mint its token instead of holding one. A
  `github_app` binding keeps the App's private key in Ovara's environment
  and injects a GitHub App installation token limited to the repositories
  and permissions you list (or, with `ovara run -scope-repo` and
  `ovara box`, to the project's repository). It covers `api.github.com`
  and git over `github.com`. An `oauth2` binding gets a Bearer token by
  the client-credentials grant or by token exchange (RFC 8693).
- Tokens are reused until shortly before they expire and replaced; if no
  token can be minted the request is refused (`credential_unavailable`)
  and not sent. Minted tokens are scrubbed from responses and never
  logged.
- `ovara doctor` checks these bindings without calling the issuer: the
  required fields, the variables, and that the key file is an owner-only
  RSA key.

### Agents: untrusted input, model budget, names and a stop switch

- **Writes after an untrusted read pause.** For 30 minutes
  (`taint.taint_window_minutes` in `proxy.json`) after an agent reads
  content anyone can write, every write the policy would allow on its own
  pauses with the source and its age in front of the person (action type
  `taint.write`, resource `taint:<METHOD> <url>`). Untrusted reads are: a
  read a person approved, a read from a host trusted from an approval
  prompt, GitHub and GitLab issues, pull request comments and discussions
  (`taint.untrusted_reads`), and a model request whose provider-side fetch
  was let through. Writes the policy already pauses or blocks, model calls
  and git fetches are unchanged; a git push allowed by a ref rule is a
  write. Receipts record `untrusted_read` and `tainted_by:<source>`.
  `"taint": {"on": false}` turns it off. **Breaking:** an agent that reads
  an issue and then opens a pull request on a repository where the policy
  allows that now pauses once.
- **Model budget.** Model requests, and the tokens their responses report
  (JSON `usage` or streamed usage events, read within fixed bounds), are
  counted per agent for the run. Past 2000 requests, 50M input or 10M output
  tokens (`model_budget`) a person is asked once (`model.budget`); approving
  doubles the allowance.
- **Named agents.** `ovara agent add NAME` gives an agent its own proxy
  token in `proxy.json` (`agents`, owner-only, never printed); `ovara env
  -agent NAME` sets up a shell for it; `ovara init -agents a,b` creates them
  with the deployment; `ovara agent list` and `ovara agent remove NAME`
  manage them, and a running Ovara picks up changes within a second. The
  single `agent_token` keeps working as the agent `default`. Receipts
  record the agent's name in `agent`, and approvals show it.
- **`ovara kill [-agent NAME]`** stops an agent (every agent without
  `-agent`): the running proxy refuses its requests within a second with
  403 "this agent was stopped by its operator" and a receipt, its waiting
  requests stop waiting, and its pending approvals are denied. It stays
  stopped across restarts until `ovara agent restore NAME` (or `-all`).
- **Client authentication never turns itself off.** Once any client token
  is configured (`agent_token` or an agent), a reload cannot relax it:
  removing the last agent leaves a proxy that refuses every client (and
  logs that it does), and `ovara agent remove` warns about it.
- **Removed agents and stopped agents lose what they already have open.**
  Each request inside an open tunnel is checked against the agents
  configured now: a removed agent, or an old token for a name that got a
  new one, is refused with 403 and an `agent_removed` receipt, and the
  tunnel is closed. A response still being relayed when its agent is
  stopped or removed is cut within about a quarter of a second, the
  client connection is aborted rather than ended cleanly, and a receipt
  records it (`agent_stopped_mid_response`).
- **Approval caps are per agent.** The gateway keeps its 64 waiting
  approvals per agent name behind a proxy (from the approval's `agent`
  context), not per proxy, with a bound of four times that for one caller
  across all names; the proxy's own limit on requests held for a person is
  per agent too (64, and 256 in all).
- **More untrusted reads by default.** Pull request bodies, lists and
  diffs, commit comments, GitHub's numeric repository id paths
  (`/repositories/<id>/...`, which its pagination links use), issue, pull
  request and commit pages on the web, and GitLab's global lists and
  commit comments now mark the agent. The default policy also pauses
  organization member reads by numeric organization id.
- **Receipts name every approval.** When a request was asked about more
  than once (its URL, then a package, taint or budget question), the
  earlier approvals are listed in the receipt's `reasons` as
  `approval:<id>`; `approval_id` keeps naming the last one. The receipt
  format is unchanged.
- **A deny for a ref covers deleting it.** A deny or escalate rule written
  for a ref (`... refs/heads/main`) now also matches its deletion
  (`refs/heads/main(delete)`); allow rules still cover a deletion only
  when they say `(delete)`.
- **Tier 1 refuses a /proc that shows the host's processes.** On a kernel
  before 5.8 the box's `/proc` cannot hide other users' processes; an
  isolated tier 1 box now refuses to start there unless
  `-allow-visible-procs` is given.

### Security hardening (October 2026)

A review of the whole product found ways around several promises. They are
fixed below. What Ovara promises now, mode by mode and with the test behind
each promise, is in [`docs/GUARANTEES.md`](docs/GUARANTEES.md).

**Breaking changes** (things you may notice after upgrading):

- A CONNECT to a port other than 443 is held for a person (or decided by a
  `tcp.connect` rule) instead of being refused at once; `tcp_gate: false`
  in `proxy.json` keeps the refusal.
- A GraphQL mutation, an AWS write action or a JSON-RPC write method in a
  POST a rule allows is held for a person unless a rule names it;
  `api_gate: false` turns that off.
- The model API is limited to the inference endpoints. Other endpoints on
  the model hosts (files, batches, …) pause for approval, and a model
  request that asks the provider to fetch a URL or reach a server (MCP
  connectors, web tools, images or documents by URL) pauses too.
- A policy rule without `action_type` or `environment` stops the policy
  from loading. Such rules never matched; now you are told.
- Under most-specific precedence, a matching deny always beats an escalate,
  and deny and escalate host rules apply on every port.
- Pending approvals expire after 10 minutes (`approval_pending_ttl_secs`),
  and one agent can have at most 64 waiting.
- A request body that needs review is read in full first and is capped at
  1 MiB (`max_held_body_bytes`; 256 MiB for a git push). A larger one is
  refused with `body_too_large_to_review`.
- Reads are capped at 2 KB of path, query and headers together
  (`max_read_request_bytes`).
- Allowed traffic is metered per host (about 600 requests or 8 MB a
  minute, more for package registries); past that a person is asked once
  (`egress_budget`).
- The interception CA now lives 30 days and is replaced at start when it is
  close to expiry. Every CA made by an earlier version is replaced once, on
  the first start: restart your agents, and refresh any copy you installed
  elsewhere.
- The default Slack binding is `slack.com`, not `*.slack.com`. Existing
  `proxy.json` files keep what they say.
- A credential binding whose secret is shorter than 8 bytes stops startup.
- `ovara env` unsets other secret-looking variables in the shell it sets up
  (`-keep-env` to keep them).
- `ovara box` tier 1 runs the agent in a root file system of its own. Tools
  under `/opt` or a home directory, and scripts under `/tmp`, need `-mount`.
  `-tier1-fs host` restores the old behaviour, which is unsafe.
- DNS inside an enforced boundary is off unless `OVARA_BOUNDARY_DNS=1`.
  Boundary setup stops (exit 3) when the host side cannot be firewalled;
  `-allow-unhardened-boundary` goes on anyway.
- Proxy receipts are format v2 (attempt and outcome receipts). Older logs
  still verify. The SDK verifiers read v1 only for now.
- `ovara init` no longer prints the operator token; it is in `config.json`.
- `receipts_max_age_minutes` is gone. It was never applied; configs that
  set it still load.
- `ovara-anchor` no longer takes `--operator-token`; use
  `--operator-token-file` or `OVARA_ANCHOR_OPERATOR_TOKEN`.

**Network egress**

- Method spelling no longer matters: `get` is checked like `GET`.
- An allowed `git-upload-pack` POST must be a real git fetch; any
  `git-receive-pack` POST is treated as a push.
- Long resources are refused rather than cut in the receipt.
- The proxy listens on the boundary address and loopback only, never on
  every interface, and the host side of the boundary is always firewalled
  (iptables, or nft when there is no iptables).

**Approvals**

- What you approve is exactly what is sent: the body's SHA-256 is shown and
  only those bytes are forwarded.
- The approval shows the request headers, the registrable domain in bold
  and whether that host is trusted, and says why a body is not shown.
- Terminal control, bidi and invisible characters are escaped in `ovara
  watch` and `ovara approvals`. Pending requests are listed oldest first,
  and keys typed before a request appears do not answer it.
- "Trust this host for reads" lasts until `ovara run` stops.
- A taken approval-page port stops `ovara run`; `-no-ui` runs without it.
- Identical pending requests share one approval.

**Credentials**

- Bindings can name a port, paths and methods. Without a port, a key goes
  to port 443 only.
- `ovara box` limits the GitHub key to the project's repository
  (`-github-scope all` turns this off); `ovara run -scope-repo` does the
  same by hand.
- GitHub API reads of secrets, keys, emails, org members and gists pause by
  default. A GET to the Slack API is shown as a call.
- Reflected keys are also scrubbed in hex, base64 and case-changed
  spellings and from header names; signed URL parameters are redacted from
  credentialed text responses.
- The CA can only sign site certificates (path length 0); site
  certificates live at most 24 hours. `ovara doctor` warns before the CA
  expires.

**Audit log**

- No request goes upstream without its receipt on disk, and the gateway
  does not allow what it cannot record.
- Receipt v2 adds the agent, the matched rule, the policy hash, the
  approver, sizes, the body hash and the key id, signed over an unambiguous
  encoding. Lines must be byte-canonical.
- `ovara keys rotate-receipt | revoke-receipt | list-receipt` keep a key
  history; verification respects it.
- `ovara log -verify-only`, `ovara log export -format jsonl|ocsf` and
  `ovara incident bundle` (verifiable offline).
- A log that was cut short, or cut and continued, fails verification, and
  `ovara run` will not append to it. `ovara doctor` says "anchored" only
  when anchoring is on.
- Gateway journals are format v2 (strict, time-bound to key state); stores,
  logs and keys are owner-only. The gateway's HMAC receipt prefix is now
  `hmac_v1:`.
- An action interrupted by a crash is marked "outcome unknown" and never
  retried automatically.
- In degraded anchor mode, a push that failed during an oracle outage is
  retried until it lands.

**Box**

- Tier 1's own root file system: host system directories read-only,
  nothing from home directories, `/root`, `/srv`, `/opt` or `/var`, other
  users' processes hidden, no_new_privs, and the proxy token on no command
  line. `-mount` works in tier 1.
- The project copy also leaves out files whose content looks like a key or
  token.
- Commit-back lands exactly the reviewed tree, built in a repository the
  agent never touched; agent config, CI and hook paths are kept out;
  sensitive files are flagged; binary files stay out unless
  `-allow-binary`; a cut diff says what it leaves out.
- Command rules match a normalised command line (`rm -r -f` reads as
  `rm -rf`), with new default pauses for `find -delete`, `shred` and agents
  started with their permission checks off.
- Strict installs name Ruby and Maven packages, ask about unrecognised
  registry downloads, and check downloads against lockfile digests.
  `-untrusted-lockfiles` for repositories you are reviewing.

**Policy semantics**

- Decisions and receipts name the rule that decided and the policy's
  content hash (`GET /v1/policy` shows it).
- A git push is decided ref by ref; an allow for refs does not cover
  deleting them unless it says `(delete)`.

**Spec 0.1**

- `spec/` writes down the four contracts another implementation, or a tool
  embedding this one, has to agree with: the resource model (canonical
  forms per action type), the policy document and precedence, the decision
  API (roles, check, approvals, claim) and the receipt chain (line format,
  signing form, keys, anchors, verification), with JSON Schemas for the
  policy document, the decision request and response and the receipt line.
  Drift tests next to each type (`spec_schema_test.go` in
  `runtime/gateway/internal/policy`, `internal/models` and
  `proxy/internal/receipts`) fail when a member is added to the code or a
  schema without the other. 0.1 means "what the code does today"; 1.0
  waits for the external review and a second implementation.
- **C5, the sandbox runtime, as the box's arguments and results**
  (`spec/runtime.md`, `proxy/internal/sandbox`). `ovara box -print-manifest`
  writes the run a command line describes as a manifest (tier, workspace,
  agent, profile, isolation, mounts, limits, credential scope, commit-back;
  never a secret: a variable whose name says it is a key is refused); `ovara
  box -manifest FILE` runs one, flags next to it winning. `ovara box -events
  FILE` streams what happens as JSON lines: `run.created` with the manifest,
  the workspace, the proxy, the agent, every command the gate decided with
  its approval id, the agent's exit, how the changes ended, and `run.finished`
  with a summary (outcome, exit code, request and command tallies, the
  branch that landed, the error). `ovara box -agent NAME` runs the box as a
  named agent. Schemas `manifest.schema.json` and `event.schema.json` with
  drift tests; the box end-to-end suites check a real run's stream.
- **Policy profiles: `strict`, `balanced`, `observe`** (`ovara init -profile`,
  `ovara policy profile`). Strict is the policy as it was. Balanced answers
  "do I have to list every website?" with no: reads from any public host
  are allowed, each read bounded (`max_read_request_bytes`), metered per
  host (`egress_budget`), capped per agent and run by distinct unlisted
  host (`open_reads` in `proxy.json`, 50 by default; past it each further
  host pauses once, action type `egress.open_hosts`) and receipted, and a
  write soon after an untrusted read still pauses; writes, credentialed
  reads of secrets, tool calls and dump sites are decided as before.
  Observe is for a first run: reads free; writes, provider-side fetches and
  MCP tool calls refused at once, never held; then `ovara policy suggest`
  turns the verified receipts into the rules a strict policy would need
  (one read allow per unlisted host, one exact allow per refused or held
  write, never a wildcard write). A profile's rules are marked and
  switching replaces only them. (`ovara box -profile dev|strict` is
  unchanged: it is about installs.)
- **Approve and remember, with scopes.** "Trust this host for reads"
  becomes one of four: reads from this host until `ovara run` stops
  (`reads-run`, as before) or for the project (`reads-project`, kept after
  the run), exactly this command line in the box for the run
  (`command-run`), this MCP tool for the run (`tool-run`). Each is offered
  only where it applies (the approval page shows one button per scope,
  `ovara watch` one numbered choice each, `ovara approve -remember SCOPE`),
  a write is never remembered, a resource with a wildcard offers nothing,
  and every remembered rule names who, when and the approval. Run-scoped
  rules go when the run ends, whatever they were for.
- **Behind a corporate proxy.** `proxy.json` takes `upstream_proxy`
  (http(s)://host:port, credentials allowed) and `upstream_ca_bundle` (a
  PEM file trusted besides the system roots). Ovara's own requests, the
  credential broker's included, go through the proxy, and TLS to the
  world is verified against the bundle: what a TLS-inspecting proxy or an
  internal CA needs. The agent still talks to Ovara only, with Ovara's
  CA. Names are then resolved by the upstream proxy after policy allowed
  the request; a non-public IP literal is still refused. `ovara doctor`
  checks both and warns when the shell's proxy is not in `proxy.json`.
- **A GitHub Action.** `uses: SidianLabs/OVARA@<ref>` (action.yml at the
  root) builds Ovara from the action's checkout, starts it for the job with
  a profile, extra rules or a whole policy, and hands every later step the
  environment that routes it through Ovara (`ovara env -shell github`, new:
  NAME=value lines for `$GITHUB_ENV`; the proxy token is masked in logs).
  Its post step stops Ovara and writes the verified receipts to the job
  summary, with `ovara policy suggest` under the observe profile. The
  `Action` workflow runs it against this repository.
- **An organisation's baseline policy.** `policy_baseline_file` in the
  gateway's `config.json` names a policy the project's `policy.json` may
  only narrow: its denies are absolute, its escalations can only be
  tightened to denies, its allows stand unless the project has a rule, and
  every refusal it causes names it (`org baseline: ...`). `policy_hash`
  covers both layers. Signed with `ovara policy baseline keygen|sign` and
  pinned by `policy_baseline_pubkey`, a baseline that does not verify stops
  the gateway instead of being skipped; `ovara doctor` checks it and warns
  when it is unsigned. Spec: `spec/policy.md` §6. A refusal's body also
  carries a `hint` saying which layer refused and what can change it.
- The agents battery (`tests/agents`) also runs under the `balanced`
  profile (`PROFILE=balanced`: every blocked-site check still holds) and
  behind an upstream CONNECT proxy (`UPSTREAM=1`: Ovara's own traffic goes
  through it, a denied host never reaches it), as two more CI jobs.
- **An attestation for every run.** `ovara run`, `ovara run -- <agent>` and
  `ovara box` end by writing `var/attestations/<run>.intoto.json`: an
  in-toto statement in a DSSE envelope, signed with the receipt key, whose
  subjects are the run's receipts and the commit the changes landed as, and
  whose predicate carries the policy hashes, the exact receipts (position,
  count, hash, chain head), every approval and approver, the host table,
  the summary and, for a box, the manifest's digest. `ovara attest verify`
  checks it offline from the incident bundle (which now carries the
  attestations), recomputing every claim from the receipts; `attest list`
  and `attest show` read them. The `run.finished` summary names the file,
  and the GitHub Action's job summary shows the verification. Spec:
  `spec/evidence.md` §8, `spec/schemas/attestation.schema.json`;
  `docs/GUARANTEES.md` 5.7.
- **`ovara status`**: the deployment at a glance, the fleet view at the
  scale of one deployment: profile, policy hash, organisation baseline, the
  record's state, and for every agent (named ones, the default token,
  stopped ones, and labels the receipts name that have no token now) its
  state, the approvals waiting on a person, what it last did and how its
  last run ended, from the attestations. `-json` for a dashboard.
- `ovara doctor` reports the receipt chain's size and the number of
  attestations, and warns past 256 MiB; `docs/operations.md` has a
  retention and export section (scheduled export, bundling, rotating the
  deployment directory).
- **Approvals from Slack.** `chat.slack` in `proxy.json` (a channel ID, the
  user IDs allowed to decide, a bot token in `var/slack.token` or a named
  variable) makes `ovara run` post every paused request to the channel as
  the approval page shows it and take the answer from a reply in the
  thread (`approve` or `deny`, a reason after a colon). Only the listed
  people decide; bots and everyone else are ignored, and with nobody listed
  the channel is told but cannot decide. Slack is polled (nothing listens),
  through `upstream_proxy` when set. The GitHub Action takes
  `slack-channel` and `slack-approvers`, with the token as
  `OVARA_SLACK_TOKEN` in the step's env. `ovara doctor` checks the setup.
  Tested against a stand-in for Slack's API, not a live workspace yet.
- **A tool guard for any agent framework.** `ToolGuard` (Python) and
  `createToolGuard` (TypeScript) wrap the functions a framework's tools
  run in-process, which the proxy cannot see. Every call is decided by the
  gateway first (`tool.call`, resource `tool:<name>`), with the arguments'
  size, SHA-256 and a preview with secret-looking values masked as the
  approval's context; a deny raises and the function never runs; an
  escalation opens an approval and waits (`wait_seconds`, 0 to fail fast
  with the approval id; the identical call gets a late answer back) and
  claims it before running; an unreachable gateway means the tool does not
  run. Afterwards the guard reports how it went to the new
  `POST /v1/runtime/outcome` (agent credential; owner or operator only;
  once; a report for a denied decision is refused and kept as a security
  event), recorded as an `action.outcome` event. `ovara approvals` and
  Slack show a tool call as "call tool <name>" with its framework and
  argument hash; the observe profile refuses every guarded call. Spec:
  `spec/decision-api.md` §2.1, `spec/resource-model.md`;
  `docs/GUARANTEES.md` 2.5. The agents harness in CI exercises it against
  a real gateway. Gateway-decided calls are in the gateway's receipts and
  events, not yet in the proxy's receipt chain or the run attestation.
- **A TCP gate for connections that are not HTTPS.** A CONNECT to a port
  other than 443 (a database, a mail server, SSH, a broker, gRPC) used to
  be refused outright. It is now decided as `tcp.connect` on
  `tcp:<host>:<port>` before anything is dialled or resolved: an unlisted
  destination pauses for a person (who sees what the port suggests the
  connection is for and that the tunnel is opaque), a rule allows or
  refuses it, the observe profile refuses it. An allowed tunnel is
  receipted twice (`CONNECT tcp://host:port`: the attempt before the first
  byte, the outcome with the bytes each way), its bytes are charged to the
  host's egress budget every 256 KiB and a refused charge cuts it, a
  stopped agent's tunnel is cut, and it goes through `upstream_proxy` when
  one is set. Nothing inside the tunnel is read and no credential is
  injected into it. `ovara policy suggest` proposes the `tcp.connect` rules
  a run needed. `tcp_gate: false` in `proxy.json` restores the flat
  refusal. Spec: `spec/resource-model.md`; `docs/GUARANTEES.md` 1.11.
- **APIs whose verb is in the body are decided by that verb.** Once a URL
  rule allows a POST, the proxy reads its body for a GraphQL operation
  (`graphql.operation`, `graphql:<host><path>/<kind>:<name>`;
  `operationName` picks among several), an AWS JSON or Query API action
  (`aws.action`, `aws:<service>:<Action>`, from `X-Amz-Target` or
  `Action=`) or a JSON-RPC method (`jsonrpc.call`,
  `jsonrpc:<host><path>/<method>`; MCP stays the MCP gate's). The
  operation is named in the receipt; a read (a query, an AWS `Describe`,
  `List`, `Get` and the like but never a read of a secret or token, a
  method whose name says it reads) passes; everything else is a question
  of its own, with the operation, its kind, the variables or params
  (credential-shaped values masked) and the body hash shown, unless a rule
  decides it. A gzip body is read; an unreadable encoding where an
  operation could be inside is refused rather than sent unchecked; a
  JSON-RPC batch is refused. `ovara approvals` and Slack say "run GraphQL
  mutation CreateIssue at ...", "call AWS ec2 TerminateInstances", "call
  JSON-RPC method ..."; `ovara policy suggest` proposes rules for held
  operations. `api_gate: false` in `proxy.json` turns it off.
  `docs/GUARANTEES.md` 1.12.
- **Browser agents: forms and downloads.** A form post (url-encoded or
  multipart) is shown to the person field by field (`form`), a password
  or credential-shaped field masked, uploads named with type and size
  (`uploads`), with the page it was submitted from (`from_page`: the
  Referer or Origin without its query); the body preview and hash stay.
  An executable or installer coming back on a read a rule allowed (`.exe`,
  `.msi`, `.dmg`, `.pkg`, `.deb`, `.rpm`, `.apk`, `.sh`, `.ps1`, `.bat`,
  `.jar`, ... by the name `Content-Disposition` gives, the URL's last
  segment or the media type) is held and asked about before the agent
  gets it (`download.file` on `download:<host><path>`, the file's name,
  type and size shown); a refusal drops the response and is receipted.
  The observe profile refuses such downloads. `docs/use-cases.md` §8 says
  how to point Chromium or Playwright at Ovara and how a session cookie
  binding keeps a login out of the agent. `docs/GUARANTEES.md` 1.13, 2.2.
- **Agent scopes: sub-agents that can only narrow, and on-behalf-of.**
  `ovara agent add NAME -allow PATTERN... -parent P -for WHO` (and
  `agent_scopes` in `proxy.json`) limits a named agent to the resources
  its patterns name, as policy sees them (`METHOD url`,
  `tcp:host:port`); anything else is refused before policy is asked and
  receipted (`agent_scope`). A sub-agent's list must fit inside its
  parent's, checked when it is added and whenever `proxy.json` is read
  (a file that breaks it leaves the running proxy on its previous
  agents); stopping an agent stops its sub-agents; a parent with
  sub-agents cannot be removed first. `-for` names who the agent acts for:
  shown with every approval (`for: …`), written into every receipt of its
  requests (`for:<who>`), never used to decide. `ovara agent list` shows
  the scopes. `docs/GUARANTEES.md` 7.5.
- **Content rules, flow rules and approval routes.** Before a request a
  rule allowed goes out, its query and body are scanned for private keys,
  cloud and API keys, JWTs, card numbers and the operator's own patterns
  (`dlp` in `proxy.json`; on by default, `dlp.exempt` for URLs never
  scanned, model requests only with `dlp.include_model_calls`); a match
  pauses for a person (`content.sensitive` on
  `content:<kinds> <METHOD> <url>`) who sees the kinds and counts, never
  the values; the observe profile refuses it. Flow rules (`flows`) say
  what was read from these sources may only go to these destinations: for
  the rule's window after such a read, a write elsewhere is asked about
  (`flow.write` on `flow:<name> <METHOD> <url>`, the source and its age
  shown) or refused (`"effect": "deny"`). `chat.slack.routes` send
  approvals of a kind (by action type or resource pattern) to a channel of
  their own, decided only by the people listed for the route.
  `docs/GUARANTEES.md` 1.14, 2.3, 7.6.
- **Agents that never stop, and many deployments.** `attest_every_minutes`
  in `proxy.json` makes `ovara run` attest the run as it goes: a signed
  statement every so many minutes covering the receipts since the previous
  one (`var/attestations/<run>.<NNN>.intoto.json`, `sequence`,
  `previous`, `interim` in the predicate; spec C4 §8), and a last one when
  it stops; `ovara attest verify` verifies the sequence as one and `attest
  list` shows the parts. `ovara fleet -dirs A,B | -root D` prints every
  deployment on one line (profile, gateway, agents and stopped ones,
  pending approvals, the record and its last activity; `-json`).
  `deploy/kubernetes/` is a sidecar recipe: Ovara next to the agent in one
  pod, the agent holding only the CA and its token, receipts on a volume,
  a NetworkPolicy as the backstop (documented, not yet run in CI).
  `docs/GUARANTEES.md` 5.8; `docs/operations.md`.
- Spec 0.1, later: the decision API gains `POST /v1/runtime/outcome` (the
  caller reports how an allowed action went; §2.1) and the resource model
  the `tool.call` action type with `tool:<name>` resources (an agent
  framework's in-process tool calls, through the SDK tool guard).

**`ovara run -- <agent>`: one command**

- `ovara run -- opencode` (or `claude`, `codex`, any command) starts Ovara,
  runs the agent with Ovara's environment (`ovara env`, applied to the
  process: proxy, certificates, `NO_PROXY` pinned, placeholders, secrets
  removed), stops Ovara when the agent exits (the gateway is shut down
  cleanly, not killed), prints what the run did and exits with the
  agent's status. Without `-dir`, the deployment in the current directory
  is used if there is one, else `~/.ovara/run`, created on first use.
- Presets: for a program it recognises (`opencode`, `claude`, `codex`)
  the hosts that agent reads on its own at start-up are allowed, and its
  model API is allowed for POST and added to `model_hosts` so the model
  gate reads every body (opencode: `models.opencode.ai`,
  `opencode.ai/zen/v1`; codex: `chatgpt.com`, `ab.chatgpt.com`; claude:
  nothing beyond the defaults). Rules are marked `[preset NAME]` in
  `policy.json`, added once, and never override a rule you wrote. `-preset
  none` skips them; `-preset NAME` forces one. Writes still ask.
- `-agent NAME` runs the command as that named agent (its own token).

**Approvals: used once, and a late answer is not wasted**

- Before an approved request runs, the proxy claims the approval
  (`POST /v1/approval/{id}/claim`, an agent-callable route; single use in
  the gateway's store). An identical request that finds it already used is
  refused (`approval_used`) and asked afresh, so one approval never runs an
  action twice.
- A request approved after the proxy stopped waiting is not asked again:
  the identical request (same agent, action, resource, body hash and
  gateway digest) gets that approval back from `/v1/approval/create` while
  it is unused and within the pending TTL, then claims it. Before, a card
  answered between two retries was wasted and the person was asked twice.
- `proxy.json` `escalate_on_timeout`: `"retry"`: an unanswered hold is
  answered 503 with `Retry-After` set to the poll interval, the approval id
  and a hint; the approval stays open. `"timeout"` is the older 504. **New
  deployments (`ovara init`) get `retry` with a 10-second hold**, so an
  agent is told quickly instead of being held for a minute; existing
  `proxy.json` files keep `timeout` and 60 seconds until edited. It applies
  to HTTP requests, the proxy's own questions (packages, budgets, taint,
  model features) and MCP tool calls. `ovara log` shows such requests as
  "told to retry". The agents battery's unanswered POST (A1) and the
  scenario suites' unanswered requests now expect 503. `ovara approvals`,
  `ovara watch` and the approval page no longer hide a request once the
  hold has elapsed under the retry answer: approving it still makes the
  agent's retry run (under the timeout answer they hide it as before).
- The box command gate and `ovara mcp wrap` claim approvals too, so every
  poller in the binary treats an approval as single-use.
- Every refusal names the policy rule that decided (`rule` in the JSON
  body) when one did, so the agent and the person reading its output see
  what to change.
- A proxy talking to an older gateway without the claim route says so once
  and behaves as before (approvals are not single-use there).

**MCP**

- MCP traffic that Ovara cannot read strictly is refused, not passed as
  "not MCP". A request body that a lenient reader could take for JSON-RPC
  (UTF-16 or UTF-32, `NaN` or `Infinity`, a second value after the first,
  escaped member names) but that is not valid UTF-8 JSON is answered with
  400 and a JSON-RPC parse error (reason `mcp_unparseable`). Once a server
  is known to speak MCP, or the client sends MCP session headers, any body
  that is not valid JSON is refused. `ovara mcp wrap` answers such a line
  with a parse error (-32700) and does not pass it on.
- Readers that take single-quoted or unquoted member names and `=` or `;`
  as separators (Gson, JSON5) are covered by the same refusal: a body that
  opens with `{` or `[`, is not valid JSON, and names `jsonrpc` or `method`
  that way is refused with 400 (`mcp_unparseable`). White space between a
  name and its separator, however long, does not hide it, and the answer
  does not depend on how the body was cut into pieces on the way in.
- A `tools/call` whose method name is spelt differently (`Tools/Call`,
  `tools/call ` with white space, text after a NUL, `ſ` for `s`) is refused
  (`mcp_message_ambiguous`), in the proxy and in `ovara mcp wrap`: a server
  that ignores case, trims the name or ends it at a NUL would run it as a
  tool call nobody decided. Other method names (`Ping`, `tools/calls`) are
  not affected.
- Responses to MCP requests must be `application/json` or
  `text/event-stream` (parameters allowed), named by one Content-Type
  header. Anything else with a body is refused (502,
  `mcp_unexpected_content_type`); error statuses and empty answers pass.
  A JSON answer or a message event that cannot be read strictly is
  refused too (502, `mcp_unparseable`).
- A request body with a Content-Encoding other than gzip is refused when
  it could be JSON-RPC (a JSON or missing Content-Type, a known MCP
  server, or MCP session headers), whether or not the server was seen
  before. A body too large to read is refused when anything in it looks
  like JSON-RPC, not only its first megabyte.
- Servers whose tools are pinned stay known for good. Other servers are
  forgotten least recently used first, past 4096, instead of all at once.
- A tool-call question carries `arguments_sha256` (the SHA-256 of the
  call's arguments in canonical JSON) and the request's `body_sha256`. An
  approval stands for those exact arguments, and the gateway no longer
  merges two pending calls that differ only past what the preview shows.
- The gateway's note on a cut approval-context value now carries the
  SHA-256 of the whole value, and `body_sha256` and `arguments_sha256` are
  always kept when a request carries more entries than the cap.

**What the upstream receives is exactly what was checked**

- A body the model gate or the MCP gate reads as JSON is no longer
  forwarded as the agent wrote it. It is read strictly (UTF-8, one value,
  no `NaN` or `Infinity`, no two members with the same name) and the
  canonical encoding of what was read is sent instead: members sorted by
  name, no white space, strings escaped one way, numbers byte for byte as
  written, arrays in order. A server or provider whose JSON reader differs
  from Ovara's has nothing left to read differently. This covers model
  requests, MCP requests (a gzip request is sent decoded), checked MCP
  responses (JSON bodies and the events of an event stream, which keep
  their name and id; comments inside a checked event are dropped) and
  both directions of `ovara mcp wrap`.
- The `body_sha256` in the approval context and in receipts is the hash of
  the canonical bytes, computed before anyone is asked, so it is still the
  hash of exactly what is sent.
- **Breaking:** a model request with duplicate member names is refused
  (403, `model_request_ambiguous`) instead of being checked on the last
  value. An MCP message with duplicate or case-variant member names, or
  invalid UTF-8, is refused whatever it carries, not only when it holds a
  tool call or a tool list. Upstreams that compared raw request bytes
  (signatures over the body, byte-exact caches) see the canonical form.

**Removed**

- `policy/compiler`: it produced rules the gateway refuses, and nothing
  used it.

### Removed

- `services/` (approval, alerting, observability, receipt-storage): four
  standalone services that nothing called, with in-memory state and, for
  receipt-storage, a signature scheme (HMAC) that no longer matches the
  gateway's Ed25519 receipts.
- `policy/adapters/` (OPA, Cedar, custom): they scoped rules by writing
  `conditions` the gateway never evaluates, which silently widened rules.
- `security/ebpf`, `security/apparmor`, `research/`, and a stray test
  `enrollment.json`. All remain in git history.

### Added

- **MCP-aware mode** (`mcp_gate`, on by default). The proxy reads MCP
  traffic it lets through. Tool definitions are pinned per server
  (`var/mcp_pins.json`): the first list, a new tool and a changed definition
  pause for a person (`mcp.tools`), with hidden characters, instruction-like
  wording and other servers' tool names flagged, and a refused list never
  reaches the agent. Every tool call pauses (`mcp.tool_call`, resource
  `mcp:<host><path>/<tool>`) unless a rule allows the tool; a tool whose
  definition was never approved is refused. `ovara mcp wrap -dir D -name
  NAME -- <server>` does the same for a stdio server. The default policy
  gains `mcp.tools` and `mcp.tool_call` escalate rules; add them to an
  older `policy.json` by hand.
- **`ovara box <project> -- <agent>`** (Linux, sudo): the agent runs in a
  network namespace whose only route is Ovara, as an unprivileged system
  user with a fresh home, in a copy of the project (a real clone with
  history, the host's uncommitted changes carried over, secret-looking files
  left out, origin pointed at a dead URL). It never holds a key. When it
  exits, its changes come back as one commit on a new `ovara/box-<run>`
  branch of the real repository, after each path has passed policy
  (`.github/workflows/*` and `.git/*` are kept out by default) and a person
  has read the diff in the approval. The real working tree is never
  touched. Tested end to end (`tests/box`) and with opencode, Codex CLI and
  Anthropic's agent CLI running the full 27-command battery inside the box
  (`tests/agents/run.sh box <agent>`).
- **The box's command gate.** Every program the agent starts, by any route
  (`bash -c`, `python -c "os.system(...)"`, a subprocess from node), is
  stopped at the moment its image is loaded and checked against policy
  (`action_type: shell`, resource `shell:<command line>`): allowed, killed
  before its first instruction, or held until a person answers. It is done
  with ptrace from the launcher, so there is no same-user bypass and no
  per-syscall cost. Default policy: development work is allowed and
  recorded; `sudo`/`su`, `mount`, firewall and namespace changes and
  running Ovara are refused; `rm -rf`, `git push`, `mkfs` and `dd` pause.
  `-no-command-gate` turns it off. Tested: a refused `sudo` never runs,
  even started from python; a refused `rm -rf` deletes nothing; the three
  real agents run their whole battery under the gate (94–508 commands each,
  none wrongly refused).
- Commit-back writes into the real repository as its owner, so a launcher
  under `sudo` leaves no root-owned objects.
- **`ovara box -tier 2`: the box as a container.** The agent runs from a
  box image (`box/Dockerfile`: Node, Python, git, an `ovara-agent` user)
  with no network interface but loopback, no capabilities, a read-only
  root, no-new-privileges, and nothing of the host inside but the
  workspace, a fresh home and paths given with `-mount` (read-only; `/`,
  system paths, credential locations and the Ovara deployment are
  refused). PID 1 is `ovara box-init`: it relays loopback to the proxy and
  asks the host's command gate about every exec, over two Unix sockets in
  a directory only root can enter, then drops to the agent's uid and traces
  it. If the host side goes away the box has no way out and every command
  is refused. Flags: `-tier`, `-image`, `-mount`, `-pids`, `-memory`,
  `-cpus`. Tested in CI on GitHub's runners: the box test with the
  container's own checks, the boundary red team from inside the box, and
  the three agents' battery in a tier 2 box.
- **`ovara box -profile strict`: new dependencies pause once.** At box
  start the launcher reads the project's lockfiles (npm, yarn, pnpm,
  requirements pins, poetry, uv, Pipfile, go.sum, Cargo.lock). The proxy
  names each package download on the pinned registries
  (`npm:left-pad@1.3.0`, `pypi:six@1.16.0`, `go:…`, `crate:…`): a pinned one
  goes through; any other asks policy (`action_type: package.install`,
  escalate by default), so the person sees "install npm package is-number
  7.0.0 (a new dependency…)" once, and an approved package is allowed for
  the rest of the run. A refused one never downloads; npm audit and
  metadata reads are not asked about; a registry outside the trusted list
  pauses at its first request; npm install scripts are off. `dev`
  (default) is unchanged. Tested end to end with real npm and pip
  (`tests/box/strict.sh`, 23 checks).
- **The box image is published with each release** to
  `ghcr.io/sidianlabs/ovara-box` (amd64 and arm64, SBOM, signed
  provenance), and a released `ovara` defaults to it by digest, so tier 2
  needs no local build. The release's Docker actions are pinned by commit;
  every pull request builds the image for both architectures.
- **Receipt retention for long runs.** Before a receipt is appended to a
  current file that has reached `receipts_segment_bytes` (default 64 MiB;
  a negative value never), the file is synced, compressed into a numbered
  segment next to it (`receipts.000001.jsonl.gz`, ...) and emptied, and
  the same chain goes on in the fresh file. The segments are part of the
  chain: `ovara log`, the approval page, exports, bundles, attestations
  and every verification walk them in order, and a segment missing, edited
  or out of order fails verification like any other cut (`ovara run` then
  refuses to resume). Nothing is deleted by Ovara; a rotation a crash cut
  short is finished at the next start. `ovara doctor` reports the chain's
  size on disk, segments and all, and warns over `receipts_warn_bytes`
  (default 256 MiB), since every verification still reads the whole
  chain. 100k receipts: 46 MB raw, 12 MB on disk, verified end to end.
- **Ready-made agent images and `ovara box -agent-image`.** Releases
  publish `ghcr.io/sidianlabs/ovara-box-<agent>` for claude, codex,
  opencode and aider (`box/agents/Dockerfile`); `sudo ovara box
  -agent-image codex ./repo -- codex` needs nothing else (`-agent NAME`
  remains the named agent a run acts as). The tier 2 agent tests now run
  from these images. The battery's raw-TCP check (B5) uses bash's
  `/dev/tcp`, so a missing `nc` can no longer make it pass.
- **Aider tested behind Ovara**, in cooperative, enforced, tier 1 box and
  tier 2 box modes, with the same 27-command battery as the other three
  agents (`tests/agents/aider.sh`).
- **Box image: pip works in a virtualenv.** `box/Dockerfile` set
  `PIP_USER=1`, which makes pip refuse every install inside a virtualenv;
  removed, and the tier 2 box test checks it.
- **`ovara box -profile ci`: nothing waits for a person.** Strict installs
  plus an unattended run (`ovara run -unattended`): anything policy would
  pause (a request to an untrusted host, an unpinned package, a command
  like `rm -rf`, the commit-back) is refused at once, and no approval is
  opened. Unattended, every gate that would hold a request refuses it the
  same way, whatever asked: a TCP connection, an MCP tool call, an API
  operation, a download, a content or flow rule; the refusal and its
  receipt say `unattended`. Tested in `tests/box/strict.sh`.
- **The docker boundary recipe is now tested.** `setup-egress-boundary.sh
  docker` (`ovara run --boundary docker`) had never been run. The red team
  now runs against it (`tests/redteam/boundary/docker.sh`) with a probe
  image that has the tools the checks need, the CA mounted, and two new
  probes in every mode: a DNS lookup of an outside name and a raw socket.

- **Policy precedence: the most specific rule decides.** `policy.json` takes
  `"precedence": "most-specific"` (what `ovara init` writes now): of the
  rules that match a request, the one with the most literal characters in
  its pattern wins, then an exact action type over `*`, then an exact
  environment; equal rules resolve deny > allow > escalate. So
  `POST https://api.github.com/repos/acme/app/pulls` allow next to `POST *`
  deny means exactly that one write, which the old any-deny-wins order could
  not express. `"default": "deny"` makes an unmatched request fail instead
  of pausing. Files without the field keep the old order. Two rules with the
  same scope and pattern but different effects (a `POST *` deny added on top
  of the default `POST *` escalate) resolve by the tie-break; `ovara policy
  validate` names which one is in force.

- **The approver now sees what is being sent**, not just where. The query
  string, body size and type, and the first bytes of a text body (credentials
  masked, binary and oversized bodies never read) are shown in `ovara approvals`,
  `ovara watch` and on the browser page. The preview travels as the check's
  metadata and is copied onto the approval from the gateway's own record, never
  from the approval caller.
- **Approve and trust a host for reads**: `ovara approve <id> -trust-host`, `[t]`
  in `ovara watch`, and a button on the approval page add a read-only
  (GET/HEAD) allow rule for that one exact host. Never offered for writes,
  wildcards, IP literals or plain http.
- `tests/redteam/separate-user`: the agent attacks Ovara from a different
  unprivileged OS user (read keys, edit policy, forge receipts, approve its own
  request, kill the process). 19 attacks, all blocked.
- `docs/use-cases.md`: where Ovara fits (laptop, container, hosted sandbox, CI,
  your own harness), what is verified and what is not.

- `tests/scenarios/ci-bot.sh` (`tests/scenarios/run.sh ci-bot`): Ovara as a
  background CI step with nobody to approve: timeouts, a job policy that
  allows exactly one write, deny-over-allow, receipts, and shutdown on SIGTERM.
- `tests/agents`: real agents installed from npm (opencode, Anthropic's agent CLI, Codex
  CLI), each driven by a scripted mock of its model API (OpenAI
  chat-completions, Anthropic Messages, OpenAI Responses), run behind Ovara in
  cooperative and enforced mode with the same 27 commands: normal work,
  blocks, policy-evasion tricks and proxy-evasion tricks. 0 failed for every
  agent in both modes; the proxy-evasion bypasses get out in cooperative mode
  and are blocked in enforced mode (28 passed each), as documented. The
  report lists every host each agent contacted on its own (opencode:
  `models.opencode.ai`; Codex: `chatgpt.com`, `ab.chatgpt.com`). Plus a
  custom-agent-harness scenario against the gateway's decision API (16
  checks). `tests/agents/run.sh coop|enforced [opencode|anthropic|codex]` and
  `run.sh harness`; CI runs the agent x mode matrix.
- The default policy allows the two `npm audit` POSTs
  (`registry.npmjs.org/-/npm/v1/security/{advisories/bulk,audits/quick}`).
  `npm install` runs them automatically and they only read advisories; before,
  every agent `npm install` stalled for the whole approval window.

### Fixed (found by running the real binary the way a person uses it)

- **`ovara env` let a `NO_PROXY` list from the shell take hosts out of Ovara.**
  Found running a real agent (opencode) through Ovara in a sandbox whose shell
  exports `no_proxy` with `api.anthropic.com` on it: the agent's calls to that
  host went straight out, with no decision and no receipt, while the
  environment said every request goes through Ovara. `ovara env` now sets
  `NO_PROXY` and `no_proxy` to loopback only (as `ovara box` already did) and
  says in a comment which hosts it replaced. Hosts that must be reachable go
  in `policy.json`. The note quotes only entries that look like host names:
  the output is `eval`'d.
- **A policy resource was taken for a URL whenever it contained `://`.** A
  command line such as `shell:curl http://…` was parsed as an egress URL,
  failed, matched no rule and fell to the default. A resource is a URL only
  by shape now (`scheme://…` or `METHOD scheme://…`); everything else is a
  plain glob. URL resources keep their strict handling.

New end-to-end harness `tests/scenarios/` drives `pip`, `npm`, `git clone`,
Node `fetch()`, `curl`, a human approving and denying, a real injected key, live
policy edits, the approval page, tampering and a restart. It found four bugs
that the unit suites had not:

- **The shield quarantined normal agents.** Every deny *and every escalation*
  counted as a risk event, forever; after three, the agent was restricted and
  every request, including reads from trusted hosts, needed a human. Only
  denials count now, events age out of a 10 minute window, automatic
  restrictions lift after 15 minutes (manual ones still last until lifted),
  and quarantine needs 10 denials, not 3.
- **Policy hot reload never ran.** The watcher only started when
  `policy_refresh_interval > 0`, which `ovara init` never sets, so edits to a
  running deployment were ignored while the README promised otherwise. It now
  starts by default, watches the directory so rename-style saves are caught,
  and folds bursts of events into one reload.
- **Proxy-forced "pauses" could never be approved.** The gateway only opens an
  approval for a decision it recorded as escalate; the proxy's forced
  escalation (sensitive hosts, reads carrying a body) hit a 409 and the agent
  got an instant 403. They are now explicit denials with the reason shown.
- **Receipts were written after the response.** An agent could hold a response
  before its receipt existed. The receipt is now written before the headers.
- **A deployment could not be restarted.** The identity registry's mutate step
  carried the new contents back from its working copy but not the new
  file_seq, so the second change at startup (operator tokens, then agent
  tokens) sealed file_seq 1 twice with different contents. The next
  `ovara run` refused the file as equivocation. Every deployment that had run
  once was affected. Deployments created by an earlier build keep refusing
  by default (it cannot be told apart from tampering) and say how to repair:
  run `ovara run -repair-registry` once. It accepts the registry only if the
  sole problem is that same-seq re-seal, signed by this gateway's own key,
  seals it again at the next seq, and starts; later starts need no flag.
  Tested by `tests/scenarios/run.sh upgrade`, which builds the last affected
  commit and upgrades a deployment it made.
- **A deployment that had approved anything could not be restarted.**
  Approving marks a paused request approved and queued in one step and
  writes one journal record (escalated → queued); the signed journal's
  replay table only allowed queued after approved, so the next start refused
  the journal. Replay now accepts that step when the record carries the
  approval (who approved it and when), and still refuses it otherwise.
- **`ovara run` ignored SIGTERM.** The embedded gateway took the signal,
  closed its stores and returned, and the proxy kept serving without it. It
  now stops the proxy too (paused requests are dropped after 5 seconds) and
  exits 0, so `docker stop`, CI job ends and service managers work.
- The user-scenario restart check passed against the old process, which had
  ignored the stop signal. It now checks that the old process is gone and the
  new one is serving.
- **The netns boundary failed on kernels without IPv6.** The setup wrote the
  `disable_ipv6` sysctls unconditionally, so `ovara run --boundary netns`
  exited with status 1 where `/proc/sys/net/ipv6` does not exist. Such a
  kernel has no IPv6 egress to close; the step is skipped there and still
  fails closed everywhere else. Found by running the real agents in a
  minimal VM.
- The CI scenario jobs could not have run: `tests/scenarios/run.sh` and the
  red-team entry scripts were committed without the executable bit.
- The agent test image no longer builds "successfully" without the agent in
  it when `npm install -g` fails.

### Security (hardening pass)

- `integrations/mcp`: `@modelcontextprotocol/sdk` 1.30.0 → 1.32.1
  (CVE-2026-104850, HIGH: OAuth credentials not bound to their server).
  Found by the Trivy scan, which had never run: its action was pinned to a
  tag that no longer exists. The action is now pinned by commit and the
  scanner version is explicit.

- CI and the test images build with Go 1.26: the standard library of Go 1.25
  no longer receives fixes (`govulncheck` on 1.25.14 reports nine `net/http`,
  `crypto/tls` and `net/textproto` advisories fixed only in 1.26.9).

- **The tip ledger only moves forward.** Recording a store tip below the
  floor, or the same seq with a different hash, is refused when it is
  written. Before, it was accepted and ignored, and the problem surfaced only
  as an unrecoverable "equivocation" at the next start.

- **The approval-page link no longer carries the operator token.** `ovara run`
  printed `http://127.0.0.1:9090/#t=<operator token>`, so the link in a log
  file or terminal scrollback was the key to the gateway's whole admin API.
  The page now gets its own random token per run, kept only in memory and
  accepted only by the page's own endpoints; the page server calls the
  gateway with the operator token itself.

- **Rules with conditions the gateway does not evaluate are refused** at load
  and in the validator (only `depends_on` / `ref` are understood). They used
  to load and apply to every request.

- **Default policy no longer lets an agent send data out unapproved.** `GET *`
  and the host-less `POST *git-upload-pack` rule are gone. Reads are allowed only
  from a list of trusted hosts (package registries, code hosts, docs); git
  clone/fetch only from GitHub, GitLab and Bitbucket; any other host pauses for
  approval. A `GET`/`HEAD` that carries a body or a query over 512 bytes is
  refused (403, with the reason) even on an allowed host. **Behaviour change:** existing
  `policy.json` files are not rewritten; re-run `ovara init -force` in a scratch
  directory and compare, or add rules for hosts you need.
- **No DNS lookup before policy.** `CONNECT` no longer resolves a host name
  before policy has seen a request for it (a lookup of `<data>.attacker.example`
  is itself a data channel). Names are resolved at dial time; private IP
  literals are still refused immediately.
- Host matching for sensitive-host rules is case- and trailing-dot-insensitive.
- `X-HTTP-Method-Override` and similar headers are no longer forwarded.
- Response scrubbing redacts only secret values (plus the bare token and its
  URL/JSON-escaped spellings), no longer protocol values such as
  `anthropic-version`.
- Proxy hardening: header/idle timeouts, TLS handshake deadline, cap of 64
  requests parked on approval, rate-limited receipts for unauthenticated
  requests, and loopback (`127.0.0.1:9443`) as the default listen address.
  `--boundary` still binds the boundary-facing address. Streamed (SSE)
  responses are flushed as they arrive.
- The proxy CA is never silently regenerated: an existing but unusable CA is an
  error instead of being overwritten.
- **Gateway fails closed.** A configured persistent store (receipts, approvals,
  continuations, executions, events, capabilities) that cannot be opened now
  stops startup. It used to fall back to an empty in-memory store, turning
  tampering or corruption into silent data loss.
- **An approved action is never run unrecorded.** Continuation claim, retry,
  cancel and recover roll back and refuse if the transition cannot be written,
  so a crash cannot make a restart run the same approved action again.
- Journal: a complete final record missing only its newline is terminated
  instead of being merged with the next append. Compaction removes stale temp
  files, and releases the live journal before renaming (needed on Windows).
- Degraded anchor mode no longer anchors an unverified local-ahead tail.
- Decision, approval, continuation, execution and event IDs are full UUIDs; the
  approval action digest is length-prefixed, full SHA-256, and binds environment
  and metadata.
- `ovara doctor` checked the wrong config keys (always warned "memory-mode"); it
  now checks the real ones, warns when no off-host anchor is configured, and
  fails on `fail_open` / `unsafe_no_agent_auth`.
- Release workflow tests the exact tag on Linux, macOS and Windows for both the
  proxy and gateway modules, runs with least-privilege permissions, and attests
  build provenance. `install.sh` no longer turns a failed download into a build
  of `main` (a pinned version is honoured), requires HTTPS, matches checksum
  names exactly, and both installers support `OVARA_VERIFY=1` provenance
  checks; `install.ps1` forces TLS 1.2 and asks before editing PATH.

### Added

- **Prebuilt releases**: pushing a `v*` tag runs `.github/workflows/release.yml`,
  which tests, builds `ovara` for linux/darwin (amd64, arm64) and windows/amd64,
  and publishes archives plus `checksums.txt` as a GitHub release.
  `install.sh` / `install.ps1` download the right archive and refuse it if the
  SHA-256 does not match (source build fallback in install.sh). `ovara version`.
- **Local approval page**: `ovara run` serves `http://127.0.0.1:9090` (link with the
  operator token in the URL fragment), with pending requests (Approve / Deny) and
  integrity-checked recent activity. Loopback-only, Host-checked against DNS
  rebinding, token in a header (no cookies, so no CSRF), not frameable.
  `-ui off` disables it.
- **`ovara watch`, `ovara approvals`, `ovara approve <id>`, `ovara deny <id>`**:
  answer an agent's paused requests from the terminal, in plain English.
- **`ovara env`**: prints the agent environment for bash / PowerShell / cmd: proxy
  URL with the agent token, Ovara's CA for Node / Python / curl / git / OpenSSL,
  and placeholder API keys. (The old instructions omitted the agent token, so
  every request got a 407.)
- **`ovara policy`** explains the rules in plain English (blocked / allowed /
  ask me first), and **`ovara policy test "<METHOD URL>"`** dry-runs a request
  against the live policy and names the rule that decided. The gateway's
  `/v1/policy/simulate` now returns `MatchedRule`.
- **`ovara log`**: what the agent did, one line per request (allowed / approved /
  blocked / timed out), with an offline integrity check of the receipt chain.
- Default policy allows `git clone`/`fetch`/`pull` (a POST to `git-upload-pack`
  that only reads). Pushes still need approval. Verified with a real clone.
- `ovara watch` and `ovara approvals` skip requests the agent already stopped
  waiting for, since approving them would do nothing.
- **A useful default policy from `ovara init`**: reads allowed, writes (git push,
  PRs, deploys, deletes) escalate for human approval, known data-dump sites denied.
- **A narrated `ovara demo`** (allow, pause-and-approve, block, verified
  receipts) with an automated end-to-end test.
- **Windows support**: the gateway and `ovara` now build and run natively on
  Windows (portable file locking, platform-aware permission checks).
- CI: the `proxy` module (the shipped `ovara` binary) is now tested and linted;
  Windows and macOS build/test jobs; Python SDK tests run in CI.
- New README that explains what Ovara is and how strong each mode is; the long
  overview moved to `docs/overview-full.md`.

### Removed

- Disconnected, broken or unsafe modules: `trust/` (unauthenticated federation
  server), `identity/` (unused, incompatible lease format), `telemetry/`,
  `services/analytics`, `packages/`, four scaffold integrations, `infrastructure/`,
  `observability/`. All are recoverable from git history.
- The cloud control plane (`cloud/control-plane`), admin dashboard
  (`apps/admin-dashboard`) and `enterprise/` (SSO, compliance). They could not
  start from their image or talk to the gateway (incompatible rule format, no
  enrollment wiring) and had multi-tenant security holes. See
  `docs/decisions/cloud-control-plane.md`; recoverable from git history.

### Fixed

- **Signed-journal mode: every continuation update failed.** `FileBackedStore.Update`
  wrote to a nil file handle, so finished work stayed "executing" and could be
  retried (a side effect running twice). Now journaled like every other write.
- **The synchronous `POST /v1/continuations/{id}/execute` endpoint skipped the
  claim-time provenance check** that the background executor runs; a forged
  continuation could execute through it. It now runs the same check.
- **Duplicate approvals under concurrent requests** for one decision (two
  approvals, two continuations, the action running twice). Creation is now
  atomic, and a failed continuation write is reported instead of dropped.
- **A key not set in Ovara's environment broke the agent's own credentials**:
  `${GITHUB_TOKEN}` expanded to nothing and the proxy overwrote the agent's working
  header with `Bearer ` (or an empty `x-api-key`, breaking Claude Code subscription
  logins). Such bindings are now skipped with a clear startup message, and `ovara env`
  sets placeholders only for keys Ovara really injects.
- **Credentials could leak to the agent (SEC-0001):** Range requests and
  upstream-encoded bodies slipped past the reflected-credential scrubber. The
  proxy now strips `Accept-Encoding`/`Range` on credentialed requests and refuses
  bodies it cannot scrub.
- **`fail_open` injected real credentials** into traffic that had no policy
  decision. Fail-open traffic is now forwarded without credentials.
- **Receipts signed by a revoked or destroyed gateway key after its
  revocation no longer verify** (`gwctl verify-receipt`, `/v1/receipts/verify`).
  Receipts from before the revocation still verify; backdating by a key holder
  remains the documented key-compromise limit.
- `ovara run --boundary netns` printed a proxy address that did not match the
  one the script configured, and told you to run the agent as root. It now
  prints the right address and runs the agent as your user.

## [0.9.0] - 2026-09-21

The OVARA 2.0 security series: the gateway becomes an enforceable execution
boundary — enrolled gateway identity, durable revocation, claim-time
authority verification, and Ed25519-signed receipts.

### Added

- **Gateway trust & enrollment (P2.3.1/P2.3.2)**: Ed25519 gateway keys,
  proof-of-possession admission, durable hash-chained registry, key
  lifecycle (active/rotating/superseded/revoked/destroyed). Unenrolled
  gateways refuse to serve.
- **Durable replay (P2.1)**: request nonces and delegation presentation
  keys consumed durably across restarts.
- **Identity & credential lifecycle (P2.2)**: registered credentials,
  rotation with grace window, revocation, suspend/resume/retire/migrate;
  lifecycle routes are operator-only; queued work of suspended or retired
  subjects never executes.
- **Journal integrity (P2.3.3)**: hash-chained registry journal, corrupt
  journals refuse startup, optional external anchor hooks.
- **Revocation boundary (P2.3.4)**: issuer/delegation/lease revocation,
  claim-time authority recheck over every captured hop, linearizable
  claim/revoke races, fail-closed on unavailable revocation state.
- **Receipt signing (P2.3.5)**: Ed25519 `edsig_v1` signatures over the full
  authoritative decision record; offline `gwctl verify-receipt` using
  registry public material only; historical receipts verify across key
  rotation and revocation.
- **Integration closure (P2.3.6)**: 56-case clean-room integration suite
  proving the composed chain — identity → delegation → lease → policy →
  approval → claim → execution → signed receipt — plus denial matrix,
  crash/SIGKILL durability, and cross-domain isolation.

### Security

- Preserved non-claims: software gateway keys ≠ clone prevention; signed
  receipts ≠ execution truth or global immutable history; trust_epoch ≠
  consensus; revocation ≠ kill-on-revoke for running executions.

## Earlier changes (previously a second, duplicate `[Unreleased]` heading)

### Security

- **Capability lease trust anchor**: lease signatures are now verified against
  a gateway-configured trusted-issuer registry (`trusted_issuers` in
  config.json), never against keys carried in the request. Unsigned leases and
  unknown issuers are rejected.
- **Default decision is escalate**: requests matching no policy rule now
  escalate for approval instead of being allowed by default.
- **Control-plane tenant isolation**: API keys are bound to their
  organization; cross-tenant requests are rejected.
- **Approval service auth**: the standalone approval service now requires a
  bearer token.
- **Receipt storage verification**: real HMAC verification instead of a
  signature-length check.
- **Sandbox fixes**: corrected Docker container-create body so network
  isolation and read-only rootfs actually apply; exec now reports the real
  exit code.
- **Executor hardening**: git `checkout` uses `--` separator (flag injection);
  GitHub executor path-escapes URL segments.
- **SDK verification fixes**: TypeScript ed25519 verification now uses a real
  WebCrypto call; Python `verify_capability_lease`/`verify_agent_identity`
  require a trusted public key parameter instead of self-asserted fields.

### Documentation

- Corrected claims across `docs/` where docs described unimplemented security
  properties (mandatory verification, TLS, RBAC, signed delegation chains,
  eBPF blocking, non-bypassable interception).
- Added `docs/architecture/executor_proxy.md` — the V2 target architecture:
  a credential-starving executor proxy where every side effect transits a
  notarizing chokepoint.

## [0.1.0] - 2026-06-12 (previously tagged v1.0.0 — premature; renumbered)

### Added

- **Runtime Gateway (Phase 1-65)**: 12 execution surfaces (`shell`, `exec`, `git.push/pull/fetch/checkout`, `github.push/pr/merge/delete_branch`, `ci.trigger`, `shell.sandboxed`) with allow/deny/escalate policy evaluation, HMAC-SHA256 cryptographic receipts, SLA health diagnostics, stuck-executing recovery, and panic recovery.
- **Machine Identity (Phase 66)**: 4 cryptographic primitives — `AgentIdentity` (ed25519), `CapabilityLease` (signed with TTL/depth), `DelegationChain` (SHA-256 hash lineage), `TrustMetadata`. Cryptographic signature verification wired into gateway evaluator.
- **Trust-Aware Security (Phase 67)**: drift detection (sliding-window action pattern analysis), trust degradation (exponential decay + streak acceleration), chain detection (self-delegation, depth, rapid re-delegation), trust-dependent policy rules (`MinTrustScore`, `MinTrustLevel`).
- **Production Hardening (Phase 68)**: deployment guide (systemd, Docker), operations runbook, security hardening profile, full API reference, comprehensive test suite.
- **Cloud Foundation (Phase 69)**: hosted control plane (Fastify + Drizzle ORM + PostgreSQL) with multi-tenant support, gateway enrollment, policy distribution, API key management, revocation APIs.
- **Enrollment Sync (Phase 70)**: cloud enrollment client (ed25519 key generation), policy sync service, cloud heartbeat.
- **Observability Pipeline (Phase 71)** *(assets shipped, not wired)*: OpenTelemetry-compatible span exporter and NATS event streaming code exist in `internal/observe/` but are never instantiated in `server.go`; ClickHouse analytics schema (5 tables, materialized views) shipped under `telemetry/`. See `observability/README.md`.
- **Enterprise Features (Phase 72)**: OIDC + SAML SSO providers, compliance report generator (SOC2, GDPR, audit summaries), audit pipeline.
- **Infrastructure (Phase 73)**: Terraform K8s manifests (control plane 2-replica, gateway HPA 3-20, PostgreSQL; multi-region us-east-1/us-west-2/eu-west-1/ap-southeast-1 layout scaffolded in regions.tf but modules commented out), Docker Compose full stack, Dockerfiles for all services.
- **Federated Trust (Phase 74)**: cross-organization trust graph with DFS path computation, portable ed25519-signed cross-org receipts, federated identity bridging.
- **SDKs (Phase 75)**: TypeScript SDK (`@ovara/sdk`) with 16-method client, retry with exponential backoff, portable verification (18 tests passing). Python SDK (`ovara-sdk`) with async httpx, ed25519 verification (70 tests passing).
- **Production Hardening & Final Validation (Phase 76)**: 0 data races across 30+ Go packages, 100% TS strict mode compliance, 4 docker-compose files, 11 Dockerfiles, 3 GitHub Actions workflows.
- **Integrations**: CrewAI, OpenAI Agents SDK, OpenAI, LangChain, MCP, Browser Automation — all with portable verification.
- **Trust Server (Phase 77)**: HTTP service for federated trust queries, federated client in gateway evaluator, portable trust state SDK with file-backed ExportState/ImportState.
- **OpenTelemetry tracing instrumentation (Phase 78)** *(not wired)*: OTLP-compatible span emission code exists; it is not instantiated by the running gateway.
- **Hardening & Code Quality (Phase 79)**: high-severity error handling fixes, security improvements, code quality improvements (deduplication, entropy), handler tests for all service servers, migration tool tests.
- **Admin Dashboard (apps/admin-dashboard)**: Next.js dashboard with gateway monitoring, policy editor, audit log, organizations, gateways, and settings pages (25 tests).
- **Go CLI (tools/cli)**: 7 integration tests for operator workflows.
- **Migration tool (tools/migration)**: local-to-cloud data transfer with converter, exporter, importer, validator.
- **Benchmark tool (tools/benchmarks)**: load generation, percentile reporting.
- **Security Profiles (security/)**: AppArmor (235 lines), eBPF interceptor (9K C with BPF maps), Seccomp profile (3.4K JSON), Firecracker microVM config.

### Security

- HMAC-SHA256 receipt signing with deterministic action digests
- ed25519 signature verification on all identity artifacts
- SHA-256 hash lineage for delegation chains
- AppArmor mandatory access control profile
- eBPF ring-buffer syscall monitoring
- Seccomp syscall allowlist (~130 syscalls)
- Firecracker microVM hardware isolation

### Performance (Apple M4)

| Operation | Latency |
|-----------|---------|
| Policy-only decision (httptest, in-process) | ~9.7 µs |
| Decision with identity | ~10.7 µs |
| Decision with trust anomaly | ~10.7 µs |
| Full identity+lease decision | ~12.9 µs |
| Throughput (loopback, 50-way) | ~115,000 decisions/sec |
| HMAC-SHA256 sign | ~620 ns |
| HMAC-SHA256 verify | ~650 ns |

### Test Coverage

- **1,200+ test functions** across 30+ packages
- **0 data races** under `go test -race`
- **100+ TypeScript test cases** (Vitest)
- **70 Python test cases** (pytest)

[Unreleased]: https://github.com/SidianLabs/OVARA/compare/v0.9.0...HEAD
[0.9.0]: https://github.com/SidianLabs/OVARA/releases/tag/v0.9.0
