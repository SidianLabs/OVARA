# Changelog

All notable changes to Ovara are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Focus: make the product usable and understandable for people running coding
agents, and fix correctness bugs found in an in-depth review.

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

### Security hardening (October 2026)

A review of the whole product found ways around several promises. They are
fixed below. What Ovara promises now, mode by mode and with the test behind
each promise, is in [`docs/GUARANTEES.md`](docs/GUARANTEES.md).

**Breaking changes** (things you may notice after upgrading):

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
