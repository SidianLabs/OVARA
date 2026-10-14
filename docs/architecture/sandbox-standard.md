# Ovara as the standard agent sandbox — system architecture

> **Status (2026-10-14).** Written on 2026-10-13 as the plan behind the
> adoption work on PR #43 and kept here as the roadmap. Since then, on that
> PR: **S1 is done** (fail-fast approvals, `ovara run -- <agent>` with
> presets, spec 0.1 in `spec/` with C1–C5, `ovara box` driven by a manifest
> with an events stream; the in-process Go form of C5 is still to come) and
> **S2 is done** (`balanced` and `observe` profiles with the open-read cap and
> `ovara policy suggest`; remember with scopes; `upstream_proxy` and
> `upstream_ca_bundle`; the GitHub Action; a signed organisation baseline the
> project policy may only narrow; approvals from Slack). S2's exit criteria
> run in CI: the agents battery under `balanced` and behind an upstream
> CONNECT proxy (`tests/agents`, the `agents-variants` jobs), and section E
> of the ci-bot scenario, where an organisation baseline refuses a project
> rule. **S3** is next; its VM driver and rootless tier 2 need macOS, Windows
> and a container runtime to develop against. The `[exists]`, `[extend]` and
> `[new]` marks below are as of the plan's writing. **Track G has started** (§13): G1, the tool guard for agent frameworks, and the first cuts of G2 (the TCP gate), G3 (the body-aware API gates) and G4 (forms and downloads for browser agents) are on the PR.

Status: PLAN. Written against the repository as it stands on branch
`ccr-83c761fa-y5ms22` (PR #43). Every component is tagged **[exists]**,
**[extend]** or **[new]** so the plan cannot drift from the code. Box
internals are specified in `docs/box.md`; this document is the layer above
it: the whole system, what has to become a stable contract for other people
to build on, and the order to do it in.

---

## 0. Are we going in the right direction?

Yes, on the core. The primitives an agent sandbox needs are all built and
most are tested in CI with real agents:

| Primitive | Where | State |
|---|---|---|
| Enforcement outside the agent (it cannot redefine its own boundary) | netns / container boundary, ptrace exec gate | **[exists]**, red-teamed in CI |
| Every outward action decided by policy, with precedence that cannot be argued with | gateway evaluator | **[exists]** |
| A person decides the risky ones, and sees exactly what will be sent | approvals + body hash | **[exists]** |
| The agent never holds a real credential | proxy injection, broker, scrubbing | **[exists]** |
| A tamper-evident record of what actually happened | receipts v2, anchors, export | **[exists]** |
| Changes come back as a reviewed diff, never as direct writes | workspace commit-back | **[exists]** |
| MCP, model-API and package-registry traffic understood, not just forwarded | mcp / model / package gates | **[exists]** |

What is **missing** is not more of that. It is what turns a good implementation
into a standard:

1. **A stable, published contract.** The policy schema, the canonical resource
   forms, the decision API and the receipt format exist in code and prose, but
   nothing is versioned as a specification a second implementation could meet.
2. **An adoption path that does not start with a list of every website.** Today
   the default is "30 hosts are readable, everything else waits 60 seconds for
   a person". That is correct and unusable at the same time.
3. **Portability.** The strong tiers need Linux and root. macOS and Windows are
   cooperative only ("the agent is asked to use the proxy").
4. **Only one implementation.** A standard is a contract that more than one
   thing can satisfy. Until a second implementation (even a minimal one) passes
   the same conformance suite, "standard" is a hope.
5. **No independent review yet.** `docs/REVIEW_SCOPE.md` is the brief; the
   review has not happened.

The benchmark idea from earlier fits here in one specific place: as the
**conformance suite** for the contract (§9), the way OCI has `runtime-tools`.
Not as a leaderboard.

One correction to the ambition: standards are won by the *smallest contract
that many can implement* plus the *best default experience*, not by breadth.
Do not chase every protocol and platform before the interface is frozen.

---

## 1. What "standard" means here

Three things in the world have become standards in the way you want:

| Standard | What was standardised | Reference implementation |
|---|---|---|
| OCI | the image format and the runtime interface | runc |
| OpenTelemetry | the data model and the wire protocol for traces | the collector |
| SLSA / in-toto | the attestation format for "what produced this artifact" | several |

The lesson is the same each time: **the interface is the standard, the
implementation is a product.** Ovara should be to the agent-sandbox standard
what runc is to OCI: the reference implementation that proves the contract is
real, and the best one to run.

### 1.1 The five contracts to standardise

| Contract | What it fixes | Today |
|---|---|---|
| **C1. Resource model** | how an action is written down so two implementations decide the same thing: `GET https://host/path`, `shell:…`, `path:…`, `mcp:server/tool`, `commit:…`, action types, the taint/budget actions | **[exists]** in `runtime/gateway/internal/policy` (canonical forms) and `docs/GUARANTEES.md`; **[new]** as a written spec |
| **C2. Policy** | the rule schema, precedence (deny beats escalate; an allow beats a deny only when at least as specific by host or by literal prefix; any port), profiles, layering | **[exists]** v2 evaluator; **[new]** spec + layering |
| **C3. Decision API** | `check` → allow / deny / escalate, approvals create/resolve, agent identity, continuation | **[exists]** gateway HTTP API + py/ts SDKs; **[new]** versioned spec, stability promise |
| **C4. Evidence** | receipt v2 signing form, hash chain, key history, anchors, export (JSONL/OCSF), offline verification | **[exists]**; **[new]** spec + attestation mapping (§4.6) |
| **C5. Sandbox runtime interface** | create a sandbox from a manifest, start the agent, stream events (approvals, receipts), finish (summary, commit-back) | **[extend]**: `ovara box` does all of this as a CLI; **[new]** as a programmatic, versioned interface |

Everything else (the proxy's TLS tricks, ptrace, the UI) is implementation
and free to change.

---

## 2. Goals, non-goals, threat model

**Goal.** An agent can do its job with the world's normal tools (shell, git,
package managers, HTTP, model APIs, MCP) while it is impossible for it to:
(1) send data where the person did not allow, (2) make a write the person did
not approve, (3) obtain or over-use a real credential, (4) make the person
approve something other than what is sent, (5) act without a record, or
(6) escape the box or alter what comes back from it.

**Non-goals.** Making the model itself safe (that is the provider's job);
stopping a hostile *operator*; protecting against someone with root on the
host; policy for the content of the agent's answers.

**Adversary.** The agent is fully hostile (prompt-injected or pursuing its
own goal). It has every tool in the box and any bytes it wants on any
connection it can open. It cannot be Ovara's OS user. In the enforced tiers
it has no route out except through Ovara. `docs/box.md` §4 and
`docs/REVIEW_SCOPE.md` §2 are the authoritative versions.

---

## 3. System architecture

```
                         ┌──────────────────────────────────────────────┐
  people / org           │  CONTROL PLANE  [extend]                     │
  ───────────────────────┤  org policy · fleet · enrollment · kill · keys│
                         └───────────────┬──────────────────────────────┘
                                         │ policy, identities, anchors
  ┌──────────────────┐   ┌───────────────▼──────────────┐   ┌───────────────────┐
  │ HUMAN PLANE      │◄─►│ DECISION PLANE   [exists]    │◄─►│ EVIDENCE PLANE    │
  │ approve/deny/    │   │ gateway: policy evaluator,   │   │ receipts v2, key  │
  │ watch/explain/   │   │ approvals, identity, journals│   │ history, anchors, │
  │ remember         │   └───────────────▲──────────────┘   │ export, verify    │
  └──────────────────┘                   │ check / approve  └─────────▲─────────┘
                                         │                            │ receipt per action
  ┌──────────────────────────────────────┴────────────────────────────┴─────────┐
  │ EGRESS PLANE  [exists]   proxy: auth, canonical resource, gates (read, model,│
  │ MCP, taint, budget, package, SSRF), credential injection, scrubbing         │
  └──────────────────────────────────────▲──────────────────────────────────────┘
                                         │ only route out
  ┌──────────────────────────────────────┴──────────────────────────────────────┐
  │ ISOLATION PLANE  [exists tiers 1–2]  box: user, netns/container/(microVM),  │
  │ own rootfs, exec gate (ptrace), file gate (workspace copy, commit-back)     │
  │                      ┌──────────────────────────────┐                      │
  │                      │ the agent + its tools         │                      │
  │                      └──────────────────────────────┘                      │
  └─────────────────────────────────────────────────────────────────────────────┘
  ┌─────────────────────────────────────────────────────────────────────────────┐
  │ INTEGRATION PLANE  [new]  runtime interface · presets · SDKs · CI action ·  │
  │ IDE/agent adapters · MCP wrap · upstream proxy / corporate CA               │
  └─────────────────────────────────────────────────────────────────────────────┘
  ┌─────────────────────────────────────────────────────────────────────────────┐
  │ SPEC & CONFORMANCE  [new]  the five contracts, versioned · conformance suite │
  └─────────────────────────────────────────────────────────────────────────────┘
```

### 3.1 Isolation plane — **[exists tiers 0–2]**, **[new tier 3, VM driver]**

| Tier | Boundary | Platform | State |
|---|---|---|---|
| 0 cooperative | `ovara env` only; the agent is asked to use the proxy | all | exists; documented as not a security boundary |
| 1 | separate user, netns, own root file system, ptrace exec gate | Linux, root | exists; CI `box tier 1 (root)` |
| 2 | container: read-only root, no capabilities, loopback-only, Ovara's sockets outside | Linux, root (rootless later) | exists; CI `box-tier2` |
| 3 | tier 2 inside a microVM (Firecracker / Cloud Hypervisor), Ovara outside the VM | Linux + KVM | planned (`box.md` §4.4) |

Platform strategy: **every strong tier runs on Linux; other platforms run a
Linux VM.** macOS via a Lima/Colima VM driver, Windows via WSL2, both driven
by the same `ovara box` with Ovara on the host side (`box.md` §10,
`proxy/internal/vm`, not built). This is the only honest way to say
"enforced" on a laptop; cooperative mode stays for development.

Design rules that must not be broken (from `box.md` §3): no secret inside the
box, ever; the agent's user cannot reach Ovara's files or sockets; a program
started by any route is seen by the exec gate; the workspace is a copy; the
box summary is written by Ovara, not the agent.

### 3.2 Egress plane — **[exists]**

One request path, in a fixed order (`proxy/internal/proxy`): client
authentication (per-agent token) → body held (bounded) → canonical resource →
gateway decision (cached) → read guards (a read may not carry data; one size
budget for path, query and headers) → model gate (provider-side features
pause) → MCP gate (tool definitions pinned, every call decided; lenient-reader
shapes refused) → taint rule (a write soon after an untrusted read pauses) →
budgets (egress per host, model per run) → package gate (lockfile pins,
digests) → SSRF checks (literal host, no private destinations) → credential
injection (host/port/path/method-scoped, broker-minted short-lived tokens) →
upstream → response scrubbing (credential and encoded forms) → receipt
synced before the response is released.

Inspected JSON bodies are forwarded in Ovara's own re-encoding so the upstream
reads exactly what was checked (`internal/canonjson`).

**[extend]:** an *upstream proxy* and *corporate CA* mode (§6.6). Today the
proxy dials hosts directly; in most companies and in cloud sandboxes it must
go through another proxy and trust another CA. This was the blocker when
running the real agent in a cloud session this week.

### 3.3 Decision plane — **[exists]**

`runtime/gateway`: policy store and evaluator (canonical resources, most-
specific precedence, per-ref git decisions, rules that can never match are
refused at load), approvals (expiry, per-agent cap, de-duplication, who may
resolve), agent vs operator authentication, identity/enrollment, signed
journals with revocation and anchoring, OpenTelemetry spans
(`internal/observe`).

**[extend]:** policy **layering** (org → team → project → run; a lower layer
may only narrow), **profiles** (§7), and a stable **decision API version**
(`/v1` frozen; changes go to `/v2`).

### 3.4 Evidence plane — **[exists]**, **[extend]**

Receipts v2: unambiguous signing form, hash chain, key rotation and
revocation, attempt-then-outcome so a crash window is visible, local anchors
and an off-host anchor URL, `ovara log` verification, `ovara log export`
(JSONL, OCSF), `ovara incident bundle`. SDK verifiers in Python and
TypeScript, tested against vectors generated by the Go code.

**[extend]:** map a run's receipts to an **in-toto/SLSA-style attestation**
("this branch was produced by agent X under policy P, with these approvals,
and nothing else left the box"). That is what an auditor, a compliance team
or an insurer can consume without learning Ovara.

### 3.5 Workspace plane — **[exists]**

Copy-in with secret exclusion and scanning; the agent works on the copy; at
exit the diff is shown and approved; commit-back lands on `ovara/box-<date>`
built outside the agent's `.git`; agent config, hook paths and CI workflow
files are kept out; binary files stay out unless allowed; strict installs
check lockfile digests.

**[extend]:** large-repo strategies (`box.md` §15.1: shared clone or overlay).

### 3.6 Human plane — **[exists]**, **[extend]**

Approval page (loopback, per-run token, terminal output neutralised, no
reordering under the cursor), `ovara watch`, `ovara approve/deny`,
approve-and-trust-host (reads, one run), `ovara policy` in plain English,
`ovara policy test` dry run.

**[extend]:** chat approvals (Slack/Teams), *fail-fast* (tell the agent at
once that a request is held, with the approval id, instead of holding the
socket for 60 s), *explain* on every refusal (which rule, which layer, how to
allow it), and *remember* with explicit scopes (§7.4).

### 3.7 Control plane — **[extend]**

Exists in parts: enrollment (`internal/enrollment`, cloud client), gateway
identity and trust (`gwidentity`, `trust`, `revocation`), named agents and
`ovara kill`, anchor push. **[new]:** fleet view (every box, its agent, its
policy version, its pending approvals), org policy distribution (signed),
key custody for credentials per tenant, retention and export schedules.

### 3.8 Integration plane — **[new]** (the adoption layer)

This is where a standard is won or lost. See §6 and §7.

### 3.9 Spec and conformance — **[new]**

See §9.

---

## 4. The contracts in detail

### 4.1 C1 — Resource model

A resource is one string in a canonical form; two implementations must
canonicalise the same action to the same string.

| Action type | Resource form | Example |
|---|---|---|
| `http.request` | `METHOD scheme://host[:port]/path` (host lower-case, no userinfo, literal host only) | `POST https://api.github.com/repos/x/y/pulls` |
| `git.push` (per ref) | derived from the pack: `push https://host/repo refs/heads/main` (+ `(delete)`) | |
| `shell` | `shell:<normalised command line>` (base name, git global options dropped, aliases resolved, rm flags merged) | `shell:git push --force origin main` |
| `fs.commit_back.path` / `fs.commit_back` | `path:<relative path>` / `commit:<branch>` | `path:.github/workflows/ci.yml` |
| `mcp.tools` / `mcp.tool_call` | `mcp:<server>` / `mcp:<server>/<tool>` | `mcp:stdio:fs/write_file` |
| `tool.call` | `tool:<name>` (an agent framework's in-process tool, through the SDK tool guard; the arguments' hash is in the approval's context) | `tool:send_email` |
| `package.install` | `npm:<name>@<version>`, `pypi:…`, `download:<registry path>` | |
| `model.server_feature`, `model.budget`, `egress.budget`, `taint.write` | `model:<host> <feature>`, `model-budget:<agent>`, `budget:<host>`, `taint:<resource>` | |

Rules for the spec: canonicalisation is total (every input maps to exactly
one string or is refused), documented per action type, and covered by the
fuzz targets that already exist (`FuzzCanonicalResource`,
`FuzzMatchResource`, `FuzzPolicyLine`, `FuzzNormalizeHost`).

### 4.2 C2 — Policy

```json
{
  "version": 2,
  "precedence": "most-specific",
  "rules": [
    {"action_type": "http.request", "environment": "*",
     "resource": "GET https://*/*", "allow": true,
     "budget": {"new_hosts_per_run": 50, "url_bytes_per_run": 1048576}},
    {"action_type": "http.request", "environment": "*",
     "resource": "*://pastebin.com/*", "deny": true},
    {"action_type": "shell", "environment": "*",
     "resource": "shell:*git push*", "escalate": true}
  ]
}
```

Fixed by the spec: the rule fields; precedence (deny beats escalate; an allow
beats a deny only if its host is at least as specific, or for commands and
paths its literal prefix is at least as long; deny and escalate match any
port); `(delete)` for refs; rules that can never match are refused at load;
**layering**: a policy may `extends` another and may only *narrow* it (add
deny/escalate, remove allow); and **profiles** as named rule sets (§7.1).

### 4.3 C3 — Decision API

`POST /v1/runtime/check` → `{decision: allow|deny|escalate, decision_id,
approval_id?, reasons[]}`; approvals `create / pending / approve / deny` with
operator credentials only; `continuation` for a held request; agent identity
in every call. The spec freezes request and response shapes, error codes,
the meaning of each reason string, and the rule that an approval binds the
exact bytes (`body_sha256`, `arguments_sha256`).

### 4.4 C4 — Evidence

Receipt v2: `{v, seq, prev_hash, ts, agent, action_type, resource, decision,
reasons[], approval_id?, status, body_sha256?, key_id, sig}` over a
canonical signing form; chain verification; key history with rotation and
revocation; anchors. The spec freezes the signing form byte-for-byte (the
SDK vectors are the test), the chain rules, and the OCSF mapping.

### 4.5 C5 — Sandbox runtime interface

The programmatic shape of what `ovara box` does, so a CI system, a cloud
sandbox service or an agent framework can embed it the way containerd embeds
runc:

```
create(manifest) -> sandbox_id            # tier, image, workspace source,
                                          # policy (layered), profile, agent
                                          # identity, credential bindings,
                                          # budgets, limits (pids, memory, cpus)
start(sandbox_id, command, env)           # the agent command; env from `ovara env`
events(sandbox_id) -> stream              # approval.created/resolved, receipt,
                                          # exec.held/killed, budget.exceeded,
                                          # agent.stopped, commit_back.ready
resolve(approval_id, approve|deny, scope) # by an operator credential
stop(sandbox_id)                          # == ovara kill
finish(sandbox_id) -> summary             # approved/denied/timed-out counts,
                                          # hosts contacted, receipts bundle,
                                          # commit-back branch, attestation
```

The **manifest** is the portable artifact (like an OCI runtime config):

```json
{
  "version": "0.1",
  "tier": 2,
  "image": "ghcr.io/sidianlabs/ovara-box@sha256:…",
  "workspace": {"source": "git+https://…", "ref": "main"},
  "policy": {"extends": "org://baseline", "profile": "balanced", "rules": []},
  "agent": {"name": "reviewer", "command": ["opencode", "run", "…"]},
  "credentials": [{"host": "api.github.com", "broker": "github-app", "scope": "repo:x/y"}],
  "budgets": {"model": {"input_tokens": 2000000}, "egress": {"bytes_per_host_per_min": 10485760}},
  "limits": {"pids": 4096, "memory": "8g", "cpus": "2"}
}
```

### 4.6 Attestation mapping — **[new]**

`finish()` emits an in-toto statement whose subject is the commit-back branch
head, whose predicate carries the policy hash, the profile, every approval
(id, resource, who, when), the receipt chain head and anchor, and the host
table. Verifiable with the receipts bundle and the public key, offline.

---

## 5. Lifecycles

**A request.** Agent → proxy (CONNECT or plain) → authenticate (which agent)
→ hold body (bounded) → canonical resource → `check` (cache by agent +
resource + policy version) → gates in order (§3.2) → allow: inject
credential, forward, scrub, receipt before release; escalate: approval with
the exact bytes and hash, fail-fast notice to the agent, hold or continuation
→ allow/403/504 → receipt; deny: 403 with reason → receipt.

**A command.** Tool starts a program → ptrace stops it at exec → normalised
line → `check` → run / hold / kill → receipt. The raw line is shown to the
person; the normalised line is what rules match.

**A run.** `create` (manifest validated, policy layered and compiled,
credentials bound, identity issued) → workspace copy with secret exclusion →
`start` inside the box with `ovara env` → events stream → `finish`: diff
approval, commit-back on a branch, summary, receipts bundle, attestation;
workspace kept only on failure or `-keep`.

**A credential.** Lives only on Ovara's side. Bound to host/port/path/method;
minted short-lived (GitHub App installation token, OAuth2) per run where the
binding says so; injected on the way out; scrubbed from every response
including encoded forms; the agent's own credential headers stripped on bound
hosts; never injected on fail-open.

**An approval.** Created with the gateway's own record of the request, never
the agent's text; expires; capped per agent; resolved by an operator
credential; "remember" with an explicit scope (§7.4); every resolution is a
receipt.

**Evidence.** Attempt receipt → outcome receipt → fsync before release →
anchor tip locally and off-host → export (JSONL/OCSF) → attestation at
`finish` → offline verification by anyone holding the public key.

---

## 6. Deployment topologies

| Topology | Shape | What must exist |
|---|---|---|
| 6.1 Laptop | `ovara run -- <agent>` (one command, §7.5); cooperative or tier 1/2; VM driver on macOS/Windows | VM driver **[new]**, one-command run **[new]** |
| 6.2 CI job | a tier 2 box per job; manifest in the repo; approvals via chat or pre-approved profile; attestation attached to the PR | GitHub Action **[new]**, chat approvals **[new]** |
| 6.3 Cloud sandbox service | one box per session; shared gateway per tenant; receipts and keys per tenant; fleet view; kill switch | control plane **[extend]**, rootless tier 2 / tier 3 **[new]** |
| 6.4 IDE agents (Claude Code, Cursor, Codex CLI) | `ovara env` today; adapters that launch the agent inside a box from the IDE | presets **[new]** |
| 6.5 Hosted / remote agents | Ovara as a sidecar the hosted runtime routes through; decision API + SDK | SDKs **[exists]**, sidecar packaging **[new]** |
| 6.6 Enterprise / air-gapped | Ovara behind a corporate proxy with a corporate CA; org policy signed and distributed; SIEM export | upstream proxy + CA **[new]**, policy layering **[new]**, OCSF **[exists]** |

---

## 7. The adoption architecture

This answers "users cannot list every website before they start".

### 7.1 Decide by what a request can do, not only by where it goes

| Class | Examples | Default under `balanced` |
|---|---|---|
| Read, public | any GET/HEAD to a public host | allowed within a per-run budget (new hosts, URL bytes, bytes per host), fully receipted |
| Read, sensitive | hosts on a deny list (data-dump sites), private addresses, credentialed reads of secrets endpoints | deny / escalate as today |
| Write | POST/PUT/PATCH/DELETE, git push, uploads | escalate, remembered by scope |
| Credentialed | any host with a binding | as today (scoped injection), writes escalate |
| Tool calls | MCP tools, provider-side model features | escalate, definitions pinned |
| Install | packages not in the lockfiles | pause once per name+version (`strict`) or allow with digests (`dev`) |

The reasoning: reading an untrusted page is how an injection *gets in*, and
the defence for that is already in place (taint: a write soon after an
untrusted read pauses). Blocking the read buys little and costs the whole
experience. The honest trade: an open read leaves a small data channel (URL,
path, subdomain). It is budgeted and receipted, not zero.

### 7.2 Profiles — **[new]**

`strict` (today's behaviour) stays the default until the balanced profile has
passed the same agent matrix and the external review. `balanced` is §7.1.
`observe` runs the agent with everything allowed except the hard denies,
writes nothing to the world (writes are refused, not held), and produces a
**suggested policy** from the receipts: the minimal rule set that would have
allowed this run. Profiles are named rule sets in the policy spec, so an org
can ship its own.

### 7.3 Policy layering — **[new]**

`org` (signed, distributed by the control plane) → `team` → `project`
(in the repo, next to the manifest) → `run` (approve-and-remember). A lower
layer only narrows. Every refusal says which layer's rule refused it.

### 7.4 Remember, with scopes — **[extend]**

Today "trust this host for reads, this run". Add: *this command pattern this
run*, *this tool this run*, *this host for the project* (writes a project
rule), never a wildcard, never a credentialed write. Each remembered rule
carries who, when and the approval id.

### 7.5 One command, fail fast, explain — **[new]**

`ovara run -- opencode …` (or `claude`, `codex`): init if needed, pick the
preset for that agent (its own model and update hosts, recorded by the CI
matrix today), start, hand the agent the environment, open the approval
page. A held request is answered to the agent at once with "held for
approval `apr_…`, ask again in a moment" instead of a 60-second hold, so
agents keep working. Every 403 says the rule and the layer, and the one-line
command that would allow it.

### 7.6 Upstream proxy and corporate CA — **[new]**

`proxy.json`: `upstream_proxy`, `upstream_ca_bundle`. Ovara's upstream
transport honours them; the box still sees only Ovara's CA.

---

## 8. Portability plan

1. **VM driver** (`proxy/internal/vm`): Lima/Colima on macOS, WSL2 on
   Windows; Ovara on the host, the box in the VM, the proxy reachable only
   from the VM's network. Acceptance: the agents matrix passes on macOS and
   Windows runners with enforced-mode numbers equal to Linux (`box.md` M6).
2. **Rootless tier 2** (user namespaces; sockets in a directory only the
   rootless user can enter).
3. **Tier 3 microVM** (Firecracker/Cloud Hypervisor) for agents you expect to
   be hostile: the kernel is no longer shared.
4. **Non-HTTP protocols.** Raw TCP, UDP, QUIC/HTTP3 and SSH are denied by the
   boundary today (no route). Keep that; add `git` over SSH only through an
   SSH gate that decides per repo and ref the way the HTTPS path does, later.
   WebSockets ride through the proxy as upgraded HTTP and need an explicit
   decision and a size budget (**[extend]**).

---

## 9. Standardisation strategy

1. **Separate the spec from the product.** A neutral repository holding the
   five contracts (§4) as versioned Markdown + JSON Schemas + test vectors,
   under an open licence, with Ovara named as the reference implementation.
   Start it from the code: extract, do not invent.
2. **Version discipline.** `0.x` while the external review is open; `1.0`
   only after the review reports no open Critical/High and a second
   implementation passes conformance.
3. **Conformance suite.** The thing the benchmark should have been: for a
   *sandbox implementation* (not a model), run the agents matrix, the
   boundary red team, the separate-user attacks, the policy precedence
   vectors, the receipt vectors and the resource canonicalisation vectors,
   and report pass/fail per contract. `tests/` already holds most of it;
   package it so someone else can run it against their implementation.
4. **A second implementation.** Even a small one (a policy evaluator + receipt
   writer in another language) proves the contracts are implementable and
   flushes out everything that only works because of Ovara's internals.
5. **Align, do not reinvent.** OCI for box images; OpenTelemetry for decision
   spans (exists); OCSF for export (exists); in-toto/SLSA for attestations
   (§4.6); MCP as the tool protocol (exists); SPIFFE-style identities for
   agents and gateways later.
6. **Review and disclosure.** The external review (`docs/REVIEW_SCOPE.md`)
   before the words "sandbox" and "enforced" are used alone; advisories per
   `docs/SECURITY_RELEASE.md`; a public report.
7. **Governance.** A small steering group with at least one member outside
   the company, an RFC process for contract changes, a compatibility promise
   (`/v1` never breaks), and a published deprecation policy.
8. **Distribution.** Where agents are launched is where the sandbox must
   already be: a GitHub Action, a Docker image, a Homebrew formula, a
   one-line installer with checksums (`install.sh` exists), and presets for
   the three agents that already run in CI.

---

## 10. Roadmap

Milestones are additive to `docs/box.md` §14 (its M6–M9 are referenced, not
renumbered). Each ships only when its CI jobs are green on GitHub and the
docs' tested/not-tested labels are updated in the same change.

| # | Milestone | Deliverables | Exit criteria |
|---|---|---|---|
| **S1** Interface candidate | C1–C4 extracted into a spec draft with JSON Schemas and vectors from the existing tests; C5 as a Go package `proxy/internal/runtime` that `ovara box` calls; fail-fast approvals; `ovara run -- <agent>`; presets for the three agents; explain on refusals | spec renders from the repo; the agents matrix passes through the runtime interface; a held request answers within 1 s |
| **S2** Adoption | `balanced` and `observe` profiles; policy layering with signed org baseline; remember-with-scopes; upstream proxy + corporate CA; chat approvals (one provider); GitHub Action | `balanced` passes the full matrix with no new reach to blocked sites; a run behind a corporate proxy passes the matrix; an org policy refused a project rule in a test |
| **S3** Portability | VM driver (macOS, Windows); rootless tier 2; WebSocket decision | `box.md` M6 numbers equal to Linux; rootless tier 2 passes `tests/box` |
| **S4** Evidence as attestation + control plane | in-toto attestation at `finish`; fleet view; kill across the fleet; retention and export schedules; multi-tenant key custody | an auditor-style verification of a run from the bundle alone; a tenant cannot read another's receipts in a test |
| **S5** Standard | spec `1.0`; conformance suite packaged; second implementation passes; external review complete; advisories shipped; governance published | all of the above true at once |
| **G** Any agent | the general-agents track in §13: tool guard (G1), TCP gate (G2), body-aware API gates (G3), browser agents (G4), identity and delegation (G5), policy depth (G6), deployment and scale (G7) | each item's exit criteria in §13 |
| later | Tier 3 microVM (`box.md` M9); SSH gate | |

Order: S1 before everything (the interface must stop moving before others
build on it). S2 and S3 can run in parallel. S4 after S2. S5 last. Track G
runs after S2, in parallel with S3 and S4, in its own order (G1 to G7).

---

## 11. Risks and open questions

1. **Certificate pinning.** Tools that pin their provider's certificate cannot
   go through an intercepting proxy. Mitigation: pass-through CONNECT with
   host-only decisions for pinned hosts, no body inspection, documented as a
   reduced mode; measure which agents need it.
2. **Latency.** One decision per request; the cache covers repeats; the
   target is < 2 ms per cached decision and < 20 ms uncached on a laptop.
   Measure with `tools/benchmarks` once the runtime interface exists.
3. **The read channel.** `balanced` accepts a budgeted data channel through
   URLs. State it in `GUARANTEES.md` "Not guaranteed" from day one.
4. **Multi-tenant key custody.** The control plane holds real credentials for
   many tenants; that is the most valuable target in the system. Hardware-
   backed keys or a KMS per tenant, short-lived minted tokens by default.
5. **Interception consent.** In some jurisdictions and companies, TLS
   interception of an employee's tool traffic needs notice. The box is the
   agent's, not a person's, which helps; document it.
6. **Approval fatigue vs. safety.** Fail-fast and remember-with-scopes reduce
   it; the number of approvals per task is a first-class metric (the
   conformance suite reports it) so regressions are visible.
7. **Large repositories.** `box.md` §15.1 remains open.

---

## 12. Recommendation: what to build first

S1, in this order, on the current branch after PR #43 merges:

1. **Fail-fast approvals and explain-on-refusal** (small, immediately felt).
2. **`ovara run -- <agent>` with presets** (removes the first-hour pain).
3. **The runtime interface** as a Go package that `ovara box` is refactored
   to call, with the manifest format (§4.5) and an events stream. This is
   the piece everything else embeds.
4. **Spec extraction** for C1–C4 into `spec/` with JSON Schemas and the
   existing test vectors, rendered as docs. No new semantics; what the code
   does today, written down and versioned `0.1`.

Then S2's `balanced` and `observe` profiles, because they are what makes the
answer to "do I have to list every website?" become "no".

---

## 13. Track G: any agent, not only coding agents

The sandboxes companies use to test agents today are the agent frameworks'
own (a tool allow-list, a dry-run flag, a mocked provider) and the general
isolation tools (containers, VMs, egress firewalls). Ovara's difference is
the decision and the record: every action decided by one policy, held for a
person with evidence, receipted and attested. Sections 1–12 built that for
coding agents, whose actions are HTTP, git, shell and MCP. An agent of any
other kind (support, operations, research, browsing, a sub-agent of another
agent) acts in ways the proxy does not see or cannot name. Track G closes
those gaps, in this order:

| # | Gap | Deliverable | Exit criteria | Status |
|---|---|---|---|---|
| **G1** Tool calls inside the process | A framework's tools run as functions: the proxy sees nothing | `ToolGuard` (Python) and `createToolGuard` (TypeScript): every wrapped call decided (`tool.call`, `tool:<name>`, the arguments' size, hash and masked preview as context), held and claimed like any action, refused when policy says so, its outcome reported to `POST /v1/runtime/outcome` and kept as an `action.outcome` event; shown in the CLI, the page and Slack; refused under `observe` | the agents harness runs guarded calls against a real gateway in CI: approved runs, denied and policy-denied never run, fail-fast returns the approval id and the identical call gets it back, a forged or lying outcome is refused | **done on PR #43** (gateway-decided calls are not yet in the proxy's receipt chain or the attestation: G1b) |
| **G2** Non-HTTP destinations | Mail (SMTP/IMAP), databases (Postgres, MySQL, Redis), SSH, gRPC, raw TCP go around the proxy or are refused wholesale | A TCP gate in the proxy: a CONNECT to a non-HTTP port is decided as `tcp.connect` (`tcp:<host>:<port>`, protocol named when recognised), receipted with bytes each way, bounded by the egress budget, with a per-protocol reader for the ones worth more (the SMTP envelope, the SQL verb) | a mail-sending agent and a database agent pass a battery: listed destinations allowed, unlisted held, a denied one never connects, receipts carry bytes | **first cut on PR #43**: the gate, the decision, the budget, the receipts, the kill switch, the upstream proxy path, `policy suggest`; a per-protocol reader (SMTP envelope, SQL verb) and an agents-battery scenario with a real database are next |
| **G3** Verbs in the body | GraphQL, cloud JSON APIs (AWS, GCP, Azure), JSON-RPC: one URL, every operation | Body-aware gates like the model and MCP gates: the operation name and type (`graphql:<host>/<operation>` mutation vs query, `aws:<service>:<action>`, `jsonrpc:<host>/<method>`), decided and shown; the approval binds the body hash as today | the GitHub GraphQL and an AWS SDK call are decided by operation in tests; a mutation disguised as a query is caught | **first cut on PR #43**: GraphQL (operation type and name, `operationName`, fragments, strings), AWS (`X-Amz-Target`, `Action=`, read prefixes, sensitive reads), JSON-RPC (method, read names, batches refused), receipts, `policy suggest`; GCP batch endpoints and a per-API catalogue of read actions are next |
| **G4** Browser and computer-use agents | The agent drives a browser: form posts and downloads are HTTP, but the person needs to see the page, not a URL | Approvals carry the page title, the form's fields (masked) and the referrer; downloads decided by type and size; per-site logins injected by the proxy so the agent never holds a password; a Playwright/CDP preset for `ovara run -- <agent>` | a browsing agent completes a purchase flow with every write held and shown as a form; a download of an executable is refused | **first cut on PR #43**: form posts listed field by field with the page, uploads named, executables and installers held and asked about, session-cookie bindings documented; page titles, a password filled into a form from a binding and a Playwright preset are next |
| **G5** Identity and delegation | Who is acting for whom: an agent for a user, a sub-agent for its parent | On-behalf-of principals in decisions and receipts; a sub-agent's credential can only narrow its parent's (capability leases and delegation chains the gateway already verifies, surfaced in `ovara agent add -parent`); OAuth token exchange (RFC 8693) for brokered bindings with the acting user as subject; CIBA for approvals from the user's own device | a sub-agent's request outside its parent's scope is refused with the chain in the receipt; a token minted for user A is never sent on user B's request | planned |
| **G6** Policy depth | Rules name resources; they do not see content or flows | Content rules on outbound bodies (data-loss patterns: keys, card numbers, named fields), information-flow taint from sources to destinations (what was read from X may not go to Y), approval routing by risk and role (who is asked, in which channel, with what deadline) | a body carrying a secret pattern is held with the match shown; a read from a customer record cannot be posted to a public host without a question; a high-risk action reaches the named approvers only | planned |
| **G7** Deployment and scale | One deployment per laptop or job | A Kubernetes sidecar mode (the proxy and gateway next to the agent pod, policy from a ConfigMap, receipts shipped), rootless tier 2, rolling attestations for agents that never stop (a statement per interval, chained), a control plane for many deployments and tenants (`ovara status` across them, key custody per tenant) | a fleet of ten sidecars under one baseline; an auditor verifies a day of a long-running agent from its rolling statements; a tenant cannot read another's receipts | planned |

Each item adds to the spec (`spec/`), to `docs/GUARANTEES.md` with its
tests, and to the agents battery, like S1–S4 did. Nothing in Track G
changes the five contracts' meaning: new action types, resource forms and
endpoints are added, never redefined.
