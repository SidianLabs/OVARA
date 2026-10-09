# Ovara Box: a sandbox whose boundary is intent

Status: **design, not built.** This document is the plan. Where it describes
code that exists, it says so and names the file. Everything else is a
proposal to build and test, in the order given in §12. Nothing in here is a
promise to users until the acceptance tests in §12 pass in CI.

Read `threat-model.md` first for what Ovara is today. Sections 1-7 describe the
problem, promise, threat model, launcher and file boundary; 8-11 the command
gate, installs, platforms and the policy model; 12-16 components, data flows,
milestones with acceptance tests, open questions, and what may be claimed.

---

## 1. The problem a new kind of sandbox has to solve

Every sandbox in use today (containers, VMs, gVisor, seccomp, AppArmor)
answers one question: *can this process touch that file, syscall or port?*
That question was designed for programs that are either trusted or not.

An AI agent is neither. It is a program that is allowed to do almost
everything (that is what makes it useful) and that can be talked into doing
the wrong thing by any text it reads. The incidents that keep happening are
not escapes from a box. They happen entirely inside what the agent was
allowed to do:

| What happens | Why a container does not help |
|---|---|
| The agent reads a web page, an issue, a README, or a tool result that contains instructions, and follows them | Reading text is allowed; acting on it is allowed |
| It already holds the API key, the git token, the cloud credential, so once it is talked into it, it can send them anywhere | The key is inside the box with the agent |
| It runs `npm install` / `pip install` and the package runs code on install | Installing packages is what a dev box is for |
| It pushes, deletes, deploys, posts; nobody said yes | The network is open; those are ordinary HTTPS calls |
| Afterwards nobody can say exactly what it did, in what order, or what it had read just before | Containers do not keep that record |

So the threat is not *whether the boundary holds*. It is **what crosses the
boundary, on whose say-so, and whether there is a record**. A sandbox for
agents has to put the boundary on intent: every action that reaches outside
the box is stated, judged against a policy, paused for a person when the
policy says so, and recorded with evidence. The box itself (namespaces, a VM)
is only there to make sure the agent cannot go around that boundary.

Ovara already does this for the network. The Box extends the same rule to
files, commands and secrets, and packages it as one command.

## 2. The promise, in one paragraph

> You start your agent with `ovara box`. It gets a copy of your project, a
> shell, package managers, and the model API. It does **not** get your keys,
> your other files, or the open internet. Reading from known places is free.
> Anything that changes something outside the box (a push, a POST, a file
> written back to your real project, a command on a list you set) stops and
> shows you exactly what is about to leave, in bytes, before you approve it.
> Every decision is signed and kept. If the agent is tricked, the damage is
> bounded by what you already approved, and you can read exactly how it
> happened.

Three guarantees, each with a test in CI behind it:

1. **Nothing changes the world without a person**, and the person sees the
   real bytes, not the agent's description of them.
2. **The agent never holds a secret.** Not in its environment, not on its
   disk, not in a response it can read.
3. **Every exit from the box leaves a signed receipt**, including what the
   agent had read before it.

## 3. Principles (the rules the design must not break)

1. **Default deny; allow by naming.** The policy lists what may happen.
   Anything not listed pauses (interactive) or fails (unattended). Never
   "allow unless suspicious".
2. **The boundary does not depend on the agent cooperating.** Environment
   variables are convenience, not security. The box has no route out except
   through Ovara. A program that ignores `HTTPS_PROXY` gets nothing.
3. **Secrets are injected at the edge, never issued to the box.** Keys live
   in Ovara's process; the proxy attaches them on the way out and scrubs
   them on the way back.
4. **The approver sees evidence, not claims.** Approval previews come from
   Ovara's own record of the request (`metadata.proxy_context`, copied by the
   gateway), never from anything the agent sends.
5. **Receipts are the product.** Signed, hash-chained, with an optional
   off-host anchor. A sandbox you cannot audit is a sandbox you cannot trust.
6. **Fail closed.** Gateway unreachable → refuse. Store unopenable → do not
   start. Unknown → pause. This is already the code's behaviour; keep it.
7. **Strict must stay easy.** Default-deny is unusable without good defaults,
   one-click "trust this host for reads", and a launcher that needs no
   configuration. Usability work is security work: a tool people turn off
   protects nobody.
8. **Say exactly what is tested.** The docs label every claim *tested*,
   *mechanism tested* or *not tested*, as `use-cases.md` does now.

## 4. Threat model for the Box

### 4.1 Attacker

The attacker is **the agent's own input**: a web page, repo file, package,
issue comment or tool output that carries instructions. We assume it fully
controls what the model decides to do next. We also assume the model may be
wrong on its own (no attacker needed). We assume the agent process may run
arbitrary code the attacker chose (through a malicious package or a tool the
agent wrote and ran).

We do **not** assume the attacker controls the host, Ovara's process, or the
person approving. We do not defend against a kernel exploit from inside the
box in the first release (see tiers, §4.4).

### 4.2 Assets

- Secrets: API keys, git tokens, cloud credentials, SSH keys, `.env` files.
- The real project and the real repository history.
- Everything else on the host (other repos, browser profiles, the user's
  home directory).
- Reputation: posting, publishing, deploying, emailing as the user.
- The record: the ability to know afterwards what happened.

### 4.3 Exits from the box (every one must be gated)

| Exit | How it is gated | Status |
|---|---|---|
| Network | All traffic through the proxy; policy allow/escalate/deny; keys injected; responses scrubbed | **built, tested** (`proxy/`, `tests/scenarios`, `tests/agents`, `tests/redteam`) |
| Files back to the real project | Workspace is a copy; "commit back" is a gated action with a diff preview | not built (§7) |
| Files anywhere else on the host | Not mounted; the box sees only its workspace and a scratch dir | not built (§7) |
| Commands | An exec gate between the agent and the shell: allow/pause/deny per command, by policy | API exists (`POST /v1/runtime/check`, action types `shell`/`exec`), no enforcement (§8) |
| Package installs | Through the proxy, with registry pins, install-script policy, new-dependency approval | partial (npm audit rule only) (§9) |
| Secrets | Never present in the box; injected by the proxy; scrubbed on return | **built, tested** |
| Process control (kill Ovara, edit policy, forge receipts) | Agent runs as a different unprivileged user with no access to Ovara's directory | **built, tested** (`tests/redteam/separate-user`, 19 attacks) |
| Non-HTTP protocols (SSH, raw TCP, DNS to the outside) | Dropped by the boundary (no route) | **built, tested** on Linux netns (`tests/redteam/boundary`, 25 checks) |

### 4.4 Isolation tiers (what the box is made of)

| Tier | Isolation | Stops | Does not stop | Platforms |
|---|---|---|---|---|
| **0 cooperative** | `ovara env` only | mistakes | a program that ignores the proxy settings | all |
| **1 user+netns** | separate unprivileged user, network namespace with no route except Ovara, workspace copy | everything in §4.3 for a non-root agent | kernel exploits; a root agent | Linux (built) |
| **2 container** | tier 1 inside a container with no capabilities, read-only root, seccomp default profile | the same, plus most of the host filesystem by construction | kernel exploits | Linux, Docker Desktop |
| **3 microVM** | tier 2 inside Firecracker / Cloud Hypervisor, Ovara outside the VM | kernel exploits from inside | hardware side channels; Ovara bugs | Linux hosts with KVM; later |

The first Box release ships tiers 1 and 2. macOS and Windows get tier 1 or 2
inside a Linux VM (Lima / WSL2) with Ovara running on the host side of the
VM boundary (§10). Tier 3 is for people running agents they expect to be
hostile; it comes after an external review of tiers 1 and 2.

### 4.5 What the Box does not claim

- It does not stop prompt injection. It bounds what an injected agent can
  do, and records it.
- It does not make an allowed host safe. If reads from `github.com` are free,
  an agent with a GitHub account can still exfiltrate through a gist. The
  policy limits *where*; it cannot limit *what* an allowed host accepts.
  (Mitigation: the receipt shows it; "trust host" is reads-only; writes to
  any host pause.)
- It does not protect a root agent, or one that shares Ovara's user.
- It does not make a hostile model honest. It makes the model's actions
  visible and gated.

## 5. Architecture

```
 host (Ovara's user)                              │ box (agent's user, netns / container / VM)
                                                  │
  ┌──────────────┐   decisions   ┌────────────┐   │   ┌───────────────────────────────────┐
  │   gateway    │◄─────────────►│   proxy    │◄──┼───│ agent: claude / codex / opencode / │
  │ policy       │               │ MITM, keys │   │   │ aider / your harness              │
  │ approvals    │               │ scrub      │   │   │                                   │
  │ receipts     │               └────────────┘   │   │  tools: shell, edit, fetch, npm,  │
  │ trust/shield │                                │   │         pip, git, python, node    │
  └──────┬───────┘   decisions   ┌────────────┐   │   └──────┬────────────────┬───────────┘
         │◄─────────────────────►│ exec gate  │◄──┼──────────┘ every command  │
         │                       └────────────┘   │                           │ workspace
         │                       ┌────────────┐   │   ┌───────────────────────▼───────────┐
         │◄─────────────────────►│ file gate  │◄──┼───│ /work  (copy of the project)       │
         │     commit-back       └────────────┘   │   │ /scratch, /home/agent              │
         │                                        │   │ no host mounts, no secrets         │
  ┌──────▼───────┐                                │   └───────────────────────────────────┘
  │ approval UI  │  browser page / `ovara watch`  │
  │ (person)     │                                │   only route out: proxy IP:9443 (+ DNS to Ovara's resolver)
  └──────────────┘                                │
```

Everything left of the line already exists as one binary (`ovara run`:
gateway + proxy + approval page). The Box adds:

- a **launcher** (`ovara box`) that creates the box, the workspace copy, the
  agent user, the boundary, and starts the agent inside with the right
  environment (§6);
- a **file gate** that owns the workspace copy and gates commit-back (§7);
- an **exec gate** the agent cannot bypass, in front of the shell (§8);
- **install policy** in the proxy for package registries (§9);
- a **policy model v2** that can express "allow these, deny the rest" (§11).

The gateway's decision API, the approval flow, the receipt chain and the
shield are reused unchanged for every new gate: a file commit-back and a
shell command are just more `action_type`s.

## 6. The launcher: `ovara box`

### 6.1 Command

```
ovara box [flags] <project-dir> -- <agent command...>

  ovara box ./myrepo -- claude
  ovara box ./myrepo -- codex
  ovara box ./myrepo -- opencode
  ovara box ./myrepo -- aider --model gpt-4o
  ovara box ./myrepo -- bash             # a shell inside the box, for you

flags
  -dir DIR          Ovara deployment (default ~/.ovara/box; created on first use)
  -tier 1|2|3       isolation tier (default: 2 if Docker is available, else 1)
  -policy FILE      policy to use (default: the box policy, §11.4)
  -profile NAME     a named policy profile: dev | ci | strict (§11.5)
  -mount SRC:DST    extra read-only mount into the box (never a secret path; refused for ~/.ssh, ~/.aws, …)
  -env K=V          non-secret environment for the agent (refused if the value looks like a key)
  -keep             keep the workspace after exit (default: kept on failure, removed on success)
  -ui ADDR|off      approval page (default 127.0.0.1:9090)
  -approve-timeout  how long a paused action waits (default 60s interactive, 10s with -profile ci)
```

### 6.2 What it does, in order

1. `ovara init` the deployment if missing (CA, keys, tokens, default box
   policy). Idempotent.
2. Start (or attach to) `ovara run` for that deployment: gateway, proxy on
   the boundary address, approval page on loopback.
3. **Snapshot the project** into a workspace: `git worktree`-style copy for
   git repos (so history and `.gitignore` are respected and the real
   `.git` is not writable from the box), `rsync` copy otherwise. Secrets
   are excluded by a built-in list (`.env*`, `*.pem`, `id_*`, `*.key`,
   `.npmrc` with tokens, `.netrc`, `.aws/`, `.config/gh/`, …) plus the
   user's `.ovaraignore`.
4. **Create the box**: tier 1 = unprivileged `ovara-agent` user + netns via
   `proxy/scripts/setup-egress-boundary.sh netns` (exists); tier 2 = the
   same inside a container from a small image with the agent's runtime
   (node, python, git) and nothing else, `--cap-drop ALL`, read-only root,
   seccomp default, no host mounts except the workspace and a scratch
   volume. Tier 1 requires root for the netns; tier 2 does not if Docker is
   usable.
5. **Enter the box with the agent environment**: what `ovara env` prints
   today (`HTTPS_PROXY`, CA variables, `NODE_USE_ENV_PROXY`, placeholder
   keys), plus `OVARA_EXEC_GATE` (§8) and `HOME=/home/agent`.
6. Run the agent command. The person uses the approval page or `ovara
   watch` in another terminal.
7. On exit: write the box summary (what was approved, denied, timed out;
   what the workspace changed), offer commit-back (§7.3), remove the box.

### 6.3 Agent-specific setup the launcher knows about

The agents differ in how they find their model and their tools. The
launcher carries a small table, the same knowledge `tests/agents/*.sh`
encode today:

| Agent | Model endpoint | Shell tool | Notes |
|---|---|---|---|
| Anthropic's agent CLI | `ANTHROPIC_BASE_URL` (default api.anthropic.com, allowed by policy) | `Bash` | `IS_SANDBOX=1` to run as a non-tty user; nonessential traffic off |
| Codex CLI | `~/.codex/config.toml` provider (api.openai.com allowed) | `exec_command` | its own sandbox off: Ovara is the sandbox |
| opencode | `opencode.json` provider | `bash` | `permission.external_directory: allow` |
| Aider | `OPENAI_API_BASE` / `ANTHROPIC_BASE_URL` | proposes `/run` commands | needs `--yes-always`; exec gate decides |
| anything else | user-supplied | whatever it has | the boundary still holds; the exec gate works for any `sh`/`bash` |

The agent's *own* traffic (telemetry, model lists, update checks) is
treated like any other: unknown hosts pause. The box policy allows the
model APIs and the known registries; the launcher sets each agent's "no
telemetry" switches where they exist, and the summary lists every host the
agent contacted on its own (the `battery.sh` host table, made a feature).

## 7. The file boundary

### 7.1 What the box sees

| Path in the box | What it is | Writable |
|---|---|---|
| `/work` | the workspace copy of the project | yes |
| `/scratch` | empty, for the agent's temp files, caches, venvs | yes |
| `/home/agent` | fresh home; agent config written by the launcher | yes |
| toolchains (`/usr/local/go`, node, python) | the image's | no |
| everything else on the host | **absent** | — |

No `~/.ssh`, no `~/.aws`, no `~/.gitconfig` with credentials, no other
repos, no browser profile. The `-mount` flag adds read-only paths and
refuses the known secret locations.

For a git project the workspace is a **separate clone of the local repo**
(`git clone --shared` or a worktree copy), so the box has full history for
`git log`/`blame`, but the host's `.git` is not in the box. The box's
`origin` points at the host repo **through the file gate**, not at GitHub:
a `git push` from inside the box is a commit-back (§7.3). A push to GitHub
is a separate, network-gated action done from the host after review.

### 7.2 Why a copy and not a mount

A bind-mounted project means every write the agent makes is immediately
real: a deleted directory is gone, a modified lockfile is modified, a
planted `.git/hooks/pre-commit` runs on the host next time the user
commits. A copy makes the blast radius of a bad run zero until commit-back,
and makes "what did it change" a diff instead of a forensic exercise.

Cost: large repos take time to copy, and build artefacts do not carry over.
Mitigations: `--shared` clones are cheap; `/scratch` persists caches per
project across runs; `-mount` can bring in a read-only `node_modules` from
the host if the user accepts that.

### 7.3 Commit-back: the gated write to the real project

Commit-back is an action (`action_type: "fs.commit_back"`) evaluated by
the gateway like everything else:

- the preview shown to the person is the **diff** (`git diff --stat` plus
  the patch, bounded and with secrets masked, same machinery as
  `preview.go`), the list of new/deleted files, and any file the policy
  flags (`.github/workflows/*`, `*.lock`, `.git/hooks/*`, dotfiles);
- policy can allow it outright (a throwaway repo), escalate (default), or
  deny paths (`.git/hooks/*`, `.github/workflows/*` deny by default: an
  agent must not be able to change what runs on the host or in CI without a
  person reading it);
- the result is applied as a **commit on a branch** in the real repo
  (`ovara/box-<date>`), never to the working tree, never to the user's
  current branch. The user merges it like any PR.

For non-git projects commit-back is an `rsync --dry-run` preview followed
by the copy, with the same deny-path rules.

### 7.4 Reads from the box's own files are not gated

Everything in `/work` and `/scratch` is the agent's to read and write
freely. Gating file reads inside the box would make the agent useless and
protects nothing (the sensitive files are not there). The boundary is at
the edge, not inside.

## 8. The command gate

Commands are the third exit. The agent's shell tool runs whatever the model
writes; some of that must stay free (building, testing, reading files) and
some must pause for a person (removing directories, changing permissions,
anything that reaches the network by a path the proxy does not cover).

### 8.1 Design

A small wrapper, `ovara-exec`, is the shell the agent's tools run. Each
command is sent to the gateway's decision API (`POST /v1/runtime/check`,
`action_type: "shell"`, the call the SDKs already wrap) with the command
line and working directory. The decision is applied the same way the proxy
applies network decisions:

- **allow**: run it; stream input and output through untouched.
- **escalate**: hold; the approval shows the command, the directory, and the
  last few receipts (what the agent read just before it decided this). On
  approval, run it; on denial or timeout, exit with status 126 and a
  one-line reason the agent can read and act on.
- **deny**: exit 126 with the reason.

Every command produces a receipt: command, directory, decision, exit
status, duration, output size. Output itself is not recorded unless the
policy asks (it can contain the project's data).

The gate is a second layer, not the first. The network and file boundaries
hold whether or not a command reaches the gate; the gate's job is to give
the person a say over actions *inside* the box that matter (destructive
commands, anything that would make the box less isolated) and to make the
command history part of the record.

### 8.2 Default command policy (box profile)

| Decision | Commands |
|---|---|
| allow | read-only tools (`ls`, `cat`, `grep`, `rg`, `find`, `git status/diff/log/blame`), builds and tests (`go build/test`, `npm test`, `pytest`, `make`), package installs (`npm install`, `pip install`; the registry side is gated in §9) |
| escalate | `rm -rf`, `chmod`/`chown`, `curl`/`wget` (the proxy still gates the request; the pause is for the person to see the intent), `git push` (also a commit-back) |
| deny | running Ovara itself, privilege changes (`sudo`, `su`), anything touching the box's network or mount setup |
| default | escalate (interactive); deny (`ci` profile) |

Patterns use the same matcher as URL rules (`policy.MatchResource`,
already fuzzed), so one policy language covers all three exits.

## 9. Package installs

Installs are the supply-chain exit: a package can run code at install time,
and the agent chooses packages from what it reads. The proxy already sees
every registry request, so the policy lives there, not in the package
manager:

- **Registry pins.** The box profile allows exactly `registry.npmjs.org`,
  `pypi.org`, `files.pythonhosted.org`, `proxy.golang.org`, `sum.golang.org`.
  A package manager pointed at any other registry pauses for approval.
- **New dependency approval (optional, `strict` profile).** The proxy sees
  the tarball fetch for each package. In `strict`, a package not in the
  project's lockfile at box start pauses once, showing name and version;
  "approve" adds it to the run's allowance. `dev` profile allows installs
  outright (today's behaviour).
- **Install scripts.** Not blocked by Ovara (that is the package manager's
  job: `npm config set ignore-scripts true`, `pip --no-build-isolation`
  are set by the launcher in `strict`), but every outbound request an
  install script makes still goes through the proxy and is recorded, which
  is what turns a silent supply-chain compromise into a visible, denied
  request.
- **Audit traffic** (npm's advisory POSTs) stays allowed by exact path, as
  it is now.

## 10. Platforms

The box's enforcement is Linux kernel machinery (users, namespaces,
nftables). The product has to work the same on every developer machine:

| Host | How the box runs | Ovara runs | Status |
|---|---|---|---|
| Linux | tier 1 (netns) or tier 2 (container) directly | on the host | tier 1 built and tested; tier 2 scripted, never run |
| macOS | tier 2 inside a Lima/Colima VM; `ovara box` drives it | on the host, proxy reachable from the VM's network only | not built |
| Windows | tier 2 inside WSL2 (Docker Desktop's VM or a dedicated distro) | on the host (Windows binary) or inside WSL2 | not built |
| CI | tier 1 in a privileged job, or tier 0 with the `ci` profile when privilege is unavailable | same job | tier 0 tested (`ci-bot`), tier 1 tested in the agent matrix |

Rule for the VM platforms: the VM's only network path is to Ovara's proxy
address, the same rule as the netns; the workspace copy lives inside the
VM; commit-back crosses the VM boundary through the file gate. "Cooperative
only" on macOS/Windows is acceptable for a first release **if the docs say
so in the first paragraph**; a release that claims the box on those
platforms without the VM is not acceptable.

## 11. Policy model v2

### 11.1 The gap in v1

Today's evaluation order is fixed: any matching **deny** wins, then any
matching **allow**, then **escalate**, then the default (escalate). That
makes "allow these writes, deny every other write" impossible: a catch-all
`POST *` deny also beats the specific allow (`tests/scenarios/ci-bot.sh`
C3 asserts this). It also means a profile cannot be composed from a strict
base plus project-specific allowances.

### 11.2 Proposal: most-specific rule wins, deny ties

Rules carry no priority field; specificity is computed from the pattern:
an exact resource beats a pattern with one wildcard, which beats a bare
`METHOD *`, which beats `*`. Among rules of equal specificity, deny beats
allow beats escalate (today's order, preserved as the tie-break). The
default stays escalate, and a profile can set the default to deny.

Consequences:

- `POST https://api.github.com/repos/acme/app/pulls` allow + `POST *` deny
  = the one write passes, everything else is refused at once. The CI case
  works.
- A deny can still be made absolute by writing it as specifically as the
  allow (`*://pastebin.com/*` stays a deny whatever allows exist, because
  nothing more specific allows it).
- Existing policies keep their meaning except where a broad deny
  overlapped a specific allow, which was the bug.

Versioned: `policy.json` gets `"version": 2`; v1 files are evaluated with
v1 order and `ovara policy migrate` rewrites them. The validator refuses a
v2 policy whose rules are shadowed (a rule no request can ever reach),
which is the case that silently widens or narrows today.

### 11.3 One language for three exits

`action_type` already distinguishes `http.request`, `shell`, `exec`; the
box adds `fs.commit_back`. Resources per type:

| action_type | resource | example |
|---|---|---|
| `http.request` | `METHOD scheme://host/path` | `POST https://api.github.com/repos/*/pulls` |
| `shell` | `shell:<command line>` | `shell:git push*` |
| `fs.commit_back` | `path:<repo-relative path>` | `path:.github/workflows/*` (deny) |

### 11.4 Profiles

| Profile | Default | Reads | Writes | Commands | Installs | Approval timeout |
|---|---|---|---|---|---|---|
| `dev` | escalate | trusted list free, others pause | pause | read/build/test free, destructive pause | free | 60 s |
| `strict` | deny | trusted list free, others pause | pause | read/build/test free, everything else pause | new deps pause | 60 s |
| `ci` | deny | trusted list free, others deny | only the listed ones | listed ones only | lockfile only | 10 s |

Profiles are ordinary policy files shipped in the binary (`policy_defaults.go`
grows two siblings); `-policy` overrides, `.ovara/policy.json` in the
project extends.

## 12. Components and where they live

| Component | Package / path | Exists |
|---|---|---|
| gateway: decisions, approvals, receipts, shield, identity | `runtime/gateway` | yes |
| proxy: MITM, policy flow, key injection, scrub, preview | `proxy/internal/proxy` | yes |
| boundary script (netns, docker) | `proxy/scripts/setup-egress-boundary.sh` | yes (docker mode never run) |
| CLI: init, run, env, watch, approvals, log, doctor | `proxy/cmd/ovara` | yes |
| approval page | `proxy/cmd/ovara/ui` | yes |
| **launcher** `ovara box` | `proxy/cmd/ovara/box.go` | no |
| **workspace + file gate** (snapshot, secret exclusion, diff preview, commit-back as a branch) | `proxy/internal/workspace` | no |
| **command gate** `ovara-exec` | `proxy/cmd/ovara-exec` (static binary, copied into the box) | no |
| **install policy** (registry pins, new-dependency pause) | `proxy/internal/proxy` + profile rules | partial |
| **policy v2** evaluator + migrate + shadow check | `runtime/gateway/internal/{policy,evaluator}` | no |
| **box image** (tier 2): agent runtimes, no secrets, read-only root | `box/Dockerfile` | no |
| **VM driver** (Lima / WSL2) | `proxy/internal/vm` | no |
| tests: agents matrix, scenarios, red teams | `tests/` | yes; grows per milestone |

## 13. Data flows

**A request leaves the box.** Agent → proxy (CONNECT) → policy check at the
gateway (literal host only; no DNS before the decision) → allow: inject
key, forward, scrub response, receipt before the response is released;
escalate: approval created with the preview, person answers, then as
allow or a 403/504; deny: 403 with reason, receipt.

**A command runs.** Agent's tool → `ovara-exec` → gateway check → run /
hold / refuse → receipt.

**Files go back.** Agent (or the person at exit) → file gate computes the
diff → gateway check (`fs.commit_back`) with the diff as preview → person
approves → commit on `ovara/box-<date>` in the real repo → receipt.

**A secret is used.** Only ever on the host side of the proxy. The box holds
a placeholder; the proxy substitutes the real value for the bound host over
HTTPS; the response is scrubbed of the value and its encoded forms.

**The person answers.** Approval page (per-run page token) or `ovara watch`;
the approval carries the gateway's own record of the request, never the
agent's text; "approve and trust host" adds a reads-only rule for that one
host.

**The record.** Every decision is a signed receipt in a hash chain; `ovara
log` verifies; `gateway_anchor_url` pushes tips off-host so a host-side
rewrite is detectable.

## 14. Milestones and acceptance tests

Each milestone ships only when its tests pass in CI on GitHub (not only in
a local or cloud session), and the docs' *tested / not tested* labels are
updated in the same change.

| # | Milestone | Acceptance (new tests) | Estimate |
|---|---|---|---|
| 0 | **Ship what exists**: push, CI green on GitHub for the first time, v0.9.1 with the `-repair-registry` note | all existing jobs green on `main` | days |
| 1 | **Policy v2** | ci-bot C3 flips to "allowed write passes under catch-all deny"; shadow-rule validator test; v1 files migrate byte-for-byte in meaning | 1 week |
| 2 | **`ovara box` tier 1 on Linux** (launcher + workspace snapshot + secret exclusion; no command gate yet) | agents matrix runs through `ovara box` instead of the hand-built netns; a planted `.env`/`id_rsa` in the project is absent in the box; commit-back lands on a branch with the diff in the approval; `.github/workflows/*` change is denied | 2 weeks |
| 3 | **Command gate** | battery adds destructive commands: `rm -rf` pauses, `sudo` denied, builds free; receipts hold the commands; agent cannot reach a shell that skips the gate (red-team checks) | 2–3 weeks |
| 4 | **Tier 2 container** + docker boundary test finally run | boundary red team passes in docker mode; box image has no secret paths and a read-only root | 1–2 weeks |
| 5 | **Install policy** | `strict`: a new dependency pauses once with name+version; a package from an unlisted registry pauses; npm audit still free | 1 week |
| 6 | **macOS/Windows via VM** | the agents matrix on a macOS runner through Lima and on a Windows runner through WSL2, enforced mode numbers equal to Linux | 2–4 weeks |
| 7 | **Real-key soak**: real model APIs, 3 agents, multi-day unattended runs, receipt chain verifying throughout | a nightly job that runs 8 hours and reports the host table and chain status | 2 weeks, then ongoing |
| 8 | **External review** of tiers 1–2 before the word "sandbox" appears in the README | findings fixed or documented | external |
| 9 | **Tier 3 microVM** (Firecracker) | same matrix inside the VM | later |

Order matters: 0 before anything (today's release cannot restart); 1 before
2 (the box profiles need v2); 3 and 4 can run in parallel; 8 before launch.

## 15. Open questions (decide before milestone 2)

1. **Workspace for large repos**: `git clone --shared` vs worktree copy vs
   overlay mount. Overlay is fastest and still a copy-on-write boundary;
   it needs root or a user namespace. Default proposal: shared clone,
   overlay as a tier-2 option.
2. **Approval fatigue**: should "approve" offer "and allow this command
   pattern for the rest of the run"? Proposal: yes, run-scoped only, shown
   in the exit summary; persistent rules only through "trust host" (reads)
   and explicit policy edits.
3. **Where the model API key lives for Aider/opencode-style agents that
   want it in a config file**: placeholder in the file, substituted at the
   proxy, same as env vars. Needs a test per agent.
4. **Receipt retention and size** for long runs: compaction exists
   (`record.compactSigned`); the box needs a retention knob and a size
   warning in `ovara doctor`.
5. **Multi-agent / sub-agent runs**: one box per top-level run; sub-agents
   share it and the receipts tag them by process. Decide whether sub-agents
   get their own agent tokens (traceability) or share one (simplicity).

## 16. What we will and will not say

- Until milestone 3 passes in CI: "a checkpoint for coding agents".
- After milestones 3 and 4, before 8: "a sandbox for coding agents (beta):
  network, files and commands gated; Linux enforced; macOS/Windows
  cooperative".
- After 8: "a sandbox for coding agents", with the review and the test
  matrix linked from the README.
- Never: "injection-proof", "unescapable", "zero trust" without the tier
  it applies to.
