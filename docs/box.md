# Ovara Box: a sandbox whose boundary is intent

Status: **milestones 1-5 are built** (tier 1, the command gate, tier 2, strict
installs; see §14). Milestones 6-9 are not. This document started as the plan
and still reads that way in places: where it describes code that exists it
names the file, and the October 2026 corrections below take precedence over
older text. What the box promises, mode by mode, with the tests behind each
promise, is in [`GUARANTEES.md`](GUARANTEES.md).

> **Corrections from the October 2026 audit and hardening (read these first).**
> - **Tier 1 has a root file system of its own** (`-tier1-fs isolated`, the
>   default; `proxy/cmd/ovara/box_tier1.go`). The agent starts through
>   `ovara box-init -tier1`, which enters the network namespace, makes a
>   new mount namespace and pivots into a fresh root: the host's system
>   directories (`/usr`, `/bin`, `/lib*`, `/etc`) read-only with
>   `/etc/shadow`, sudoers, SSH and private-key directories covered; a
>   private `/dev`; `/proc` that hides other users' processes; empty
>   `/tmp`, `/var/tmp` and `/run`; the workspace and a fresh home
>   read-write; the public CA and `-mount` paths read-only. Nothing from
>   `/home`, `/root`, `/srv`, `/opt`, `/mnt`, `/var` or `/nix`, and not
>   the original project. The agent runs with no_new_privs and no
>   supplementary groups, and the proxy token is never on a command line.
>   `-tier1-fs host` keeps the old behaviour (the agent's user reads
>   whatever it may read on the host) and is unsafe on a machine that
>   holds secrets.
> - **Command rules see a normalised command line** (`boxgate.PolicyLine`):
>   the program's base name, git without its global options, `rm` flags
>   merged (`rm -r -f`, `rm --recursive --force` and `rm -Rf` all read as
>   `rm -rf`). The person still sees the command as run. Every child exec is
>   checked on its own, and a deny always beats an escalate, so
>   `sudo … # rm -rf` is refused. The default rules are still text rules:
>   interpreter one-liners, renamed binaries and scripts that delete files
>   themselves are not caught by them. Treat them as catching mistakes;
>   the network and file boundaries do not depend on them.
> - **Commit-back** reads the workspace once into a tree in a repository the
>   launcher owns (the agent's `.git` is never used, so its hooks, filters
>   and config never run on the host). Path policy, the diff and the commit
>   all come from that tree, and the branch is exactly that tree on top of
>   the starting point. Agent config and host-execution paths (`.claude/`,
>   `.mcp.json`, `.github/`, `.husky/`, `.gitattributes`, ...) are kept out by
>   default; `CLAUDE.md`, `AGENTS.md`, `package.json`, lockfiles, `Makefile`,
>   `Dockerfile` and scripts are flagged; binary files stay out unless
>   `-allow-binary`. A cut diff says what it leaves out and where the full
>   diff is.
> - **Secrets left out of the copy** by name and by content: files whose
>   content looks like a private key, a cloud or GitHub/GitLab/Slack token,
>   an npm auth line, a `.netrc` password and the like are removed and
>   listed ("left out (looks like a secret: …)"). Secrets in git history
>   stay in the clone's objects.
> - **The GitHub key is scoped to the project's repository** (`-github-scope
>   repo`, the default): requests about any other repository go out without
>   it. `-github-scope all` turns this off.
> - **No DNS inside the boundary** unless `OVARA_BOUNDARY_DNS=1`; the proxy
>   listens on the boundary address and loopback only; the host side is
>   always firewalled (iptables or nft), or setup stops.
> - `OVARA_EXEC_GATE`/`ovara-exec` (§8) do not exist; the gate is ptrace in
>   `proxy/internal/boxgate`. `/scratch` is a tmpfs, not persistent.

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
| Files back to the real project | Workspace is a copy; "commit back" is a gated action with a diff preview | **built, tested** (`proxy/internal/workspace`, `tests/box`) |
| Files anywhere else on the host | Tier 1: a root file system of its own with the host's system directories read-only and nothing from home directories, `/root`, `/srv`, `/opt` or `/var`; tier 2: not mounted at all | **built, tested**: tier 1 (`TestTier1IsolatedFileSystem`, `tests/box/box.sh`); tier 2 (`tests/box` with `TIER=2`: host paths, Docker socket and credential files absent, root read-only) (§6.4) |
| Commands | Every exec in the agent's tree is stopped and checked by policy: allow / pause / kill | **built, tested** (`proxy/internal/boxgate`, ptrace; `tests/box`, agents `mode: box`) |
| Package installs | Through the proxy, with registry pins, install-script policy, new-dependency approval | **built, tested** (`-profile strict`; `tests/box/strict.sh` with real npm and pip) (§9) |
| Secrets | Never present in the box; injected by the proxy; scrubbed on return | **built, tested** |
| Process control (kill Ovara, edit policy, forge receipts) | Agent runs as a different unprivileged user with no access to Ovara's directory | **built, tested** (`tests/redteam/separate-user`, 19 attacks) |
| Non-HTTP protocols (SSH, raw TCP, DNS to the outside) | Dropped by the boundary (no route; DNS off unless `OVARA_BOUNDARY_DNS=1`); tier 2 has no interface but loopback. Through the proxy (a CONNECT to another port) they are decided as `tcp.connect`, counted and receipted as opaque tunnels | **built, tested**: netns (27 checks), from inside a tier 2 box (28) and the docker recipe (29) (`tests/redteam/boundary`; docker mode run for the first time in milestone 4) |

### 4.4 Isolation tiers (what the box is made of)

| Tier | Isolation | Stops | Does not stop | Platforms |
|---|---|---|---|---|
| **0 cooperative** | `ovara env` only | mistakes | a program that ignores the proxy settings | all |
| **1 user+netns+mount ns** | separate unprivileged user, network namespace with no route except Ovara, a root file system of its own (system directories read-only, workspace and fresh home read-write; `-tier1-fs host` turns this off), no_new_privs, the command gate | everything in §4.3 for a non-root agent | kernel exploits; a root agent; signals to host processes of the agent's own user (no PID namespace) | Linux (built) |
| **2 container** | a container with no network interface but loopback (the proxy through a root-only socket), no capabilities for the agent, read-only root, no-new-privileges, Docker's default seccomp profile, nothing of the host mounted but the workspace (§6.4) | the same, plus the host filesystem by construction | kernel exploits | Linux (built, milestone 4); Docker Desktop later |
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
  │ (person)     │                                │   only route out: proxy IP:9443 (no DNS unless OVARA_BOUNDARY_DNS=1)
  └──────────────┘                                │
```

Everything left of the line already exists as one binary (`ovara run`:
gateway + proxy + approval page). The Box adds:

- a **launcher** (`ovara box`) that creates the box, the workspace copy, the
  agent user, the boundary, and starts the agent inside with the right
  environment (§6) — **built, milestone 2**;
- a **file gate** that owns the workspace copy and gates commit-back (§7) —
  **built, milestone 2** (`proxy/internal/workspace`);
- an **exec gate** the agent cannot bypass, in front of the shell (§8) —
  **built, milestone 3**;
- **tier 2**: the same box as a container, with nothing of the host in it
  (§6.4) — **built, milestone 4**;
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

flags (built)
  -dir DIR          Ovara deployment (default ~/.ovara/box; created on first use)
  -tier 1|2         isolation tier (default 1; 2 needs Docker and a box image)
  -tier1-fs isolated|host
                    tier 1: isolated (default) = a root file system of its own;
                    host = the agent's user sees the host's files (unsafe where
                    the host holds secrets)
  -allow-visible-procs
                    tier 1 isolated: start on a kernel before 5.8, whose box /proc
                    cannot hide other users' processes (refused without it)
  -image NAME       tier 2: the box image (default ovara-box, from box/Dockerfile)
  -mount SRC:DST    extra READ-ONLY mount, tier 2 and isolated tier 1 (refused: /,
                    system paths, ~/.ssh, ~/.aws, ~/.gnupg, ~/.docker, ~/.kube,
                    .netrc, .npmrc, …, the Ovara deployment, and any directory
                    containing one of them; in tier 1 also /dev, /proc, /sys, /run,
                    /tmp and /var/tmp themselves). Needed in tier 1 for tools under
                    /opt or a home directory, and for scripts kept under /tmp
  -pids N           tier 2: process limit (default 4096); -memory, -cpus likewise
  -user NAME        tier 1: the agent's user (default ovara-agent, created if missing)
  -name NAME        tier 1: network namespace name (one box per name at a time)
  -env K=V          non-secret environment for the agent (refused if the name looks like a key)
  -exclude GLOB     extra path to leave out of the workspace (.ovaraignore is read too)
  -keep             keep the workspace after exit (default: kept when something is left, removed on success)
  -no-commit-back   keep the workspace, offer nothing back
  -allow-binary     let binary files the agent added or changed come back (default:
                    they stay in the workspace, since a diff cannot show them)
  -github-scope repo|all
                    repo (default): the GitHub key only goes with requests about the
                    project's own repository (from its origin remote); all: every
                    GitHub request gets it
  -no-command-gate  run without the exec gate (the network and file boundaries still hold)
  -ui ADDR|off      approval page (default 127.0.0.1:9090)
  -approve-timeout  how long the commit-back waits for a person (default 10m)
  -agent NAME       run as this named agent (ovara agent add NAME): receipts and
                    approvals name it, and ovara kill can stop it alone
  -agent-image NAME tier 2: the published image with this agent installed
                    (claude, codex, opencode or aider); implies -tier 2
  -manifest FILE    read the run from a manifest (§6.5); a flag given here wins
                    over it, a project directory or -- command replaces its
  -print-manifest   write the run these flags describe as a manifest on stdout
                    and stop (no root; works on any platform)
  -events FILE      append the run's events to FILE, one JSON line each (§6.5)

  -profile dev|strict|ci  dev (default): installs free; strict: a dependency the
                    project's lockfiles do not pin pauses once (§9); ci: strict,
                    and anything that would pause is refused at once (§11.4)
  -untrusted-lockfiles
                    strict or ci: the project's lockfiles are not trusted (a
                    repository you are reviewing): nothing they pin is let
                    through unasked

planned
  -tier 3           microVM (§4.4)
  -policy FILE      a policy for this run only (§11.4)
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
   `.npmrc` with tokens, `.netrc`, `.aws/`, `.config/gh/`,
   `.git-credentials`, kubeconfigs, …) plus the user's `.ovaraignore`, and
   then every text file in the copy is scanned: one whose content looks
   like a key or token is removed too, and listed.
4. **Create the box**: tier 1 = unprivileged `ovara-agent` user + netns via
   `proxy/scripts/setup-egress-boundary.sh netns`, entered through
   `ovara box-init -tier1`, which builds the agent's own root file system
   (§7.1) and receives the agent's environment over a pipe, so the proxy
   token never appears on a command line; tier 2 = the
   same inside a container from a small image with the agent's runtime
   (node, python, git) and nothing else, `--cap-drop ALL`, read-only root,
   seccomp default, no host mounts except the workspace and a scratch
   volume (§6.4). Both tiers need root on the host today (tier 1 for the
   netns; tier 2 to hand the workspace to the box's uid and to keep Ovara's
   sockets in a directory only root can enter). Rootless tier 2 is later.
5. **Enter the box with the agent environment**: what `ovara env` prints
   today (`HTTPS_PROXY`, CA variables, `NODE_USE_ENV_PROXY`, `NO_PROXY`
   pinned to loopback, placeholder keys) and a fresh `HOME`. The command gate needs nothing in the
   environment: it traces the agent from outside (§8).
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
| Aider | `OPENAI_API_BASE` / `ANTHROPIC_BASE_URL` | shell blocks in its reply, run after a yes | `--yes-always` does not cover shell commands: a person answers (tests pipe `yes`); exec gate decides; tested in every mode (`tests/agents/aider.sh`) |
| anything else | user-supplied | whatever it has | the boundary still holds; the exec gate works for any `sh`/`bash` |

The agent's *own* traffic (telemetry, model lists, update checks) is
treated like any other: unknown hosts pause. The box policy allows the
model APIs and the known registries; the launcher sets each agent's "no
telemetry" switches where they exist, and the summary lists every host the
agent contacted on its own (the `battery.sh` host table, made a feature).

### 6.4 Tier 2 in detail (built in milestone 4)

`ovara box -tier 2 -image IMAGE` runs the agent with `docker run` and these
properties, each checked by `tests/box/box.sh` with `TIER=2`:

| Property | How | Test |
|---|---|---|
| No network but Ovara | `--network none`: the container has loopback only. PID 1 (`ovara box-init`) listens on `127.0.0.1:9443` inside and relays each connection to Ovara's proxy through `/run/ovara/proxy.sock`, a Unix socket the host mounts | only `lo`; direct TCP, UDP, the Docker host gateway and cloud metadata have no route; the red team runs inside (`tests/redteam/boundary`, `MODE=inside`) |
| The agent cannot reach Ovara's sockets | `/run/ovara` is a host directory, mode 0700, owned by root; the agent is uid 10001 | `ls /run/ovara` and connecting to either socket are refused |
| No privilege | `--cap-drop ALL`, then only `SETUID`, `SETGID` and `KILL` for PID 1 (to drop to the agent's uid and stop its processes); the agent's capability sets are empty; `--security-opt no-new-privileges` | `CapEff` and `CapPrm` are 0, `NoNewPrivs` is 1; `sudo` is killed by the gate and could not elevate anyway |
| Read-only root | `--read-only`; `/tmp` and `/scratch` are in-memory; `/work` and `/home/agent` are the run's directories | writing under `/usr` and `/etc` fails |
| Nothing of the host | mounts: the workspace, a fresh home, the Ovara binary and the public CA read-only, the socket directory read-only, and `-mount` paths read-only (secret and system locations refused, §6.1) | the host's project, `/var/lib/ovara` and the Docker socket are absent; no credential files |
| Command gate | PID 1 starts the agent traced (`internal/boxgate`) and asks the host about each exec over `/run/ovara/gate.sock`; the host side is the same gate as tier 1 | the tier 1 gate checks pass unchanged (`sudo` killed, `rm -rf` paused and refused) |
| The agent cannot stop the gate | PID 1 runs as root inside the container; the agent has no capability to signal or trace it | `kill -9 1` is refused; the processes in the box are root (the gate) and the agent only |
| Fails closed | if Ovara or the launcher goes away, the relay has nowhere to go and every exec is refused; the container is removed on exit (`--rm`, then `docker rm -f`) | no box container left after a run |
| Bounded | `--pids-limit` (default 4096), optional `-memory` and `-cpus`, `--ipc private` | — |

Each release publishes the image as `ghcr.io/sidianlabs/ovara-box:<tag>`
(amd64 and arm64, SBOM and signed provenance:
`gh attestation verify oci://ghcr.io/sidianlabs/ovara-box@<digest> --repo
SidianLabs/OVARA`), and the released binary defaults to it by digest
(`ovara version` prints it). Builds from source default to a local
`ovara-box`.

Each release also publishes one image per agent,
`ghcr.io/sidianlabs/ovara-box-<agent>:<tag>` for `claude`, `codex`,
`opencode` and `aider`, built FROM the box image by digest
(`box/agents/Dockerfile`). `ovara box -agent-image codex` picks it (and
implies tier 2; `-agent NAME` is the named agent the run acts as). The tier 2 agent tests run from these images, so what users get
is what is tested.

The box image (`box/Dockerfile`) is Node 24 on Debian slim with git,
Python, curl and an `ovara-agent` user (uid 10001); npm and pip install into
the per-run home. People extend it with their agent (`FROM ovara-box`, then
`npm install -g ...` as root). It holds no keys: the agent gets placeholders
and Ovara injects the real ones at the proxy. The agent environment is
passed in a root-only file, not on the `docker` command line.

Limits of tier 2, stated plainly: it shares the host's kernel (a kernel
exploit leaves the box; tier 3 is the answer); it needs root on the host
today; `-mount` exposes whatever the person mounts, read-only; and the
person's Docker daemon is trusted.

### 6.5 Driving the box from a tool: manifest and events

The command line is for a person. A CI job, an orchestrator or a service
drives the box through two documents instead (contract C5,
`spec/runtime.md`):

- the **manifest** is the run written down: tier, workspace, agent command
  and name, profile, isolation, mounts, limits, credential scope,
  commit-back settings. `ovara box -print-manifest [flags] <project> --
  <command>` writes the one a command line describes (on any platform, no
  root); `ovara box -manifest sandbox.json` runs it, flags given next to it
  winning, a `-- command` next to it replacing the file's. It carries no
  secret: a variable whose name says it is a key is refused, and real keys
  stay in the deployment. Kept in the repository, it says what the agent
  may do, not what it may use.
- the **events stream** (`-events FILE`) is what happens, one JSON line
  each, as it happens: `run.created` (with the manifest, defaults resolved),
  `workspace.copied`, `proxy.started`, `agent.started`, one `command.*`
  event per program the gate decided (allowed, refused, paused, approved,
  not_approved, with the approval id), `agent.exited` (the code), one
  `commit_back.*` event for how the changes ended (disabled, nothing, kept,
  refused, waiting, not_approved, landed with the branch), and always
  `run.finished` last, carrying the summary: outcome (clean, kept, failed),
  the agent's exit code, request and command tallies, the commit-back's
  end, and the error when the run failed.

A tool that watches the stream can answer `command.paused` and
`commit_back.waiting` through the approval API or `ovara approve <id>`,
and read the receipts (`ovara log export`) for the full record.

### 6.6 The attestation

Every run ends with one signed statement about it, in the deployment at
`var/attestations/<run>.intoto.json`: an in-toto statement in a DSSE
envelope, signed with the receipt key (spec C4 §8). Its subjects are the
run's own receipts and, when the changes landed, the branch and its commit;
its predicate carries the manifest's digest, the policy hashes, the exact
receipts (position, count, hash), every approval and who gave it, the host
table and the summary. The `run.finished` summary names the file. `ovara
attest verify` checks it against the chain, the key history and the anchors,
recomputing every claim from the receipts; it needs nothing that is not in
the incident bundle, so an auditor can verify a run without Ovara.

## 7. The file boundary

### 7.1 What the box sees

| Path in the box | What it is | Writable |
|---|---|---|
| `/work` | the workspace copy of the project | yes |
| `/scratch` | empty, for the agent's temp files, caches, venvs | yes |
| `/home/agent` | fresh home; agent config written by the launcher | yes |
| toolchains (`/usr/local/go`, node, python) | the image's | no |
| everything else on the host | **absent** | — |

This table is what tier 2 builds (milestone 4, §6.4). Tier 1 (isolated,
the default) builds the same shape in a mount namespace:

| Path in a tier 1 box | What it is | Writable |
|---|---|---|
| the workspace, at its real path | the copy of the project | yes |
| the run's home | fresh, per run | yes |
| `/usr`, `/bin`, `/sbin`, `/lib*`, `/etc` | the host's, bind-mounted; `/etc/shadow`, `/etc/gshadow`, sudoers, `/etc/ssh`, `/etc/ssl/private` covered | no |
| `/dev` | null, zero, full, random, urandom, tty, a private pts, `/dev/shm` | — |
| `/proc` | a fresh mount that hides other users' processes (Linux 5.8 or later; on an older kernel the box is refused unless `-allow-visible-procs`) | — |
| `/tmp`, `/var/tmp` | empty, in memory | yes |
| `/run` | empty | — |
| the public CA, `-mount` paths | read-only | no |
| `/home`, `/root`, `/srv`, `/opt`, `/mnt`, `/var`, `/nix`, the original project | **absent** | — |

Tools that live under `/opt` or a home directory, and scripts kept under
`/tmp` on the host, are not visible in a tier 1 box: add them with
`-mount` (and `-env PATH=…`). `-tier1-fs host` runs on the host's file
system as a separate user instead; there "absent" means only "not readable
by that user".

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

### 8.1 Design (built in milestone 3)

A shell wrapper was rejected: it runs as the same user as the agent, so
whatever it can execute the agent can execute directly. Instead the
launcher traces the agent's whole process tree with ptrace, asking only for
exec stops: every program, by any route, is stopped at the moment its new
image is loaded and before its first instruction (`internal/boxgate`). The
launcher reads the real command line from the kernel (`/proc/<pid>/cmdline`;
for a shell with `-c`, that string) and asks the gateway (`action_type:
"shell"`, resource `shell:<line>`). A traced process cannot shed its tracer
and a traced setuid program runs without its privilege. The decision is
applied the same way the proxy applies network decisions:

- **allow**: run it; stream input and output through untouched.
- **escalate**: the process stays stopped; the approval shows the command,
  its program and directory. On approval it continues; on denial or timeout
  it is killed (the tool sees exit 137 and a line on stderr).
- **deny**: killed before its first instruction.

In tier 2 the tracer is the container's PID 1 and the decision is made on
the host; the policy, the approvals and the receipts are the same.

The gate reads the command line from the stopped process's memory, so the
one way the approved line could differ from the arguments the program then
uses is another process of the same agent reaching into that memory before
the program reads it. Writing one process's memory from another needs the
ptrace-class syscalls (`process_vm_writev`, or `ptrace`'s own poke), and a
box process holds no capability that would let it reach outside the box, so
the only possible target is a sibling in the same box.

- **Tier 1** closes this: before the agent execs, box-init installs a
  seccomp filter (inherited by the whole tree, held in place by
  `no_new_privs`) that refuses `process_vm_writev`, `process_vm_readv` and
  `ptrace` with `EPERM`, so no box process can read or write another's
  memory (`installBoxSeccomp`, `cmd/ovara/box_seccomp_linux.go`). The
  gate's tracer is a separate host process and is unaffected. A debugger
  run inside the box gets `EPERM` as a result — the box is a sandbox, not a
  debugging environment.
- **Tier 2** still relies on the container runtime's default seccomp
  profile, which permits these syscalls between the container's own
  processes; a box-specific profile that removes them (while leaving the
  host-side tracer its ptrace) is the next step (§3 of the roadmap's
  hardening stage).

Independently of the gate: the program image itself cannot change, every
further exec is stopped again, and the network and file boundaries do not
depend on the gate.

Every command produces a receipt: command, directory, decision, exit
status, duration, output size. Output itself is not recorded unless the
policy asks (it can contain the project's data).

The gate is a second layer, not the first. The network and file boundaries
hold whether or not a command reaches the gate; the gate's job is to give
the person a say over actions *inside* the box that matter (destructive
commands, anything that would make the box less isolated) and to make the
command history part of the record. Cost: the three real agents ran their
battery under it (94–508 execs each) with no measurable slowdown.

### 8.2 Default command policy (box profile)

As shipped (`proxy/cmd/ovara/policy_defaults.go`):

| Decision | Commands |
|---|---|
| deny | `sudo`, `su`, `mount`/`umount`, `nft`, `iptables`, `ip netns`/`ip link`/`ip route`, running `ovara` |
| escalate | recursive `rm` (`rm -rf`, `rm -fr`, `rm -r…`), `find … -delete`, `shred`, `truncate -s 0`, `git push`, `mkfs`, `dd if=`, and an agent started with its own permission checks off (`--dangerously-skip-permissions`, `--dangerously-bypass-approvals-and-sandbox`, `--yolo`) |
| allow | everything else, recorded |

Rules match the normalised line from `boxgate.PolicyLine` (program base
name, git's global options dropped, `rm` flags merged, whitespace
collapsed). The first exec, when it is exactly the agent command given to
`ovara box`, is exempt from escalate (deny still applies), so an agent
launched with a bypass flag does not pause on its own start; the same
command started later by the agent still pauses.

Patterns use the same matcher as URL rules (`policy.MatchResource`,
already fuzzed), so one policy language covers all three exits. The
"escalate everything not listed" default for a stricter profile is not
built (§11.4).

## 9. Package installs

**Built in milestone 5** (`ovara box -profile strict`; `proxy/internal/lockfiles`,
`proxy/internal/proxy/packages.go`). How it works, as built:

- When the box starts, the launcher reads the project's lockfiles in the
  workspace: `package-lock.json`/`npm-shrinkwrap.json`, `yarn.lock` (classic
  and berry), `pnpm-lock.yaml`, `requirements*.txt` pins, `poetry.lock`,
  `uv.lock`, `Pipfile.lock`, `go.sum`, `Cargo.lock`, `Gemfile.lock` and
  `gradle.lockfile`. Lockfiles inside `node_modules`, `vendor` and the like
  are not the project's and are not read. It hands the pinned packages,
  with any digests the lockfiles record, to Ovara (`ovara run
  -package-gate`).
- The proxy names every package **download** on the registries it knows:
  `npm:left-pad@1.3.0`, `pypi:six@1.16.0`, `go:module@v1.2.3`,
  `crate:serde@1.0.200` (static.crates.io and the crates.io download API),
  `gem:rake@13.0.6` (rubygems.org), `maven:group:artifact@1.2.3`
  (repo1.maven.org, repo.maven.apache.org). Metadata reads (an npm
  packument, a PyPI index, a Go `.info`, a crates.io sparse index entry,
  `maven-metadata.xml`, checksums) are not downloads of code and are not
  asked about. A request to one of these registries that is neither a
  recognised download nor metadata asks policy once as
  `download:<host><path>`.
- **Digests.** When a lockfile records a digest for a pinned package (npm,
  yarn classic and pnpm `integrity`, requirements `--hash`, poetry and uv
  hashes, `Pipfile.lock`, Cargo `checksum`), the proxy hashes the download
  as it streams and holds back the last chunk until the end. If the digest
  differs, the agent never gets the whole file: the connection is cut and
  a second receipt (`deny 502`) names the URL. `go.sum` is not checked (it
  records a tree hash, not the file's). Yarn berry checksums and poetry v1
  `[metadata.files]` hashes are not read.
- `-untrusted-lockfiles`: for a repository you are reviewing rather than
  your own. The lockfiles are still read, so packages are named, but
  nothing they pin is let through unasked and their digests are not used.
- After the URL policy has allowed a download, a pinned package goes
  through. Any other asks the gateway: `action_type: "package.install"`,
  resource `npm:name@version`, which the default policy escalates. The
  person sees "install npm package is-number 7.0.0 (a new dependency: not in
  the project's lockfiles)". Approved, it is allowed for the rest of the
  run, so each new dependency pauses **once**; parallel downloads of one
  package ask once; refused, it never downloads (npm reports a 403). A
  policy can allow trusted names outright (`npm:@types/*`).
- A registry that is not in the trusted list is not read freely, so a
  package manager pointed at it pauses at its first request (tested with
  `--registry https://registry.npmmirror.com/`).
- `npm audit` stays free (exact-path rules); strict sets
  `npm_config_ignore_scripts=true` for the agent.

Tested (`tests/box/strict.sh`, CI job `box-strict`): `npm ci` and `pip
install -r` of pinned packages ask no one; a new npm and a new pip package
each pause once by name and version, then install; installing the first
again after clearing npm's cache asks no one; a refused package never
arrives; the unlisted registry pauses and, refused, gives nothing; npm
audit needs no one; the receipts agree; the dev profile asks nothing.

Limits: a dependency that comes as a git URL or a tarball from another
host is not a registry download and goes through the URL policy only (a
new host pauses anyway); in a project with no lockfile every package pauses
once, including each transitive dependency, so commit the lockfile first.
Policies written before milestone 5 have no `package.install` rule; the
launcher warns, and without the rule new packages are refused rather than
paused.

The design as first written:

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
| Linux | tier 1 (netns) or tier 2 (container) directly | on the host | tier 1 and tier 2 built and tested (tier 2 in CI on GitHub's runners) |
| macOS | the box inside a Lima VM; `ovara box` drives it (`-vm lima`, the default) | on the host, proxy and command gate reachable from the VM's network only | built (§10.1); tested end to end on Linux with a stand-in VM; not yet run on a real Mac |
| Windows | tier 2 inside WSL2 (Docker Desktop's VM or a dedicated distro) | on the host (Windows binary) or inside WSL2 | not built |
| CI | tier 1 in a privileged job, or tier 0 with the `ci` profile when privilege is unavailable | same job | tier 0 tested (`ci-bot`), tier 1 tested in the agent matrix |

Rule for the VM platforms: the VM's only network path is to Ovara's proxy
address, the same rule as the netns; the workspace copy lives inside the
VM; commit-back crosses the VM boundary through the file gate. "Cooperative
only" on macOS/Windows is acceptable for a first release **if the docs say
so in the first paragraph**; a release that claims the box on those
platforms without the VM is not acceptable.

### 10.1 The VM driver (built so far)

`proxy/internal/vm` is the host's side of the VM platforms. A `Driver`
creates a VM, verifies it, copies the workspace in and the result out, runs
a command in it and deletes it; Lima (macOS) is the first, WSL2 and the
tier 3 microVM are meant to be further drivers behind the same interface.

What the Lima driver does today:

- **Instance config, hardened by setting, not by default.** Lima's defaults
  share the home directory, forward guest ports to the host's loopback and
  copy the host's proxy variables into the guest. Ovara's config turns each
  off explicitly: no mounts (the workspace is copied in), no SSH agent or X11
  forwarding, the host user's SSH keys not authorised in the guest, no port
  forwards in either direction of the guest's addresses, no proxy variables
  copied in, containerd off. Ubuntu 24.04 cloud images, amd64 and arm64.
- **Guest network lockdown.** A provisioning script that Lima runs as root
  at every boot loads an nft table `ovara_vm` in the guest: every packet out
  is dropped unless it is loopback, the reply to a connection made *to* the
  guest (Lima's own control channel), or TCP to the host's proxy or
  command-gate port. DNS and QUIC are dropped by name; IPv6 falls to the
  drop policy and is also switched off. The host is found through the
  guest's hosts file (`host.lima.internal`), not DNS.
- **Fail closed.** Before an agent runs, `Verify` checks from inside the VM
  that the table is loaded with a drop policy and that a direct connection to
  a public address fails. Any other outcome, including an error running the
  check, is a refusal. Every driver call also refuses a VM whose name is not
  `ovara-...`, so Ovara never touches a VM it did not make.

How it is tested without a Mac: the guest is a Linux kernel and only the
hypervisor is missing, so CI's root job runs the real provisioning script
in a network namespace standing in for the guest, twice (Lima reprovisions
at every boot), and checks from inside it that the proxy and gate ports
answer while another host port, TCP 53 and a UDP datagram to 443 do not
(`TestLockdown_GuestReachesOnlyTheProxyAndGate`); the test fails if the drop
policy is removed. The `limactl` command sequence, the config and the
fail-closed checks are tested against a stand-in `limactl`.

The guest side of the box (`box-init -vm`, `cmd/ovara/box_vm_guest.go`)
runs as root in the guest once the host has copied in the workspace and a
spec:

- **The agent is its own unprivileged user**, created in the guest and in no
  group that can become root (the image's own user has passwordless sudo, so
  the agent is never it). As that user it cannot unload the lockdown.
- **Every program goes to the host's command gate**, over TCP this time:
  the guest's lockdown lets the whole guest reach the gate port, so the
  connection opens with a per-run token that only box-init holds. It reads
  it from the spec and deletes the spec before the agent exists. A
  connection without the token gets no answer, so an agent cannot ask the
  gate about programs that are not running and have the answers remembered.
  Without the gate box-init does not start the agent.
- **The agent starts through a shim** (`box-init -vm-exec`) that, as the
  agent's user, sets `no_new_privs` and the box's seccomp filter before the
  agent's first instruction, the same protection tier 1 has (§8). The gate
  never sees the shim; it sees the agent's own exec.
- **The workspace comes back as one tar** written after the agent and every
  process it started have gone: directories, files and links, links kept as
  links and never read through, FIFOs and devices left out (`writeTree`). The
  host unpacks it into a fresh directory and refuses anything that could
  write outside it: absolute names, `..`, a path through a link, a repeated
  name, any other entry type, more than 8 GiB or a million entries
  (`extractTree`). Then the existing commit-back reads it as for any box.

Tested on Linux as root with this host as the guest and a gate in the test
as the host (`TestVMGuest_*`, CI's root job): the agent runs as a fresh
non-root user under `no_new_privs` and the filter, a program the gate refuses
never runs, the spec is gone, and a wrong token stops the run before the
agent starts.

The host side (`ovara box -vm lima`, `cmd/ovara/box_vm_host.go`) ties it
together, and on macOS it is the default, since tiers 1 and 2 need a Linux
host. `ovara box` runs as the person there (Lima refuses root), keeps its
runs in the deployment directory, and for each run:

1. starts Ovara on the host as for tier 2, and the command gate on a port
   only the run's token opens;
2. creates the VM with its lockdown and verifies it from inside, or stops;
3. copies in the workspace as one tar (so a link in the project cannot pull
   a host file into the guest), Ovara's public CA, the Linux build of ovara
   (`ovara-linux-<arch>` next to the macOS one, or `-vm-binary`) and the
   guest spec;
4. runs `box-init -vm` there as root, and so the agent as its own user;
5. copies the workspace tar out, unpacks it strictly, puts it in place of the
   host's copy, and hands over to the same commit-back as every tier;
6. deletes the VM. `-cpus` and `-memory` size it.

A stop (SIGTERM or Ctrl-C to `ovara box`) is done in order: the host runs
`box-init -vm-stop` in the guest, box-init sends SIGTERM to every process of
the agent's user (SIGKILL after 10 seconds), still writes the workspace, and
it comes back as after a normal exit; the gate refuses any new program
meanwhile. A second signal, or a guest that has not finished within two
minutes, ends the run at once, and then the workspace stays as it went in.

End to end on Linux in CI: `TestVMBox_EndToEnd` runs the real binary with a
network namespace standing in for the VM (`-vm netns-test`, offered only
when `OVARA_BOX_VM_NETNS_TEST=1`; it shares the host's file system and is
not a boundary). Everything but the hypervisor is the code a Lima run uses:
the agent runs as its own non-root user under `no_new_privs` and the seccomp
filter, a request to a blocked site gets Ovara's 403, a direct connection
out is blocked, `sudo` is refused by the gate, the project goes in without
`.env`, the agent's change comes back, and nothing of the VM is left. The
test fails if the gate is turned off. `TestVMBox_StopBringsTheWorkBack`
stops a run with SIGTERM and checks that the agent got SIGTERM in the guest
and that what it wrote came back; it fails if the stop kills the guest's
command instead.

Not done yet: **no real Lima VM has booted this code on a Mac** — that needs
a macOS CI runner (the owner's) and is the next step, followed by WSL2 for
Windows. Until a real Mac run passes the agents matrix, the first-paragraph
rule above stands: macOS and Windows are documented as cooperative only, and
`-vm lima` is new and unproven there. The VM choice is a launcher flag, not
yet part of the run manifest (C5); adding it is an RFC (`spec/rfcs/`).

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

Selected per file: `"precedence": "most-specific"` (what `ovara init`
writes now); files without it keep the order-based rule. `"default":
"deny"` sets the no-match decision. Two rules of identical scope and
pattern but different effects resolve by the tie-break and the validator
names the one in force. **Built in milestone 1.**

### 11.3 One language for three exits

`action_type` already distinguishes `http.request`, `shell`, `exec`; the
box adds `fs.commit_back`. Resources per type:

| action_type | resource | example |
|---|---|---|
| `http.request` | `METHOD scheme://host/path` | `POST https://api.github.com/repos/*/pulls` |
| `shell` | `shell:<command line>` | `shell:git push*` |
| `fs.commit_back` | `path:<repo-relative path>` | `path:.github/workflows/*` (deny) |

### 11.4 Profiles

(These are the box's install profiles, `-profile dev|strict|ci`. The policy
profiles `strict|balanced|observe` of `ovara policy profile` are a different
setting, applied to the deployment's `policy.json`; a box runs under either.)

| Profile | Default | Reads | Writes | Commands | Installs | Approval timeout |
|---|---|---|---|---|---|---|
| `dev` | escalate | trusted list free, others pause | pause | read/build/test free, destructive pause | free | 60 s |
| `strict` | deny | trusted list free, others pause | pause | read/build/test free, everything else pause | new deps pause | 60 s |
| `ci` | deny | trusted list free, others deny | only the listed ones | listed ones only | lockfile only | 10 s |

As built: `-profile dev` (default) and `-profile strict` differ in installs
only (strict: new dependencies pause once, npm install scripts off; §9).
`-profile ci` is strict for an unattended run: anything the policy would
pause (a request to a host outside the trusted list, a package the
lockfiles do not pin, a command such as `rm -rf`, the commit-back) is
refused at once instead of waiting for a person, and no approval is
opened (`ovara run -unattended`). The commit-back needs a person by
default, so in `ci` the workspace is kept unless the policy allows
`fs.commit_back` outright. Tested in `tests/box/strict.sh` (refusals take
seconds; no approval, no branch). The rest of the `strict` row (default
deny, commands beyond read/build/test pausing) is not built.

Profiles are ordinary policy files shipped in the binary (`policy_defaults.go`
grows two siblings); `-policy` overrides, `.ovara/policy.json` in the
project extends.

## 12. Components and where they live

| Component | Package / path | Exists |
|---|---|---|
| gateway: decisions, approvals, receipts, shield, identity | `runtime/gateway` | yes |
| proxy: MITM, policy flow, key injection, scrub, preview | `proxy/internal/proxy` | yes |
| boundary script (netns, docker) | `proxy/scripts/setup-egress-boundary.sh` | yes (both modes red-teamed in CI) |
| CLI: init, run, env, watch, approvals, log, doctor | `proxy/cmd/ovara` | yes |
| approval page | `proxy/cmd/ovara/ui` | yes |
| **launcher** `ovara box` (tiers 1 and 2) | `proxy/cmd/ovara/box.go`, `boxinit.go` | yes |
| **workspace + file gate** (snapshot, secret exclusion, diff preview, commit-back as a branch) | `proxy/internal/workspace` | yes |
| **command gate** | `proxy/internal/boxgate` (ptrace, in the launcher) | yes |
| **install policy** (registry pins, new-dependency pause) | `proxy/internal/lockfiles`, `proxy/internal/proxy/packages.go`, `-profile strict` | yes |
| **policy v2** evaluator + migrate + shadow check | `runtime/gateway/internal/{policy,evaluator}` | yes |
| **box image** (tier 2): agent runtimes, no secrets, read-only root | `box/Dockerfile` | yes |
| **VM driver** (Lima / WSL2) | `proxy/internal/vm` | started: the driver interface and the Lima driver (hardened instance config, guest network lockdown, fail-closed verify), the guest side of the box (`box-init -vm`) and `ovara box -vm lima` (the default on macOS); tested end to end on Linux with a stand-in VM, not yet booted on a real Mac; WSL2 not started (§10.1) |
| tests: agents matrix, scenarios, red teams | `tests/` | yes; grows per milestone |

## 13. Data flows

**A request leaves the box.** Agent → proxy (CONNECT) → policy check at the
gateway (literal host only; no DNS before the decision) → allow: inject
key, forward, scrub response, receipt before the response is released;
escalate: approval created with the preview, person answers, then as
allow or a 403, or a 503 "held, retry" (the default) / 504 once the hold ends; deny: 403 with reason, receipt.

**A command runs.** The agent's tool starts a program → the launcher's
ptrace gate stops it at exec → gateway check on the normalised line → run
/ hold / kill → receipt.

**Files go back.** Agent (or the person at exit) → file gate computes the
diff → gateway check (`fs.commit_back`) with the diff as preview → person
approves → commit on `ovara/box-<date>` in the real repo → receipt.

**A secret is used.** Only ever on the host side of the proxy. The box holds
a placeholder; the proxy substitutes the real value for the bound host over
HTTPS; the response is scrubbed of the value and its encoded forms.

**The person answers.** Approval page (per-run page token) or `ovara watch`;
the approval carries the gateway's own record of the request, never the
agent's text; "approve and remember" adds a rule for exactly one thing: reads
from that host (for the run or the project), this command line for the run, or
this MCP tool for the run; never a write, never a wildcard.

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
| 2 | **`ovara box` tier 1 on Linux** (launcher + workspace snapshot + secret exclusion; no command gate yet) | **done**: agents matrix runs through `ovara box` (`mode: box`); `tests/box` plants `.env`/`id_rsa`/a committed `.pem` and finds them absent; commit-back lands on a branch with the diff in the approval; the `.github/workflows/*` change is kept out | done |
| 3 | **Command gate** | **done**: `tests/box` adds `sudo` (killed), `sudo` via python (killed), `rm -rf` (paused, refused, nothing deleted); the agents matrix runs under the gate; a program started by any route is seen (ptrace, no same-user bypass) | done |
| 4 | **Tier 2 container** + docker boundary test finally run | **done**: the boundary red team passes in docker mode and from inside a tier 2 box; `tests/box` with `TIER=2` passes the tier 1 checks plus the container's own (no capabilities, read-only root, loopback only, sockets closed to the agent, no host paths or credential files, init unkillable); the three agents run their battery in a tier 2 box | done |
| 5 | **Install policy** | **done**: `strict`: a new dependency pauses once with name+version; a package from an unlisted registry pauses; npm audit still free (`tests/box/strict.sh`, 23 checks, real npm and pip) | done |
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
2. **Approval fatigue**: answered. "Approve" offers "and allow exactly this
   command until ovara run stops" (run-scoped, the exact normalised line,
   never a wildcard; the rule names who, when and the approval); persistent
   rules only through "remember reads for the project" and explicit policy
   edits.
3. **Where the model API key lives for Aider/opencode-style agents that
   want it in a config file**: placeholder in the file, substituted at the
   proxy, same as env vars. Needs a test per agent.
4. **Receipt retention and size**: answered. The chain rotates into
   gzip-compressed, numbered segments (`receipts.NNNNNN.jsonl.gz`) at
   `receipts_segment_bytes` (default 64 MiB), the next file continuing the
   same chain. Ovara never deletes a receipt; the log, the page, the
   verifier and the attestations walk every segment, and every segment must
   be there: a missing one fails verification like any other cut. `ovara
   doctor` reports the size and warns over `receipts_warn_bytes` (default
   256 MiB on disk); `docs/operations.md` (Retention and export) says what
   to do then. Tested at 100k receipts.
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
