# OVARA Runtime Gateway — Security Architecture

This document describes **what the gateway actually enforces in code today**
and, separately, what the artifacts in this directory are (deployment /
monitoring templates that require per-deployment tuning). Earlier versions of
this document implied the artifacts below were wired into the gateway's
decision path — they are not; see "Enforcement reality" below.

## What is enforced in code

```
agent ──► gateway /v1/runtime/check ──► evaluator (policy + trust + leases)
                                              │ allow / deny / escalate
        ◄── signed decision receipt ◄─────────┘
agent ──► executor (shell/exec/git/github/ci continuations) — only runs
          after an allow/approved decision
agent ──► proxy — boundary between the agent and external side effects
```

Concretely:

- **Policy evaluation**: `runtime/gateway` evaluates every action request
  against the configured policy store. Decisions are `allow`, `deny`, or
  `escalate` (requires human approval via the approval flow).
- **Capability leases**: when `trusted_issuers` is configured, lease
  signatures are verified with ed25519 against trusted issuer keys
  (`internal/identity`). With no trusted issuers configured, signed lease
  validation fails closed and `/v1/capabilities/track` accepts unsigned
  leases only in that explicitly-warned dev mode.
- **Receipts**: decisions produce HMAC-signed receipts (`sig_v1`) so a caller
  can prove what decision was issued.
- **Execution boundary**: continuations only execute through registered
  executors after the required decision/approval state. The interceptors
  (`interceptors/shell`, `interceptors/git`) check with the gateway first and
  fail closed on deny, escalate, unknown decisions, or gateway errors.
- **Sandbox executor** (`shell.sandboxed`, enabled via
  `OVARA_SANDBOX_ENABLED=true`): runs commands inside a Docker container with
  `NetworkMode=none` (default), all capabilities dropped, and
  `no-new-privileges`. NOTE: it talks to `/var/run/docker.sock`, which is
  host-root — treat that socket as a trust boundary.

## What the artifacts in this directory are

Everything under `security/` is a **deployment/monitoring template**, not
part of the gateway binary:

| Artifact | What it is | What it is NOT |
|----------|-----------|----------------|
| `apparmor/ovara-gateway` | A minimal, working AppArmor starting template | A shipped policy. Paths must be tuned per deployment; test in complain mode first. |
| `sandbox/seccomp-profile.json` | A syscall allowlist for container runtimes (e.g. `docker --security-opt seccomp=...`) | Applied automatically by the gateway or by Firecracker. It also does not restrict `setuid`/`setgid`/`chown` or io_uring — those syscalls are absent from the allowlist. `clone3` is allowed because the Go runtime needs it on newer kernels. |
| `sandbox/firecracker.yaml` | A valid Firecracker config-file skeleton with no NIC | A complete sandbox. Guest images, the jailer, cgroup limits and runtime caps are host-side concerns documented in the file. |
| `ebpf/` | Audit/monitoring hooks: tracepoints and kprobes that push events to a ring buffer | An enforcement mechanism. Tracepoints cannot block syscalls; `hooks.yml` is `action: audit` only. `global_agent_id` defaults to 0 and must be set by the loader. |

### Deployment guidance

If you want kernel-level confinement around the gateway:

- **AppArmor**: copy `apparmor/ovara-gateway` to `/etc/apparmor.d/`, adjust
  paths, run `aa-complain` first, then enforce:
  `sudo apparmor_parser -r /etc/apparmor.d/ovara-gateway`
- **Seccomp** (container deployments):
  `docker run --security-opt seccomp=security/sandbox/seccomp-profile.json ...`
- **Firecracker**: `firecracker --config-file security/sandbox/firecracker.yaml`
  after preparing `vmlinux.bin` and `rootfs.ext4`; use the jailer and cgroup
  limits for privilege separation (see file comments).
- **eBPF**: `cd security/ebpf && make`, then load with a loader that sets
  `global_agent_id`; consumes events for audit only.

## Known limitations

- The gateway's decisions are **advisory by design**: an agent that ignores
  the check result and calls out-of-band tooling bypasses it. Enforcement at
  the endpoint requires interceptors/proxy on the agent's execution path.
- eBPF hooks are audit-only (see above).
- The docker-socket sandbox grants host root to whoever controls the socket.
- Receipt signatures are HMAC-SHA256 with a single configured key; key
  rotation invalidates cross-restart verification.

## Security Contact

Report security vulnerabilities to the OVARA security team. Do not open
public issues for security reports.
