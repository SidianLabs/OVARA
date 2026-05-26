# Phase 59 Multi-Surface Execution Foundations — Checkpoint

**Date**: Tue May 26 2026
**Branch**: Not yet created — awaiting Phase 58/58.5 PR merge
**Parent**: Phase 58/58.5 (PR #2)
**Objective**: Remove shell-only execution constraint, introduce executor abstraction, add first non-shell execution surface

---

## 1. Repository Verification

- **Current branch**: `phase-58-5-orchestration-verification` (Phase 58/58.5)
- **Remotes**: `origin` → https://github.com/SidianLabs/OVARA.git
- **PR**: https://github.com/SidianLabs/OVARA/pull/2 targeting `phase-7-foundations`
- **Phase 58 status**: Under review — NOT YET MERGED
- **Default remote branch**: `origin/phase-7-foundations`

**Decision**: Phase 59 implementation must NOT begin until Phase 58 PR merges. This checkpoint documents findings and plan. No implementation code is committed in this pass.

---

## 2. Execution Model Audit

### Shell-Specific Constraints (Hard Barriers)

| Location | Line | Code |
|---|---|---|
| `continuation/store.go` | 242 | `if c.ActionType != "shell" { return false }` in `CanExecute()` |
| `handlers/continuations.go` | 460 | `execution only supported for shell action type` in `handleExecute()` |

**These two checks are the only thing preventing non-shell execution.**

### What Is Already Properly Abstracted

| Component | Abstraction Quality |
|---|---|
| `Executor` interface | `Execute(ctx context.Context, e *Execution) error` — clean, type-neutral |
| `ShellExecutor` | Concrete shell implementation — only implements `Executor` |
| `Execution` struct | Has `ActionType` string — already used for routing |
| `execution.Store` | Generic over all execution types |
| Orchestrator | Calls `executor.Execute()` — zero shell knowledge |
| `continuation/orchestrator.go` | Already accepts any `execution.Executor` |

### Shell-Specific Implementation

| Component | Shell-Specific |
|---|---|
| `ParseShellResource("shell:cmd")` | Only parses `shell:` prefix — returns raw command string |
| `ShellExecutor.Execute()` | Calls `exec.CommandContext(execCtx, "sh", "-c", cmd)` |
| Default policy escalation for `shell` | Policy rule: shell → escalate by default |

### Resource Format Analysis

| ActionType | Resource Format | Parser |
|---|---|---|
| `shell` | `shell:<command string>` | `ParseShellResource()` |
| `git.push` | `git:<repo>:<ref>` (seen in PRD examples) | Not implemented |
| `git.pull` | `git:<repo>` | Not implemented |
| `github.merge` | `github:<repo>:<pr>` | Not implemented |
| `ci.trigger` | Not yet defined | Not implemented |

### Identified Gap

**The abstraction boundary is clean at the `Executor` interface, but the enforcement at `CanExecute()` and `handleExecute()` is shell-locked.** The resource parsing (`shell:` prefix) and execution (`sh -c`) are correctly encapsulated in `ShellExecutor`, but there is no routing mechanism from `ActionType` → `Executor`.

---

## 3. Proposed Abstraction

### ExecutorRegistry

```go
// No new interface — reuse existing Executor
type Executor interface {
    Execute(ctx context.Context, e *Execution) error
}

// Registry maps ActionType → Executor
type ExecutorRegistry struct {
    executors map[string]Executor
}

func (r *ExecutorRegistry) Register(actionType string, exec Executor)
func (r *ExecutorRegistry) Get(actionType string) (Executor, bool)
```

**Minimal changes required:**

1. **Remove** `ActionType != "shell"` from `CanExecute()` — the executor registry handles unknown types
2. **Remove** `ActionType != "shell"` from `handleExecute()` — replaced with registry lookup
3. **Add** `ExecutorRegistry` — registers `shell` → `ShellExecutor` at startup
4. **Update** `handleExecute()` and orchestrator to call `registry.Get(cnt.ActionType)` then `executor.Execute()`
5. **Unknown action types** → `404` or `400` with message (degraded gracefully — not a panic)

### Why Not a Factory Interface?

A factory (`NewExecutor(actionType string) Executor`) would require every new executor to implement initialization logic. The registry approach is simpler: register concrete instances at startup, lookup at runtime. No new interface needed — reuse `Executor`.

---

## 4. Candidate Next Execution Surface

**Chosen: Structured Local Command Execution (Subprocess without shell)**

**Rationale:**
1. The PRD V1 scope says "shell command execution" — Ovara's agents currently ONLY run shell commands
2. The shell executor is the most risky: `sh -c` interprets metacharacters, allows pipes/redirection/backgrounding
3. A "direct subprocess" executor would run `exec.CommandContext(ctx, binary, args...)` directly — no shell interpretation
4. This is safer by default AND opens the door to structured git operations (git binary called directly, not via `sh -c`)
5. The gap between "shell:echo hello" and "git:push origin main" is smaller than it appears — both could use `exec.CommandContext`

**Alternative considered: Git executor**
- Well-justified by PRD (V1 scope includes "GitHub and Git mutation")
- But git operations need repo context, remote resolution, auth — more scope than Phase 59's "smallest practical next surface"
- Better as Phase 60

**Decision: Structured Local Command Executor (Direct Subprocess)**

| Aspect | ShellExecutor | DirectExecutor (new) |
|---|---|---|
| Command | `sh -c "echo hello"` | `exec.Command("echo", "hello")` |
| Metacharacters | Pipes, redirects, glob, bg | None — args are literal |
| Security posture | High risk | Low risk |
| Use case | Ad-hoc scripts | Structured tool invocation |
| `shell:` resource | Yes | No — new `exec:<binary> <args>` format |

### New Resource Format

```
exec:git push origin main
exec:docker ps
exec:kubectl get pods
```

**Parsing:**
```go
func ParseExecResource(resource string) (cmd string, args []string, error) {
    if !strings.HasPrefix(resource, "exec:") {
        return "", nil, fmt.Errorf("resource does not start with exec:")
    }
    parts := strings.SplitN(strings.TrimPrefix(resource, "exec:"), " ", 2)
    // ... validation
}
```

---

## 5. Implementation Plan (For Phase 59 Proper)

### Milestone A: Remove Shell Lock ✓ (Documented — no code committed)

- `CanExecute()` — remove `ActionType != "shell"` check
- `handleExecute()` — replace with registry-based routing

### Milestone B: ExecutorRegistry ✓ (Documented — no code committed)

- Add `executor_registry.go` with `ExecutorRegistry` struct
- Register `ShellExecutor` as `shell` action type
- Update `handleExecute()` and orchestrator to use registry

### Milestone C: DirectExecutor (New Execution Surface) — PENDING

- Add `DirectExecutor` struct implementing `Executor`
- `Execute()` calls `exec.CommandContext(ctx, binary, args...)` directly
- No shell interpretation — args are literal
- Register as `exec` action type
- Add `ParseExecResource()` resource parser
- Add policy rule: `exec` actions → escalate by default (until trusted)

### Milestone D: Tests and Docs — PENDING

- Unit tests for `ExecutorRegistry` lookup
- Unit tests for `ParseExecResource()`
- Unit tests for `DirectExecutor`
- Update `runtime_examples.md` with `exec:` format

---

## 6. Why Phase 59 Should Not Start Yet

Phase 58/58.5 PR (#2) is under review. Building Phase 59 on a stacked branch creates:
- Dependent PRs that can't be reviewed independently
- Risk of rebase conflicts when Phase 58 finally merges
- Blurred phase boundaries

**Recommendation**: Wait for PR #2 to merge, then create `phase-59-multisurface-execution` from `phase-7-foundations` (or whatever `main` becomes post-merge).

---

## 7. Non-Goals Confirmed

- No distributed executors
- No cloud worker orchestration
- No browser/payment execution
- No full plugin architecture
- No broad execution rewrite — only remove the shell lock and add one new surface

(End of file — checkpoint prepared, no implementation committed)
