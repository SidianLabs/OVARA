# `git.checkout` Implementation — Engineering Report

## Chosen Capability: `git.checkout`

`git.checkout` was selected as the next git capability after `git.fetch`, following evaluation of the implementation complexity and product value.

## Why `git.checkout`

1. **Naturally narrow**: Checkout is a single git operation with well-defined semantics for existing branches only
2. **Operationally useful**: Agents frequently switch branches during automated workflows — a checkout that requires approval adds safety
3. **No ambiguous variants**: Unlike `git checkout -b` (create branch) or `git checkout -- <file>` (restore file), plain `git checkout <branch>` is unambiguous and safe within the existing resource model
4. **Local repo only**: Unlike push which modifies remote state, checkout is local. However, it CAN overwrite uncommitted changes in the working tree, which is why escalation (not denial) is the right policy
5. **Existing infrastructure**: Reuses the GitExecutor, registry, interceptor, and resource parsing — minimal new code

## Resource and Action Design

### Resource Format: `git:<repo>:<branch>`

**Example**: `git:/home/user/repo:main` → `git -C /home/user/repo checkout main`

The format uses a single `:` separator between repo and branch (unlike push/pull which use `:branch/`). This avoids ambiguity with the `WithBranch` helper used by push/pull which appends `:branch/<name>`. A new `WithCheckout(branch)` helper was added to the interceptor to construct the correct format.

### Action Type Constant

```go
ActionTypeGitCheckout ActionType = "git.checkout"
```

### Interceptor Changes

The `resolveGitActionType` function now has an explicit case for `checkout`:
```go
case "checkout":
    return models.ActionTypeGitCheckout
```

A new `ActionOption` was added:
```go
func WithCheckout(branch string) ActionOption {
    return func(a *Action) {
        a.CheckoutBranch = branch
    }
}
```

And `normaliseAction` was updated to handle `action.CheckoutBranch` differently from `action.Branch` — `CheckoutBranch` sets `:branch` directly without the `branch/` prefix.

### Executor Case

```go
case "git.checkout":
    if gitRes.Branch == "" {
        e.MarkFailed("git checkout: branch is required", 1)
        return fmt.Errorf("branch is required for git checkout")
    }
    args = []string{"checkout", gitRes.Branch}
```

Runs `git -C <repo> checkout <branch>`.

### Safety Constraints

V1 `git.checkout` is intentionally limited to switching between **existing branches only**:
- `git checkout <branch>` — supported ✓
- `git checkout -b <new-branch>` — not supported, exits non-zero when agent runs it
- `git checkout -- <file>` — not supported, exits non-zero when agent runs it

This keeps the scope small and safe. If an agent passes `-b` or paths, the underlying git command fails naturally.

## Policy

**Default: escalate** (require approval in all environments)

Checkout modifies the working tree and can discard uncommitted changes. Unlike `git.pull`/`git.fetch` which are read-only, checkout is a write operation that requires human review before proceeding.

```json
{
  "action_type": "git.checkout",
  "environment": "*",
  "escalate": true,
  "description": "Git checkout modifies working tree — requires approval to prevent accidental overwrites"
}
```

## Failure and Degraded Behavior

| Scenario | Behavior |
|----------|----------|
| No branch provided | `"git checkout: branch is required"` — StateFailed |
| Branch does not exist | git exits non-zero — StateFailed |
| Working tree has uncommitted changes | git may refuse to switch — StateFailed or git error |
| Repo path does not exist | `"git: repository path does not exist"` — StateFailed |
| Not a git repo | `"git: not a git repository"` — StateFailed |
| Symlink in repo path | `"git: symlink traversal not allowed"` — StateFailed |
| git binary not found | `"git: binary not found in PATH"` — StateFailed |
| Timeout | `"git: command timed out after Xs"` — StateTimedOut |

## Commands Run

```bash
cd runtime/gateway
go build ./...              # passed
go vet ./...                # passed
go test ./...               # passed (all packages)
go test -race ./...         # passed (all packages)
```

## Files Changed

| File | Change |
|------|--------|
| `internal/models/action_request.go` | Added `ActionTypeGitCheckout = "git.checkout"` |
| `interceptors/git/interceptor.go` | Added `CheckoutBranch` field, `WithCheckout` option, explicit `checkout` case in `resolveGitActionType`, updated `normaliseAction` to handle checkout separately |
| `internal/execution/store.go` | Added `git.checkout` case in `GitExecutor.Execute` switch |
| `cmd/server/main.go` | Registered `git.checkout` in executor registry; updated startup log |
| `examples/sample_policy_local.json` | Added `git.checkout` escalate rule |
| `examples/sample_policy.json` | Added `git.checkout` escalate rule |
| `runtime/gateway/SUPPORT_MATRIX.md` | Added `git.checkout` to supported action types, default policy, failure modes |
| `docs/architecture/runtime_support_matrix.md` | Added `git.checkout` to supported action types, default policy, failure modes |

## Tests Added/Updated

| File | Test | Purpose |
|------|------|---------|
| `interceptors/git/interceptor_test.go` | `TestResolveGitActionType` | Added checkout cases |
| `interceptors/git/interceptor_test.go` | `TestInterceptor_normaliseAction_Checkout` | Verifies resource format `git:/home/user/repo:feature` |
| `interceptors/git/interceptor_test.go` | `TestInterceptor_normaliseAction_CheckoutMain` | Verifies resource format `git:local:main` |
| `internal/execution/store_test.go` | `TestGitExecutor_Integration_Checkout` | Real git repo, creates branch, verifies checkout succeeds |
| `internal/execution/store_test.go` | `TestGitExecutor_Checkout_MissingBranch` | Verifies `branch is required` error when no branch provided |
| `internal/execution/store_test.go` | `TestGitExecutor_Checkout_NonexistentBranch` | Verifies failure when branch does not exist |

## Policy Implications

- **Default: escalate** — `git.checkout` requires approval before execution in all environments
- **No breaking change** — existing policies that don't mention `git.checkout` use the catch-all rule or allow nothing specific
- **Backward compatible** — checkout was not previously implemented; no existing usage is affected

## Future Git Phases

Potential follow-on git capabilities (not implemented here):
- `git.checkout -b <new-branch>` — creating branches is more dangerous; would need separate policy consideration
- `git.checkout -- <file>` — file-level restoration; different resource format needed
- `git.merge` — merging modifies working tree; escalate policy appropriate
- `git.rebase` — rebasing rewrites history; requires careful policy design
- `git.stash` / `git.stash pop` — working-tree save/restore; moderately risky
