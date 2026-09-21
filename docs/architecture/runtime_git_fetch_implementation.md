# `git.fetch` Implementation — Engineering Report

## Chosen Capability: `git.fetch`

`git.fetch` was selected as the next V1 capability after evaluating the codebase and existing action type inventory.

## Why `git.fetch`

The codebase exploration revealed:

1. **Already partially wired**: The git interceptor's `resolveGitActionType()` generates `models.ActionType("git.fetch")` for any `git fetch` command via its default case. The action type constant was not defined and the executor had no case for it, so `git fetch` would fail at execution time with "unsupported git action type".

2. **Natural fit**: `git fetch` is a read-only operation (updates remote-tracking refs but does not modify working tree or remote). This maps cleanly to `git.pull`'s safety profile — it can be auto-approved in all environments.

3. **Simple implementation**: Adding `git.fetch` required only:
   - A new `ActionTypeGitFetch` constant
   - A new case in `GitExecutor.Execute`'s action-type switch
   - Registration in the executor registry
   - Policy rule
   - Docs updates

4. **Real product value**: Agents performing `git fetch` to inspect remote branches before pull/merge no longer need manual approval, reducing friction in automated workflows.

5. **Alternatives considered**:
   - `git.clone`: Would require a different resource format (destination path), raising questions about security and directory creation. More complex than justified.
   - `git.checkout`: Modifies working tree state — riskier than fetch, less clear policy story.
   - `git.force_push`: Dangerous, intentionally left unimplemented.
   - `github.*`: Requires API integration, broader scope.

## What Now Works End-to-End

An agent running `git fetch origin` (or `git fetch origin feature-branch`) is now:

1. **Intercepted** by the git interceptor → `action_type = "git.fetch"`
2. **Sent to gateway** via `POST /v1/runtime/check`
3. **Policy-evaluated**: Default policy allows `git.fetch` in all environments (read-only)
4. **Decision**: `allow` — interceptor executes directly (agent-side)
5. **If escalated**: Continuation created with `action_type = "git.fetch"`, `resource = "git:<repo>[:<refspec>]"`
6. **Orchestrator picks up** continuation → calls `GitExecutor.Execute`
7. **GitExecutor runs**: `git fetch <remote> [<refspec>]` in the local repo directory

Resource format: `git:<remote>[:<refspec>]`
- `git:origin` — fetches all refs from origin
- `git:origin:refs/heads/main` — fetches just the main branch

## Failure and Degraded Behavior

| Scenario | Behavior |
|----------|----------|
| No git binary in PATH | `git: binary not found in PATH` — StateFailed |
| Repo path does not exist | `git: repository path does not exist` — StateFailed |
| Not a git repo | `git: not a git repository` — StateFailed |
| Symlink in repo path | `git: symlink traversal not allowed` — StateFailed |
| git fetch times out | `git: command timed out after Xs` — StateTimedOut |
| No remote configured | `git fetch` with no remote succeeds as no-op (exit 0) |
| Invalid resource format | `invalid git resource: git: repository is empty` — StateFailed |

## Commands Run

```bash
cd runtime/gateway
go build ./...              # passed
go vet ./...                # passed
go test ./...               # passed (all packages)
go test -race ./...        # passed (all packages)
```

## Files Changed

| File | Change |
|------|--------|
| `internal/models/action_request.go` | Added `ActionTypeGitFetch = "git.fetch"` |
| `internal/execution/store.go` | Added `git.fetch` case in `GitExecutor.Execute` switch |
| `cmd/server/main.go` | Registered `git.fetch` in executor registry; updated startup log |
| `interceptors/git/interceptor.go` | Explicit `case "fetch": return models.ActionTypeGitFetch` in `resolveGitActionType` |
| `examples/sample_policy_local.json` | Added `git.fetch` rule (allow, all environments) |
| `examples/sample_policy.json` | Added `git.fetch` rule (allow, all environments) |
| `runtime/gateway/SUPPORT_MATRIX.md` | Added `git.fetch` to supported action types, default policy, failure modes |
| `docs/architecture/runtime_support_matrix.md` | Added `git.fetch` to supported action types, default policy, failure modes |

## Tests Added/Updated

| File | Change |
|------|--------|
| `interceptors/git/interceptor_test.go` | Added `{"fetch", []string{"origin"}, models.ActionTypeGitFetch}` and `{"fetch", []string{"origin", "main"}, models.ActionTypeGitFetch}` to `TestResolveGitActionType` |
| `internal/execution/store_test.go` | Added `TestGitExecutor_Integration_Fetch` — integration test that creates a real git repo and runs `git.fetch` |

## Policy Implications

- **Default policy**: `git.fetch` is **allowed** in all environments (read-only, like `git.pull`)
- **Breaking change**: None — `git.fetch` was not previously registered; no policy referenced it
- **Backward compatible**: Existing policies that don't mention `git.fetch` will use the catch-all rule. In `local`/`dev`/`staging` environments the catch-all defers to more specific rules or allows; only `production` with a catch-all would require escalation

## Compatibility

No breaking changes. `git.fetch` was unimplemented before — adding it expands the set of working action types.

## Future Phases

Potential follow-on capabilities (not implemented here):
- `git.clone` — would need destination path in resource format; security review required
- `git.checkout` — modifies working tree; policy should require approval
- `git.fetch --tags` or `git.fetch --prune` — current resource format doesn't support flags; would need extended format
