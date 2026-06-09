# Taste (Continuously Learned by [CommandCode][cmd])

[cmd]: https://commandcode.ai/

# Agent Workflow
- Provide dense, context-rich, structured agent prompts with full phase plan, progress, constraints, key decisions, next steps, and critical context sections. Confidence: 0.85
- Prefer fewer, larger agent runs that complete 5-15 phases in a single pass rather than many small incremental steps. Confidence: 0.85
- Every agent prompt must include: Goal, Constraints & Preferences, Progress (Done/In Progress/Blocked), Key Decisions, Next Steps, Critical Context, and Relevant Files sections. Confidence: 0.85

# Development
- Use Go for runtime/gateway; single-binary deployment, fast compile, aligns with architecture doc. Confidence: 0.90
- Use phase-based development with feature branches named `phase-<n>-<short-scope>` and conventional commits (`feat(...)`, `fix(...)`, `docs(...)`, `test(...)`, `chore(...)`). Confidence: 0.85
- Every phase must conclude with `go build ./...`, `go vet ./...`, `go test ./...`, `go test -race ./...` all passing. Confidence: 0.85
- Every phase produces a checkpoint doc at `docs/build/phase_<n>_<name>_checkpoint.md`. Confidence: 0.80
- Local-first architecture; no distributed executors, plugin architecture, or cloud control plane. Confidence: 0.85

# Communication
- Always respond in English. Confidence: 0.90
