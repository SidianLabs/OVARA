# Development
- Use Go for runtime/gateway; single-binary deployment, fast compile, aligns with architecture doc. Confidence: 0.90
- Use phase-based development with feature branches named `phase-<n>-<short-scope>` and conventional commits (`feat(...)`, `fix(...)`, `docs(...)`, `test(...)`, `chore(...)`). Confidence: 0.85
- Every phase must conclude with `go build ./...`, `go vet ./...`, `go test ./...`, `go test -race ./...` all passing. Confidence: 0.85
- Every phase produces a checkpoint doc at `docs/build/phase_<n>_<name>_checkpoint.md`. Confidence: 0.80
- Local-first architecture; no distributed executors, plugin architecture, or cloud control plane. Confidence: 0.85
- Cloud control plane uses TypeScript with Fastify and Drizzle ORM for PostgreSQL; split control-plane/data-plane per architecture doc. Confidence: 0.70
