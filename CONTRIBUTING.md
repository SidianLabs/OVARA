# Contributing to Ovara

Thank you for your interest in contributing to Ovara. Ovara is a runtime trust
infrastructure for autonomous systems, and contributions from the community
help it stay reliable, secure, and useful for everyone.

## Code of Conduct

This project and everyone participating in it is governed by the
[Ovara Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are
expected to uphold this code. Please report unacceptable behavior to
[security@ovara.dev](mailto:security@ovara.dev).

## How to Contribute

### Reporting Bugs

- **Search existing issues** before opening a new one to avoid duplicates.
- Use the **bug report** issue template and include:
  - Ovara version (`ovara-gateway --version` or `git describe`)
  - Operating system and architecture
  - Reproduction steps with the smallest possible policy + request
  - Expected vs. actual behavior, with logs

### Suggesting Enhancements

- Open an issue with the **feature request** template.
- Describe the problem first, then the proposed solution.
- For large changes (new executor, new action surface, new cloud feature),
  discuss in an issue before writing code.

### Security Issues

**Do not open a public issue for security vulnerabilities.** Email
[security@ovara.dev](mailto:security@ovara.dev) with details and we will
respond within 72 hours. See [SECURITY.md](SECURITY.md) for our full
vulnerability disclosure policy.

### Pull Requests

1. **Fork** the repository and create a feature branch.
2. **Write tests first** (TDD). All new code must be test-driven — see
   the [TDD workflow](#test-driven-development) below.
3. **Keep PRs focused.** One logical change per PR. Larger refactors
   should be split into reviewable units.
4. **Run the full validation** before requesting review:
   ```bash
   make check    # runs vet, test, build, test-ts, build-ts
   ```
5. **Update documentation** for any user-facing change. Every endpoint,
   CLI flag, config field, or policy schema change should update the
   relevant doc under `docs/`.
6. **Reference the issue** in the PR description (`Closes #123`).
7. **Sign your commits** (we follow the DCO; see below).

## Test-Driven Development

Ovara follows strict TDD for all production code. The workflow is:

1. **Red** — write a failing test that describes the desired behavior.
2. **Verify it fails** for the right reason (feature missing, not typo).
3. **Green** — write the minimum code needed to make the test pass.
4. **Verify all tests pass**, not just the new one.
5. **Refactor** while keeping tests green.

If you write code first, delete it and start over. Tests written after
code pass immediately and prove nothing.

## Style Guides

### Go

- Standard `gofmt` / `go vet` / `goimports` compliance.
- `golangci-lint run` must pass.
- Public symbols have godoc comments.
- Keep functions small; extract helpers early.
- Use table-driven tests for similar cases.
- File names are lowercase, snake_case.
- Use context for cancellation; never `context.Background()` in libraries.

### TypeScript

- `strict: true` in `tsconfig.json` (no `any` without justification).
- Prettier + ESLint compliant.
- Prefer `interface` for object types, `type` for unions/aliases.
- File names match primary export (`client.ts` exports `OvaraClient`).
- Vitest for tests; mock at the boundary, not the implementation.

### Python

- Type hints on all public functions.
- `pytest` with `asyncio_mode = "strict"`.
- File names match module names (`verify.py` exports verification functions).
- `cryptography` library for ed25519 (not `nacl` — we use libsodium-compatible
  signatures in the Go side and need to match).

### Markdown

- One sentence per line (easier diff review).
- Use reference-style links for repeated URLs.
- Code blocks must be runnable or clearly marked as illustrative.

## Project Structure

```
ovara/
├── apps/                # End-user applications (admin dashboard)
├── cloud/               # Hosted control plane
├── docs/                # User-facing documentation
├── enterprise/          # Enterprise add-ons (SSO, compliance)
├── examples/            # Sample configs and demo scripts
├── identity/            # Machine identity primitives (standalone Go module)
├── infrastructure/      # Terraform, docker-compose
├── integrations/        # Framework integrations (CrewAI, LangChain, etc.)
├── observability/       # Grafana/Prometheus dashboards
├── packages/            # Shared cross-language types
├── policy/              # Policy adapters and compiler
├── research/            # Research notes
├── runtime/gateway/     # The main Go gateway
├── sdk/                 # Client SDKs (TypeScript, Python)
├── security/            # Security profiles (AppArmor, eBPF, Seccomp)
├── services/            # Microservices (approval, alerting, observability, etc.)
├── telemetry/           # Telemetry collector and schema
├── tools/               # Operator tools (CLI, migration, benchmarks)
└── trust/               # Federated trust graph and CLI
```

## Branch and Commit Conventions

- Branch names follow `phase-N-short-description` or `topic/short-description`.
- Commit messages use Conventional Commits: `feat:`, `fix:`, `docs:`,
  `refactor:`, `test:`, `chore:`.
- Reference the issue number: `feat(policy): add OPA adapter (#123)`.
- Sign your commits (`git commit -s`) to certify the DCO.

## Review Process

1. **CI must pass** (build, vet, test, race, typecheck).
2. **At least one maintainer review** for non-trivial changes.
3. **Architecture review** required for changes to:
   - `runtime/gateway/internal/evaluator/` (the decision pipeline)
   - `runtime/gateway/internal/trust/` (trust models)
   - `identity/` (cryptographic primitives)
   - `trust/` (federated trust graph)
4. **Security review** required for changes to:
   - `security/`
   - `runtime/gateway/internal/auth/`
   - `runtime/gateway/internal/identity/`
   - Any cryptographic code paths.

## Release Process

Ovara uses [Semantic Versioning](https://semver.org). Releases are tagged
on the `main` branch after the phase exit criteria are met. See
`docs/build/` for the checkpoint pattern used during development.

## License

By contributing, you agree that your contributions will be licensed under
the Apache License 2.0. See [LICENSE](LICENSE) for the full text.
