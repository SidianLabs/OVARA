# Security release checklist

How a release that fixes security problems goes out. Use it for the
October 2026 hardening and for every security fix after it.

## Before anything is public

- [ ] Fixes are developed in a **private fork** created from a GitHub Security
      Advisory draft (repository → Security → Advisories → New draft →
      "Start a temporary private fork"), not on a public branch.
- [ ] One advisory per independent weakness, each naming the affected
      versions, the fixed version, a severity (CVSS), and what users should
      do. Advisories describe the effect, not a recipe.
- [ ] The commit messages describe the fix, not how to exploit the old code.
- [ ] Detailed review notes stay out of the repository until the release.

## Before merging

- [ ] Every Go module: `go vet ./...` and `go test -race -count=1 ./...`.
- [ ] Windows and macOS builds: `GOOS=windows go vet ./cmd/ovara`,
      `GOOS=darwin go vet ./cmd/ovara` (from `proxy/`).
- [ ] `golangci-lint` (the version in `lint.yml`) clean on changed code.
- [ ] `make fuzz` with at least the CI fuzz time, no new crashers.
- [ ] `ovara bench`: no FAIL; the results table in `docs/BENCHMARK.md` is
      updated, including known-limit numbers and prompts per benign task.
- [ ] The container suites pass in CI: `scenarios`, `ci-bot`, `upgrade`,
      `separate-user-attacks`, `boundary-redteam`, `box`, `box-strict`,
      `box-tier2`, `box-boundary`, `box-tier1-root`, `agents` (all three
      agents, cooperative, enforced and box), `agents-harness`.
- [ ] `govulncheck` clean for `proxy` and `runtime/gateway`.
- [ ] Trivy image scan clean.
- [ ] SDK suites: `sdk/python` (pytest) and `sdk/typescript` (vitest, tsc).
- [ ] `docs/GUARANTEES.md` matches the code: every new or changed promise
      has its tests named; anything weakened is under "Not guaranteed".
- [ ] `CHANGELOG.md` lists every behaviour change a user will notice, with
      breaking changes first.

## Before calling it reviewed

- [ ] An external review against [`REVIEW_SCOPE.md`](REVIEW_SCOPE.md) has
      reported, and no Critical or High finding is open.
- [ ] A real-key soak (`docs/box.md` §14, milestone 7) has run for at least
      8 hours with real model APIs and the three supported agents, with the
      host table and receipt chain checked.

## Releasing

- [ ] Tag and build the release; publish checksums (as `install.sh` expects).
- [ ] Publish the advisories at the same time as the release, and request
      CVE IDs through GitHub where they apply.
- [ ] Update `SECURITY.md` supported versions.
- [ ] Announce the upgrade steps that need action (for the October 2026
      hardening: policy rules missing `action_type`/`environment` now stop
      startup; the interception CA is replaced once; see the CHANGELOG).
