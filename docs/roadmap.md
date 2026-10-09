# Roadmap: from here to production (1.0)

Written 2026-10-09. `docs/box.md` is the design; this file is the order of
work, what each stage must prove, and who it waits on. A stage is done when
its exit test passes in CI on GitHub, not when the code exists.

## Where we are

Built and green on GitHub (PR #39, merged): the proxy and gateway, real
agents behind Ovara (opencode, Codex CLI, Anthropic's agent CLI), restart
fixes, policy v2, `ovara box` tier 1 (user + network namespace) and tier 2
(container), the command gate, strict installs. Red teams pass in netns,
docker and tier 2 modes.

On branch `box/ci-profile`, green locally, CI pending: the `ci` profile
(nothing waits for a person), Aider tested in every mode, the box image's
pip-in-virtualenv bug fixed.

What we can say today: "a sandbox for coding agents (beta): network, files,
commands and installs gated; Linux enforced; macOS and Windows cooperative
only".

## Stage 1. Land what is built — days

| Work | Who | Exit test |
|---|---|---|
| Merge `box/ci-profile` (ci profile, Aider, pip fix) | PR + owner merge | all checks green |
| Release **v0.9.1**: release notes lead with `ovara run -repair-registry` (deployments made by v0.9.0 cannot restart without it) | owner pushes the tag; the release workflow builds and signs | `install.sh` installs it; the upgrade job passes on the tag |
| Fix the 54 commits on `main` with the misspelled email (optional) | owner, history rewrite of `main` | `git log --format=%ae main` shows one address |

## Stage 2. Beta release v0.10 — 1–2 weeks

Make the box installable by someone who has never seen the repository.

| Work | Who | Exit test |
|---|---|---|
| Publish the box image to `ghcr.io/sidianlabs/ovara-box` on each release, signed, with an SBOM; `ovara box -tier 2` defaults to it, pinned by digest | build here; owner enables package publishing | a clean VM: `install.sh`, then `sudo ovara box -tier 2 . -- bash` works with no `docker build` |
| Ready-made agent images (`ovara-box-claude`, `-codex`, `-opencode`, `-aider`) built FROM the box image | here | the agents matrix runs from the published images |
| `ovara box --help` and a one-page quickstart (`docs/box-quickstart.md`): tiers, profiles, approving, what comes back | here | a reader runs a first box from the page alone (checked in a fresh container) |
| Approval fatigue: "approve and allow this for the rest of the run" (`docs/box.md` §15.2) | here | test: a second identical request does not pause; the summary lists run-scoped allowances |
| Receipt retention and size warning in `ovara doctor` (§15.4) | here | test: a 100k-receipt deployment warns and compacts |

Exit: v0.10 tagged; README's first paragraph says "beta" and "Linux".

## Stage 3. Hardening — 2–4 weeks

| Work | Who | Exit test |
|---|---|---|
| **Milestone 7, real-key soak**: a nightly job runs the three agents against the real model APIs for hours, unattended, and reports the host table and the receipt chain | job built here; **owner adds API keys as repository secrets** (spend cap advised) | 7 consecutive green nights |
| Rootless tier 2 (no root on the host: user namespaces, the socket directory owned by the invoking user's mapping) | here | box tests pass as a non-root user in the docker group |
| Close the command gate's argv gap (`docs/box.md` §8): stop the whole tree, or read argv by `process_vm_readv` while every sibling is stopped | here | a test where a sibling rewrites argv after the exec stop cannot change what runs |
| A tighter seccomp profile for tier 2 than Docker's default | here | box and agent suites still pass; the red team adds the removed syscalls |
| Fuzzing of the proxy's request parsing and the lockfile and download parsers, in CI | here | fuzz jobs run nightly without findings |
| Performance: proxy latency and the gate's overhead measured per release (`docs/BENCHMARKS.md`) | here | numbers published; a regression fails the job |

## Stage 4. macOS and Windows (milestone 6) — 2–4 weeks

The box is Linux kernel machinery, so on macOS and Windows it runs inside a
Linux VM (Lima / WSL2) with Ovara on the host side.

| Work | Who | Exit test |
|---|---|---|
| `ovara box` on macOS drives a Lima VM; on Windows, WSL2 | here | the agents matrix passes in the VM with the same numbers as Linux |
| CI that can run a nested VM | **owner: self-hosted runners** (a Mac and a Windows machine) or larger runners with nested virtualization | the matrix runs on every PR |

Until this stage ships, the docs say in their first paragraph that macOS
and Windows are cooperative only.

## Stage 5. External review (milestone 8) — external

| Work | Who | Exit test |
|---|---|---|
| Independent security review of tiers 1 and 2, the proxy, the gateway's decision and approval paths, and the receipt chain | **owner engages a reviewer**; here: a review pack (threat model, `docs/box.md`, how to run every red team) | the report's findings fixed or documented |
| Publish the report and link it from the README | owner | — |

## Stage 6. Production 1.0

All of these, each checkable:

- Stages 1–5 done; CI green on `main`, including 7 nights of soak.
- Review findings closed or documented with their risk.
- Releases signed, with provenance (exists) and an SBOM for binaries and images.
- `SECURITY.md` with a working disclosure address and response times.
- Upgrade guarantee: every 1.x reads every earlier 1.x deployment; the
  upgrade job tests the previous minor release.
- Support matrix in the README: which tiers on which platforms, tested how.
- No telemetry; every network request Ovara itself makes is listed.

Then the README may say "a sandbox for coding agents", with the review and
the test matrix linked, never "unescapable" or "injection-proof"
(`docs/box.md` §16).

## After 1.0

- Tier 3: the box inside a microVM (Firecracker), for agents expected to be
  hostile; it stops kernel exploits from inside.
- Team mode: one Ovara for several people, approvals from a shared page,
  policy in the repository.

## What waits on the owner

| Needed | Unblocks |
|---|---|
| Merge PRs; push release tags | Stages 1 and 2 |
| Enable package publishing to ghcr.io | the published box image |
| Model API keys as repository secrets | the real-key soak (milestone 7) |
| A Mac and a Windows machine as self-hosted runners (or nested-virtualization runners) | macOS and Windows (milestone 6) |
| An external reviewer | the review (milestone 8) and 1.0 |
