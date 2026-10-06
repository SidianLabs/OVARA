# Enforcement Completeness — controls declared vs realized

Per the Phase-3 review: a mechanism is real only when it reaches the
actual security decision. Chain: Declared → Parsed → Verified →
Enforced → Ground-truth tested. Every "✗/partial" is either a declared
residual or an experiment gap — the class P3A-05 belonged to
(declared field, never enforced) and must not recur silently.

| Control | Declared | Verified | Enforced | Ground-truth tested |
|---|:-:|:-:|:-:|---|
| request signature (edsig_v2) | ✓ | ✓ | ✓ | ✓ corpus sig modes |
| capability blocks (scope/caveats/subject) | ✓ | ✓ | ✓ | ✓ scope_boundary, authority |
| delegation custody chain | ✓ | ✓ | ✓ | ✓ authority, scope_boundary |
| approval redemption (hash-bound single-use) | ✓ | ✓ | ✓ | ✓ sc-am-001..006 |
| replay — in-memory | ✓ | ✓ | ✓ | ✓ replay scenarios |
| replay — durable ReplayStore | ✓ | ✓ | ✓ | partial: unit-tested restart, not corpus-driven |
| freshness window | ✓ | ✓ | ✓ | ✓ 59s/61s boundary |
| epoch revocation (min_epoch) | ✓ | ✓ | ✓ | partial: stale_authorization; no live revocation feed |
| env_in caveat | ✓ | ✓ | ✓ (since RT-R2) | partial: thin corpus coverage |
| require_capability policy effect | ✓ | ✓ | ✓ | ✓ rc-* scenarios |
| actor key registry | ✓ | ✓ | ✓ | ✓ unknown-actor denies |
| coarse agent-visible reason classes | ✓ | ✓ | ✓ | pending: T3 probes info-leakage |
| audit write-ahead + Merkle anchors | ✓ | ✓ | ✓ | partial: core tamper tests; no live off-host anchor |
| selftest refuse-boot | ✓ | ✓ | ✓ | ✓ selftest suite |
| taint_max caveat | reserved | — | — | fail-closed at verify (rejects tokens) |
| canonicalization (net/fs/shell) | ✓ | ✓ | ✓ | ✓ egress/filesystem/shell classes |
| egress containment (netns/proxy) | ✓ spec | n/a | partial: proxy folded on engine | ✗ needs Linux lane |
| fs/exec mediation (Landlock/seccomp) | ✓ spec | ✗ | ✗ | ✗ needs Linux lane |
| monitoring layers (D-system) | spec only | ✗ | ✗ | ✗ T2+ |

Rule going forward: adding a declared control requires simultaneously
marking its position in this table; "Enforced" means a decision path
consumes it; "Ground-truth tested" means a corpus/experiment row or a
unit test exercises it end-to-end.
