# Guarantee degradation map — what OVARA's claims actually cover

Each rung names the guarantee and where it stops. This is the honest
capability statement; every boundary below has a measured cell behind
it or is explicitly marked unmeasured.

## Rung ladder

| rung | guarantee | measured evidence | stops at |
|---|---|---|---|
| C-core decision engine | signed-request, canonical-form-bound, write-ahead audited decisions over the 26-type vocabulary | 79/79 open corpus, 103/103 pre-carve, 8/8 red-team classes, 140M fuzzer execs | resources that change identity between authorization and execution (T2-F03: symlink→inode) |
| + canonicalization | wire action must equal its canonicalization — signature/eval/audit bind the same bytes | traversal/NUL/IP-spelling/wildcard regressions | same as above |
| + Landlock fs | the kernel enforces the resolved object, not the string | **H9 SUPPORTED** (Case A): core allowed, landlock EACCES'd the same write — Ubuntu 6.8, ABI 4 | one kernel/ABI/op; see scope limits |
| + netns+proxy | egress interception at namespace level | v1 proxy path only (proxy folded onto core) | not yet measured against adaptive attacker |
| + full sandbox | gVisor/Firecracker lanes | unmeasured — needs containers/Linux | — |

## Explicit non-guarantees (do not read past this)

- **In-scope writes can still reach out-of-scope objects via fs
  indirection** on C-core alone (symlink; presumably hardlink — same
  class). This is the T2-F03 boundary, under test on the Linux lane.
- **No guarantee when the host kernel is adversarial** — the runtime
  trusts the OS beneath it; kernel compromise is out of TCB scope.
- **No guarantee on side channels** (timing, resource exhaustion as a
  covert channel) — detection only, not prevention.
- **Prompt-only parity**: A condition bypassed on attempt 1–2 in every
  measured cell — prompt-level control is not a boundary.
- **v1**: heterogeneous — net canonicalized, fs not; persistent-mode
  shield alters reachability mid-campaign (a v1 property, not a defense
  claim).
