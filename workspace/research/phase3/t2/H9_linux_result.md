# H9 — Linux result: Landlock vs the minimized T2-F03 symlink attack

**Verdict: H9 SUPPORTED** — under the tested Linux configuration,
Landlock prevented the minimized T2-F03 filesystem action that was
permitted by application-level core enforcement.

Scoped claim (no stronger): *Landlock prevented the tested
symlink-based filesystem escape under the tested Linux configuration.*
This experiment alone does not establish general filesystem security,
complete symlink protection, complete containment, or control
invariance.

## Environment

| field | value |
|---|---|
| OS | Ubuntu 22.04.5 LTS (Jammy) |
| Kernel | 6.8.0-1061-aws |
| Architecture | x86_64 |
| Machine | Devin VM (`devin-box`, AWS kernel) |
| Landlock | LSM active (`landlock` in `/sys/kernel/security/lsm`; `CONFIG_SECURITY_LANDLOCK=y`) |
| Landlock ABI | 4 (`landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION) = 4`) |
| Go | go1.25.6 linux/amd64 |
| Base commit | `75c092b` (`feat/ovara-redesign`) |
| Tree state | clean + one apparatus-defect repair (see A1 below) |
| Test binary | `go test -c ./tests/phase3` (`phase3.test`) |

## Exact test command

```
cd runtime/gateway
OVARA_COMMIT=$(git rev-parse --short HEAD) \
  go test ./tests/phase3/ -run TestContainmentComparison -v
```

The committed harness (`tests/phase3/containment_test.go`) re-execs the
test binary per level so the irreversible ruleset applies only to a
throwaway child. Same minimized attack both cells: probe string
`$ROOT/allowed/link/leak.txt` where `allowed/link → $ROOT/canary`
(absolute symlink). Real filesystem, no mocks.

## Results (committed harness run)

| cell | write_allowed | child exit | stderr |
|---|---|---|---|
| core | **true** | 0 | — |
| landlock | **false** | 2 | `open …/allowed/link/leak.txt: permission denied` |

## Independent ground truth (parent-controlled fixture)

The harness's `t.TempDir()` is deleted at test end, so each cell was
additionally replayed against a persistent fixture
(`/tmp/h9fixture/{allowed,canary}`, `allowed/link → /tmp/h9fixture/canary`)
via the binary's own child path (`OVARA_CONTAIN_CHILD=<level>`), and the
filesystem state was inspected outside the process.

Topology check: `stat -c %i canary/leak.txt` = `stat -Lc %i allowed/link/leak.txt`
= inode **3098622** — different string, same object.

### level=core

- authorization_result: permitted (string beneath `allowed/`)
- execution_result: `openat("…/allowed/link/leak.txt", O_WRONLY|O_CREAT|O_TRUNC) = 6`, exit 0
- filesystem_ground_truth: `canary/leak.txt` content `canary` → `x`;
  sha256 `e100fbce…` → `2d711642…`; inode unchanged
- detection_result: self-report exit 0, corroborated by strace (successful openat)
- **write_allowed = true** — consistent with the macOS core cell

### level=landlock

- authorization_result: permitted (string beneath `allowed/` — attack unchanged)
- execution_result: `openat("…/allowed/link/leak.txt", O_WRONLY|O_CREAT|O_TRUNC) = -1 EACCES`, exit 2
- filesystem_ground_truth: `canary/leak.txt` remains `canary`
  (sha256 `e100fbce…` unchanged), inode 3098622
- detection_result: denial surfaced as stderr `write denied` + strace EACCES;
  the harness has no kernel-audit/telemetry layer for the denied syscall

## Landlock verification (per protocol §8)

strace of the landlock child (abridged):

```
landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION) = 4
landlock_create_ruleset({handled_access_fs=<all 13 FS rights>}, 8, 0) = 6
landlock_add_rule(6, LANDLOCK_RULE_PATH_BENEATH,
                  {allowed_access=<all 13 FS rights>, parent_fd=7}, 0) = 0
prctl(PR_SET_NO_NEW_PRIVS, 1) = 0
landlock_restrict_self(6, 0) = 0
openat(AT_FDCWD, "…/allowed/link/leak.txt", O_WRONLY|O_CREAT|O_TRUNC) = -1 EACCES
```

1. Landlock available: ABI 4, LSM in `lsm` list. ✔
2. Ruleset created (fd 6). ✔
3. Intended hierarchy restricted: one `PATH_BENEATH` rule granting all
   13 fs rights on `allowed/`; everything else denied by omission. ✔
4. `WRITE_FILE` and friends are in the handled set. ✔
5. Process restricted **before** the write (`restrict_self` = 0
   precedes the openat). ✔
6. The write crosses the boundary: the string is beneath `allowed/`,
   the resolved object (`canary/leak.txt`) is not. ✔
7. Ground truth observed post-hoc: canary unmodified. ✔

## Apparatus defect found and repaired (A1 — required disclosure)

As committed at `75c092b`, `contain.probeABI()` issued the
`LANDLOCK_CREATE_RULESET_VERSION` query with a non-NULL `attr` and
`size=8`. The API contract requires `attr=NULL, size=0` for the version
query; kernel 6.8.0-1061-aws enforces it and returns `EINVAL`. Result:
`Available()` returned false and the landlock cell was `SKIPPED` even
though Landlock is present — on this kernel the committed harness could
not measure the landlock cell at all.

Evidence:

- raw `syscall(444, NULL, 0, VERSION)` → 4 (ABI present)
- harness-identical `syscall(444, &attr, 8, VERSION)` → `EINVAL`
- `create_ruleset(flags=0)` and `restrict_self` both succeed → only the
  probe was broken; `ApplyFS` logic was otherwise functional

**Classification:** apparatus defect (not a security finding, not
environmental — the kernel implements the documented contract).

**Repair (minimal, non-redesign):** `probeABI()` now calls
`create_ruleset(NULL, 0, VERSION)`. One syscall signature corrected;
attack, targets, policy, canary, authorization config, and the
irreversible re-exec design are unchanged. The measurement above is on
`75c092b` + this probe repair. Without it the cell could not be
measured honestly; a denied-by-ErrUnsupported result would have been a
fake measurement.

## Interpretation

- Matrix row now reads: `T2-F03 minimized symlink | n/a | n/a |
  write_allowed=true | write_allowed=false`.
- The causal variable (enforcement level) is the only change between
  cells: identical attack, policy, canary, and binary.
- The denial is inode-level: the kernel resolved the symlink and judged
  the *target object*, which lies outside every granted hierarchy.
  This is exactly the string-vs-object gap T2-F03 identified.
- Case A of the protocol applies.

## Limitations

- One kernel/distro/ABI (Ubuntu 6.8, ABI 4), one filesystem (ext4/tmpfs
  on `/tmp`), one operation (`openat O_WRONLY|O_TRUNC` through a symlink).
- The probe repair means the measured code differs from `75c092b` by
  exactly the availability check; `ApplyFS` enforcement logic is as
  committed.
- Single-attack falsification probe — does not speak to hardlinks,
  rename races, mount tricks, ioctl, or other resolution features.
- Harness detection is exit-code + stderr; no audit-receipt coverage
  for the denied syscall was measured.
- Landlock gates the resolved object's hierarchy, not path-string
  traversal: an attacker that can place the *canary* beneath an allowed
  root (e.g. bind mount) is out of scope here.

## Reproduce

```
git checkout feat/ovara-redesign
cd runtime/gateway && go test ./tests/phase3/ -run TestContainmentComparison -v

# independent ground truth (persistent fixture):
F=/tmp/h9fixture; rm -rf $F; mkdir -p $F/allowed $F/canary
printf canary > $F/canary/leak.txt; ln -s $F/canary $F/allowed/link
go test -c -o /tmp/phase3.test ./tests/phase3/
OVARA_CONTAIN_CHILD=landlock OVARA_CONTAIN_ALLOWED=$F/allowed \
  OVARA_CONTAIN_PROBE=$F/allowed/link/leak.txt OVARA_CONTAIN_ROOT=$F \
  strace -f -e trace=landlock_create_ruleset,landlock_add_rule,landlock_restrict_self,openat \
  /tmp/phase3.test -test.run=TestContainmentComparison   # expect exit 2, EACCES
sha256sum $F/canary/leak.txt   # must equal the pre-run value
# repeat with OVARA_CONTAIN_CHILD=core → expect exit 0 and content "x"
```
