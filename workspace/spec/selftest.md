# Spec: Self-test and fail-closed verification (v0.9)

P10's active leg: misconfiguration must be *detected*, not assumed
absent. Self-test runs at boot, periodically, and on config change.
It is inside the TCB (a compromised self-test lies about containment).

## 1. What self-test must prove each run

| Check | Method | Failure means |
|---|---|---|
| Egress deny | Attempt real TCP connect to a canary IP outside allowlist from inside sandbox; MUST fail | containment broken — refuse to start |
| Mediation presence | Spawn a test action that would bypass a cooperative interceptor; assert it produced a DecisionRecord | seam gap — refuse |
| Audit write-ahead | Inject fsync-failure on a test record; assert executor refuses action | audit degraded — refuse |
| Checkpoint push | Verify last checkpoint was acked by the off-host destination within bound | anchoring degraded — alarm (config: refuse vs degrade is a tier decision) |
| Replay protection | Re-submit a just-seen signed nonce → must deny `action_not_allowed` | replay broken — refuse |
| Revocation epoch | Assert current_epoch ≥ last checkpoint's epoch (no silent regression) | epoch rollback — refuse |
| Policy load | Re-evaluate the known corpus probes; decisions must match expected vector | policy-drift — refuse |
| Key custody | Signing key readable only by runtime UID, never inside sandbox mount namespace | key exposure — refuse |

## 2. Boot vs periodic vs on-change

- **Boot**: all checks; any refuse → gateway does not open its port.
  Boot gate result is itself a signed record (first chain entry).
- **Periodic**: cheap subset (egress canary, epoch, checkpoint ack,
  audit chain tip verify) on a configurable interval; full suite on
  slower interval. Failures → alarm + tiered posture (drain /
  refuse-new / continue-with-flag per config).
- **On-change**: policy reload, config reload, executor spawn →
  re-run relevant subset before the change takes effect.

## 3. Negative tests are the point

Self-test's value = tests that **must fail**:
- the canary connect must fail
- the replayed nonce must deny
- the tampered record must flag

A self-test that can only pass is theater. Every check has an
expected-failure assertion.

## 4. Tamper-evidence of self-test itself

- Self-test code is part of the runtime binary (P12: agent can't
  modify it; binary integrity measured at boot).
- Self-test results are audit records — a skipped run leaves a gap
  in the chain visible to the verifier.
- **Honest gap**: self-test running inside the same process as the
  runtime can't detect a compromised runtime binary post-boot.
  Mitigation: periodic binary measurement + external attestation
  point — flagged as residual, not claimed.

## 5. Reporting

`ovara doctor` becomes the self-test surface: reports each check's
last result, last-run timestamp, and whether any check has ever
failed since boot. A `doctor` output that says "unknown" is itself
a finding — no silent gaps in health reporting.
