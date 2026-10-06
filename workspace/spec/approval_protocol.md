# Spec: Approval + revocation protocols (v0.9)

Two specs in one file — they share the provenance machinery.

## Part 1 — Approval protocol

Defends against T4's approval-fatigue + spoofing class. An approval is
a cryptographic object bound to one exact request — never a vibe.

### Flow

```
1. Evaluator returns escalate → DecisionRecord escalated with
   action_hash = sha256(canonical action bytes).
2. Approval record created: {approval_id, action_hash, policy_id,
   agent_summary (for operator), expiry = now + TTL,
   state = pending, requester_principal}.
3. Operator resolves via out-of-band channel (not the channel the
   agent controls — not the agent's stdout, not a webhook the agent
   can reach). Resolution = {approve|deny, operator_sig over
   approval_id + action_hash}.
4. Orchestrator resolves the queued continuation only if the
   approval's action_hash == the recorded action_hash AND the
   operator_sig verifies AND not expired AND single-use not consumed.

   State pinning is asymmetric (F-SPEC-6): content fields
   (action_hash, policy_id) are pinned at issue — the approval covers
   exactly that request. Liveness fields (token.epoch, revocation
   state) are RE-CHECKED at resolution — an approval granted
   pre-revoke cannot land post-revoke.
```

### Anti-fatigue design

- **Single-use**: an approval can satisfy exactly one action. Reusing
  an approval_id for a different request fails the hash check.
- **Bounded expiry**: approvals TTL out; a flooded approval queue
  ages into "expired-deny" rather than "rubber-stamped".
- **No bulk approve**: API allows resolving one id at a time
  (bulk-approve is itself a fatigue surface).
- **No self-approval**: the requester principal can never resolve
  its own escalation — operator role only.
- **Distinct channels**: approval resolution travels a separate
  authenticated channel the agent can't synthesize (enrollment-
  time credentials, not runtime tokens).

### What v1 had vs v2 keeps

v1 fixed SEC-0014 (approvals bind RequestHash = action digest) and
added provenance gate at claim. Keep: the binding, the gate, the
single-resolution semantics. Change: resolution itself is signed —
v1's approve call was bearer-token-authed HTTP; a stolen operator
token could approve anything. v2's operator_sig adds a second factor
(the key needn't be the same credential as the session token).

## Part 2 — Revocation protocol

### Mechanism

- `epoch` is a monotonic counter in the trust store; tokens carry
  `epoch` at issue; decisions check `action.min_epoch ≤ current` AND
  `token.epoch = current` (stale-epoch tokens deny —
  `revocation_epoch_stale` already exists as a reason code, VERIFIED
  in v1 corpus min-epoch-huge row).
- Revocation = epoch bump. Two delivery paths:
  - **Push**: epoch update broadcast to live executors/sandboxes;
    executor refuses new actions until it acks the new epoch —
    revoked authority stops mid-flight, not just at next check.
  - **Pull**: executors poll checkpoints; epoch is part of each
    checkpoint (so a checkpoint is also a revocation witness).
- Latency bound: `max(executor poll interval, push ack timeout)`
  — this number is **measured** and published, not asserted.

### In-flight semantics

On revoke:
- **Pending decisions**: denied at check time (epoch stale).
- **Held escalations**: approval resolves still check epoch — an
  approval granted pre-revoke cannot land post-revoke.
- **Executing sandboxes**: risk-tiered — tier R0 (low risk) drains
  to completion; tier R1+ receives SIGKILL-class termination. The
  choice is per-policy, recorded in DECISIONS.md.

### Kill switch

Operator kill = epoch bump + executor drain + session teardown.
The kill record is itself a signed checkpoint — the kill is
auditable, not silent.

## Failure semantics (P2)

- Approval service down → escalated actions remain pending until
  TTL expire → deny. Never auto-approve.
- Revocation push unreachable → executor falls back to checkpoint
  pull at tighter interval; never silently extends validity.
- Revocation record lost → next checkpoint carries the new epoch;
  divergence between in-memory epoch and checkpoint epoch is a
  self-test alarm condition.
