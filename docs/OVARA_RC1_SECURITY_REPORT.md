# OVARA 2.0 — RC1 Security Report

Release-candidate verification report for the security freeze. Every
claim below is tied to an executable check or a live clean-room run;
nothing is asserted from reading code alone.

## 1. Exact tree under review

| Field | Value |
|---|---|
| Base commit | `7fc1b685463efc7828a34c5a1ff697c2a4040aa2` (`7fc1b68`) |
| Branch | `security-freeze/rc1` |
| Working-tree fingerprint | `git write-tree` = `17649ac6fc36a25a0a2ec297f2e4ebeef8008bb5` — **post-final-review state** (full tree excluding this report file — reproducible via `git add -A && git reset docs/OVARA_RC1_SECURITY_REPORT.md && git write-tree`) |
| Changed files | 95 paths vs HEAD (~53 modified, ~10 pycache deletions, ~30 untracked) |
| Commit status | **No freeze commit exists** — no git identity is configured on this machine and git config must not be modified. The branch exists; the tree fingerprint above pins the exact reviewed content. |
| Toolchain | go1.25.6 linux/arm64, python3.12 + cryptography |
| Clean-room | `/tmp/rc1-e2e` (fresh keys, tokens, CA, config, state — nothing reused) |
| Harness | `tests/e2e/rc1_harness.py` (repeatable, exits non-zero on any failure) |

## 2. Files changed since the P0.5 baseline (security-relevant)

New (P1/P1.1):
`identity/canon.go`, `identity/scope.go`, `identity/canon_vectors_test.go`,
`evaluator/delegation_capability_test.go`, `sdk/python/.../canon.py`,
`sdk/python/tests/test_canon.py`, `auth/principal.go`,
`proxy/internal/gateway/client.go` (RC1 fix)

Modified:
`identity/validator.go` (canonical sigs, scope grammar, replay order),
`identity/delegation_redteam_test.go`, `evaluator/evaluator.go`
(capability enforcement, dedicated replay map), `models/*.go`,
`handlers/runtime.go`, `handlers/approval.go`, `handlers/continuations.go`,
`auth/middleware.go` (agent/operator roles, allowlist), `policy/store.go`
(RC1 canonicalizer fix), `policy/canonical_test.go` (regressions),
`pkg/server/server.go` (wiring), docs (`SECURITY.md`,
`OVARA_2_THREAT_MODEL.md`, `OVARA_2_SECURITY_INVARIANTS.md`,
`OVARA_2_P1_IDENTITY_AUDIT.md`, this report)

## 3. Security invariants — RC1 statements

These statements are the frozen RC1 guarantees:

- **IDENTITY**: authenticated identity is derived from the credential
  and cannot be supplied arbitrarily by the caller.
- **DELEGATION**: delegation is a bounded capability, not a policy
  bypass.
- **POLICY**: delegation cannot elevate a request beyond policy.
- **LEASE**: delegation cannot bypass lease requirements.
- **APPROVAL**: approval cannot be self-created or substituted by an
  untrusted caller.
- **PROXY**: credential injection happens at the trusted proxy
  boundary; credentials are not supplied by the agent.
- **NETWORK**: the agent cannot simply bypass the intended proxy path
  under the tested containment configuration.
- **RECEIPTS**: receipts provide tamper-evident integrity within the
  implemented trust boundary; they are NOT claimed to be externally
  immutable evidence.
- **EXECUTION**: denied/escalated requests cannot execute through the
  tested execution path unless the required approval flow authorizes
  execution.

| # | Invariant | Status | Evidence |
|---|-----------|--------|----------|
| I1 | Mandatory egress | LIVE VERIFIED (boundary tests, manual) | `tests/boundary/*` |
| I2 | Credential custody | TESTED | RC1 e2e: injected canary echoed by upstream → `[REDACTED]` at the agent |
| I3 | Complete evidence | IMPLEMENTED (denies/unauth/SSRF all receipted live) | proxy receipts.jsonl |
| I4 | Denied cannot execute | TESTED | e2e: unapproved shell → marker absent; atomic resolve |
| I5 | Approvals single-use & bound | TESTED | e2e: resume replay → 409; fabricated decision → 404 |
| I6 | Policy agent-immutable | TESTED | EvalSymlinks confinement |
| I7 | Evidence agent-immutable | TESTED | host-side chain + tamper detect → `valid=false` |
| I8 | Bypass attempts observable | PARTIAL | integrity monitor not built (P0.5 scope); authz violations emit `security_violation` events (observed live) |
| I9 | Honest coverage | enforced by this report's claim discipline | — |
| I10 | Fail closed | TESTED | e2e: no token → 401, malformed decision → deny, proxy unreachable → 502 deny |

## 4. Attack coverage (RC1 e2e harness — 46/46 live cases)

### Identity
no token → 401 · forged token → 401 · foreign `subject_id` → 400
`identity_mismatch` + security_violation event · valid credential →
policy decision · operator token on check → 200 · agent token on
operator route → 403

### Delegation (capability)
valid `A→B→C` → allow · POST vs GET capability → deny · resource
outside scope → deny · forged terminal signature → deny · untrusted
intermediate → deny · terminal ≠ principal → deny · mutated signed
nonce → deny · replay in window → deny

### Capability lease
valid lease in-scope → allow · wrong subject → deny · capability
mismatch → deny · wrong audience → deny · expired → deny · scope
mismatch → deny. **Semantic note:** lease audience must equal the
gateway identity exactly (stricter than delegation hops, where empty
audience is unscoped).

### Policy
allow rule → allow · explicit deny rule → deny · catch-all → escalate
(never lifted by valid credentials)

### Approval
shell → escalate → owner creates (201) → fabricated decision_id → 404 ·
agent-token approve → 403 · operator approve → 200 · auto-executed
(marker file on host) · resume-after-execution → 409 · second resume →
409 · foreign read → 401/404

### Proxy (real transit — live internet)
unauthenticated → 407 · CONNECT non-443 → denied+receipted · SSRF to
link-local metadata → 403 · SSRF to gateway loopback → 403 · plain-HTTP
transit → 200 · **MITM HTTPS transit → 200** · policy deny → 403 ·
injected credential echoed by upstream → **`[REDACTED]`** (agent never
sees the secret)

### Execution
unapproved escalated action → does not execute (marker absent)

### Receipts
proxy chain non-empty · `ovara-proxy -verify` → `valid=true` ·
byte-tampered receipt → `valid=false, fail_at=N` · gateway receipt
store queryable → 200

## 5. Defects found during RC1 verification (reproduced → fixed → retested)

| # | Severity | Defect | Fix | Status |
|---|----------|--------|-----|--------|
| R1 | HIGH | `%2e%2e` encoded dot-segments survived `EscapedPath` normalization — passed `/foo/*` scope while decoding to `/bar/x` | decoded `.`/`..` rejected fail-closed at shared `CanonicalResource` choke point; regression tests | FIXED, live-verified deny |
| R2 | HIGH (functional) | Proxy→gateway identity mismatch: hardcoded `subject_id:"egress-agent"` vs P1 `bindIdentity` → **every** transit failed 400→502 | proxy client now derives its honest principal `ag_<sha256(token)[:16]>` mirroring the gateway | FIXED, live-verified 200 |
| R3 | LOW | Response **trailers** forwarded unscrubbed while headers/body were scrubbed — a reflector echoing injected credentials in trailers could leak them | trailer values get the same `[REDACTED]` scrub; regression `TestTrailerSecretScrubbed` | FIXED (final review) |

R2 was fail-closed (denied everything, no bypass) but broke the entire
proxy→gateway path — the class of defect this gate exists to catch.
R3 was a narrow completeness gap in the credential-custody boundary;
no live reflector is known to echo via trailers, but the fix is
one-line-equivalent and removes the residual surface.

## 6. Semantic findings (not defects — documented behavior)

- **Empty delegation audience = unscoped**: valid at ANY gateway sharing
  the trust registry (verified live at two gateways). The issuer's
  signed choice — a delegation meant for one gateway MUST set audience.
- **Lease audience = exact match required** (stricter than delegation).
- **Trust containment**: repeated violations restrict the principal and
  turn later denies into escalates — a real defense, but reports must
  distinguish direct deny from containment escalate.
- **Canonical equivalences**: URL fragments dropped, `//` collapsed,
  default port folded, `nil≡[]` actions — identical bytes AND semantics.

## 7. Security claims matrix

Claims use only: PROVEN · VERIFIED IN TEST ENVIRONMENT ·
PARTIALLY VERIFIED · DEFERRED · ARCHITECTURAL LIMITATION.

| Claim | Classification | Evidence |
|---|---|---|
| Credential-derived principal binding | VERIFIED IN TEST ENVIRONMENT | e2e identity stage |
| Delegation authenticity/issuer/linkage/subject/audience/expiry/non-amplification | VERIFIED IN TEST ENVIRONMENT | e2e + 34-case gate + unit suite |
| Delegation canonicalization (Go↔Python) | VERIFIED IN TEST ENVIRONMENT | byte-identical vectors, Python-signed 2-hop chain verified by Go |
| Delegation replay protection | PARTIALLY VERIFIED | signed nonce + dedicated cache + post-verify mark; process-local 5-min window — NOT durable |
| Lease validation + scope binding | VERIFIED IN TEST ENVIRONMENT | e2e lease stage |
| Policy independence (never lifted) | VERIFIED IN TEST ENVIRONMENT | e2e: valid creds + escalate policy → escalate |
| Approval binding + single-use | VERIFIED IN TEST ENVIRONMENT | e2e approval stage |
| Proxy authz + SSRF guard + port-443 | VERIFIED IN TEST ENVIRONMENT | e2e proxy stage |
| Credential custody (inject + scrub) | VERIFIED IN TEST ENVIRONMENT | e2e: canary → `[REDACTED]` |
| Denied cannot execute | VERIFIED IN TEST ENVIRONMENT | e2e execution stage |
| Receipt integrity (hash-chain + sig) | VERIFIED IN TEST ENVIRONMENT | verify → valid; tamper → invalid |
| Mandatory egress (I1 boundary) | VERIFIED IN TEST ENVIRONMENT | boundary tests — not re-run in RC1 e2e (kernel-level) |
| Complete evidence incl. aborts | PARTIALLY VERIFIED | denials/SSRF/unauth receipted live; abort-after-upstream edge untested |
| Durable replay across restart | ARCHITECTURAL LIMITATION | documented, not claimed |
| Credential lifecycle (expiry/rotation/revocation of tokens) | DEFERRED | per instruction |
| Persistent identity/principal registry | DEFERRED | |
| Receipt external anchoring | ARCHITECTURAL LIMITATION | anchor file written; remote endpoint unverified |
| Network containment (netns/seccomp/AppArmor) | DEFERRED | hardening path, not default deployment |
| Kernel/host compromise | OUT OF SCOPE | documented assumption A7 |

**No claim is marked PROVEN** — all evidence is test-environment
evidence, not mathematical proof or production-deployment attestation.

## 8. Remaining deferred work

- Credential lifecycle (issuance/expiry/rotation/revocation)
- Durable replay state (persistence + restart-survival)
- Receipt anchoring to an external verifier endpoint
- Network-namespace containment verification (I1 automation)
- Integrity monitor for bypass-attempt observability (I8)
- Bearer-token principal registry (named principals vs token-hash)

## 9. Verdict

RC1 security posture: the authorization chain is internally consistent
end-to-end. Three defects were found by this verification and fixed
with regression coverage (R1, R2, R3). The final adversarial review
(alternate identity/authz/proxy paths, credential leakage, substitution
classes, fail-open, SSRF, endpoint inconsistency) found no further
genuine HIGH/CRITICAL defect; source changes during final review were
limited to the R3 trailer scrub and regression tests, plus
documentation-only corrections. No open HIGH/CRITICAL bypass is known
in the tested surface.

**RC1 SECURITY FREEZE = ACCEPTED** for the single-tenant threat model
documented in `OVARA_2_THREAT_MODEL.md`.

## 10. Reproduce

```bash
cd runtime/gateway && go test ./... -count=1
cd runtime/gateway && go test -race ./internal/identity/ \
    ./internal/evaluator/ ./internal/policy/ -count=1
cd proxy && go test ./... -count=1

# Full clean-room e2e (fresh keys/tokens/CA/config/state; needs
# outbound HTTPS for real-transit proxy cases):
python3 tests/e2e/rc1_harness.py /tmp/rc1-e2e
# exit 0 + "RESULT: 46/46 passed" ; results.json per-case details
```
