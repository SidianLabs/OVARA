# OVARA 2.0 — P0.5 Acceptance Audit + P1 Identity Threat Model

**Audit type:** independent security-gate re-verification (no P1 code)
**Audited baseline:** commit `7fc1b685463efc7828a34c5a1ff697c2a4040aa2` + uncommitted P0.5 remediation working tree
**Audit deployment:** genuinely fresh clean-room — `/tmp/p1-audit` created by `ovara init` from a freshly built binary (`/tmp/ovara-audit`), NOT reused from the earlier `/tmp/p05-replay` deployment
**Auditor privileges:** uid 1001, non-root — netns/firewall boundary classes rely on Phase-0 live verification; this audit re-verifies everything reachable without root

---

## A. Exact baseline

- **Commit:** `7fc1b68` (HEAD == audited commit; all remediation is in the working tree, uncommitted)
- **Working tree:** 25 modified files + 14 untracked entries (docs, findings, tests)
- **Go:** go1.25.6 linux/arm64 (`/usr/local/go/bin/go`)
- **Services started:** `ovara run -dir /tmp/p1-audit` — gateway `127.0.0.1:18222`, executor proxy `127.0.0.1:19443`. No netns, no firewall changes, no external dependencies beyond outbound HTTPS for one proxy-transit check.
- **Environment genuinely recreated:** yes — new directory, new CA, new issuer keypair, new receipt keypair, three freshly minted tokens (operator/agent/proxy), fresh policy `v1-init`, empty approval/decision/execution state. A second agent token was later added to the *disposable* deployment to test cross-credential attacks — that is a test fixture, not a repo change.
- **Config deltas for the test deployment (disposable, not repo):** `server_port` 8080→`"18222"` (foreign process owned 8080), `proxy.json` `gateway_url`→`:18222`, proxy `listen_addr`→`127.0.0.1:19443`, `enable_host_executors` toggled for one test phase (restored), second `agent_tokens` entry.

### Test commands executed

```bash
# builds
cd proxy && go build -o /tmp/ovara-audit ./cmd/ovara
cd runtime/gateway && go build -o /tmp/gateway-audit ./cmd/server
# unit/regression
cd runtime/gateway && go test ./internal/... -count=1
go test -race ./internal/policy/ ./internal/handlers/ ./internal/auth/ ./internal/evaluator/
cd proxy && go test ./... -count=1
go test ./internal/receipts/ -run TestAudit_TamperMatrix -v   # TEMP audit harness
# live deployment
/tmp/ovara-audit init /tmp/p1-audit && /tmp/ovara-audit run -dir /tmp/p1-audit
# live attacks — all via curl against :18222/:19443 (exact payloads in sections below)
```

---

## B. P0.5 acceptance verdict

| Gate item | Result |
|---|---|
| SEC-0016 original exploit fails live | ✅ 404 fabricated / 403 self-approve / no execution |
| SEC-0016 variants fail | ✅ divergence 400 per field, replay idempotent, cross-credential create = approval bound to server state |
| No caller can mint arbitrary approval state | ✅ only escalated server decisions mint approvals |
| Approval bound to server-held decision state | ✅ all fields rebuilt server-side |
| Host executor unreachable by agent | ✅ 403; no API registration path exists |
| Host executor cannot be accidentally enabled | ✅ `enable_host_executors` absent from generated config; default false |
| Fresh config fails closed | ✅ missing/malformed config fatal; auth+no-tokens → 503 deny-all |
| Fresh config requires auth | ✅ `ovara init` → `auth_enabled:true` + real tokens |
| Agent/operator separation | ✅ 4-route agent allowlist; everything else 403 |
| Policy mutation operator-authorized | ✅ all mutation routes 403 to agent |
| Canonical parser actually used | ✅ all load paths → `ParseStore`/`parseFilePolicyStrict` |
| Resource survives every load path | ✅ shared `Rule` struct; strictness tests pass |
| Matcher: no demonstrated bypass | ✅ 29-case live battery + ~80-case unit matrix clean |
| Proxy auth before credential processing | ✅ 407 before CONNECT/policy/injection |
| No new critical/high P0 regression | ✅ — see §F for identity issues (P1 scope, not P0 regressions) |

**P0.5 ACCEPTANCE = ACCEPTED**

Caveat: "ACCEPTED" covers the seven P0.5 findings and their exploit
classes. It does NOT extend to identity authenticity, credential
reflection encodings, or evidence completeness — those were never
claimed as fixed and are enumerated in §F–§L as P1 work.

---

## C. SEC-0016 replay (fresh deployment)

| Attempt | Result | Side effect |
|---|---|---|
| Fabricated `decision_id` (agent token) | 404 | none |
| Fabricated `decision_id` (operator token) | 404 | none — even operator cannot invent decisions |
| No token | 401 | none |
| Real escalate → divergent `resource` | 400 `resource does not match` | security.violation event |
| divergent `action_type` | 400 | security.violation event |
| divergent `environment` | 400 | security.violation event |
| divergent `agent_identity.subject_id` | 201 — **silently rebound to server agent** (see note) | none |
| Agent self-approve | 403 | none |
| Agent deny / resume / execute | 403 | none |
| Operator approve | 200, `resolved_by=operator:oncall` | continuation queued |
| Operator execute (no executors) | 400 `no executor registered` | none — `/tmp/p1-pwn.txt` absent |
| Executors ON + fabricated decision | 404 | none |
| Executors ON + agent self-approve | 403 | none |
| Executors ON + operator approve (intended path) | executes | `/tmp/p1-pwn.txt` created — intended behavior |
| Second `create` for same decision | returns same `approval_id` | no duplicate continuation |

**Note (divergent agent_identity):** `agent_identity` is not a
`CreateRequest` field, so caller-supplied identity is *ignored* rather
than compared — the approval binds `agent_id` from the server-recorded
request. Safe outcome, but inconsistent with the other fields' explicit
400s. Cosmetic, not exploitable.

**Verdict: the original exploit is dead at three independent layers**
(provenance lookup, role check, executor registry), verified live on a
fresh deployment including the `enable_host_executors=true` variant.

---

## D. SEC-0017 / 0018 / 0020 verification

- **0017:** `ovara init` config = `127.0.0.1` + `auth_enabled:true` + real tokens; shipped `etc/*.json` = loopback + auth; `Load` errors on missing/malformed; `ValidateStartup` refuses no-auth non-loopback without `unsafe_no_auth`; `0.0.0.0` absent from every shipped JSON. **VERIFIED.**
- **0018:** two token domains; `roleFor` resolves operator first (dual-listed token = operator — privilege-safe direction); agent allowlist = 4 routes; `resolved_by` = `operator:<label>` from credential, not body. Live: agent self-approve → 403 on fresh deployment. **VERIFIED.**
- **0020:** 18-route privileged sweep as agent → all 403 (policy candidate/promote/rollback, shield, capabilities, admin, continuations, executions, receipts, events, audit, trust, runtime introspection). **VERIFIED.**

---

## E. SEC-0005 / 0010 / 0008 verification

- **0005:** every production load path (`LoadStoreFromFile`, watcher/source reload, candidate load, simulate, validate) funnels into `ParseStore`/`parseFilePolicyStrict`. Strict decode rejects unknown fields, `resource:null`, duplicate keys, type confusion (verified live — all rejected with precise errors). `LoadStoreFromConfig` deleted. **VERIFIED.**
- **0010:** 29-case live battery through `/v1/policy/simulate` under a scoped policy — userinfo, suffix/prefix host, percent-host, unicode/homoglyph, port tricks, IPv4/IPv6-mapped literals, tab smuggling, `HTTP/1.1` tail, double-port — all `escalate`; all legit same-host forms `allow`. Space-truncation (V1) and git-ref (V5) round-2 bugs fixed and regression-tested. **VERIFIED.**
- **0008:** no token → 407, wrong token → 407, correct → 200 established + real transit. Auth precedes CONNECT/policy/injection. Non-loopback bind requires `agent_token` (all unspecified spellings). **VERIFIED.**

---

## F. Identity threat model (P1 work item — live results)

### Attack A — self-asserted identity: **WORKS**

Agent token submitted `agent_identity.subject_id="agent-B"` →
decision, approval, and receipt all record `agent-B`. Identity is
derived from **caller-supplied payload**, not the credential.
`issuer` is required but is also a plain caller-chosen string
(`"ovara-init"` accepted — it is the config's trusted issuer ID, and
no proof of issuer is demanded for `agent_identity`).

### Attack B — cross-agent approval: **WORKS (creation side)**

With a second agent token: token-B created an approval on token-A's
decision → 201, approval records `agent-A` (server state wins, but the
approval EXISTS and is real). Execution still requires operator —
contained — but approval-creation is not scoped to the decision's
owning credential.

### Attack C — containment poisoning: **WORKS (trust-state pollution)**

Token-B's requests claiming `subject_id=agent-A` produce decisions
recorded under agent-A (incl. deny/escalate history feeding the
trust/shield engine → agent-A's risk_count rises). Observed earlier:
repeated probes → `containment_active` → real agent-A requests
escalate. An attacker can DoS another agent's trust score or hide
their own history under a victim's identity.

### Attack D — approval GET ownership: **WORKS (no object authz)**

`GET /v1/approval/{id}` returns any approval to any agent token —
verified: token-B read the approval it created AND the earlier 404s
were stale-ID-after-restart, not ownership. `handleGet` performs no
principal check. IDs are unguessable (random), so the exposure is
bounded but real.

### Attack E — receipt ownership: **NOT REACHABLE (route-level)**

All receipt/event/audit endpoints → 403 for agent tokens. Evidence
surfaces are operator-only — ownership is moot because there is no
agent-readable evidence path at all.

### Attack F — delegation: **NOT AUTHENTICATED**

`ValidateDelegationChain` requires issuer strings + verifies
`chain_hash` — a **hash** of the chain fields, computed by the caller.
No signature, no issuer-authentication, no signature-verification
against `trusted_issuers`. Anyone can mint a valid-looking chain.
The evaluator flags only *hash-inconsistent* chains — self-consistent
forgeries pass validation.

---

## G. Lease binding

- Leases are **optional**: nil lease → decided on policy+identity alone.
- A present lease is strictly validated: ed25519 signature against
  `trusted_issuers` (issuer→pubkey map in config), expiry, scope
  (action+resource), revocation via `/v1/capabilities` state, and a
  `garbage lease → deny` (can't weaken). Live: forged lease → `deny
  [capability_not_allowed, capability_expired, identity_invalid]`.
- `lease.VerifyKey` field is explicitly NOT trusted — keys come only
  from server config.
- **Gap:** lease `subject` is not cross-checked against
  `agent_identity.subject_id` or the credential — a valid lease minted
  for agent-A presented while claiming agent-B is not rejected on
  binding grounds (it is rejected today only if the lease itself fails
  sig/scope/expiry).
- `/v1/capabilities/track` is operator-only; with no
  `trusted_issuers`, `allow_unsigned_leases=true` is required and logs
  a WARNING (dev-only).

**Answer: a valid-looking lease provides metadata + a separately
verified capability grant — it does NOT prove caller identity, because
nothing binds lease.subject to the authenticated principal.**

---

## H. Receipt integrity (audit harness results)

`verifyChain` (offline, `VerifyFile(path, pubkey)`) on a 5-entry chain:

| Tamper | Result |
|---|---|
| baseline | Valid (expected) |
| delete first / middle | DETECTED (prev_hash break) |
| reorder / duplicate | DETECTED (prev_hash break) |
| rewrite + original key | DETECTED (signature invalid) |
| **tail truncation** | **UNDETECTED** (4/5 valid) |
| **head truncation (keep first N)** | **UNDETECTED** (prefix valid) |
| **whole-chain rewrite + attacker key** | **UNDETECTED** (self-asserted pubkey accepted) |
| unparseable last line at load | startup refuses (anti-fork) |

What the chain proves: **entry integrity, linkage, per-entry
signature authenticity (given a trusted pubkey)**. What it does NOT
prove: continuity (no length/epoch commitment), completeness (no
external anchor), or authenticity without an independent pubkey
distribution. The anchors file (`var/anchors.jsonl`) exists but there
is no periodic external commitment — self-authenticating by default.
Matches SEC-0002 status: **OPEN, correctly scoped to P1 receipt v2.**

Harness: `proxy/internal/receipts/zz_audit_tamper_test.go` — TEMPORARY
audit code, clearly labeled, not a regression suite.

---

## I. Credential reflection (SEC-0001 status)

- Scrub = literal-byte replacement of injected values in response
  headers + streaming body (64KB hold-back for cross-chunk matches).
- **Confirmed open surfaces (code + prior live PoC):** response
  trailers forwarded WITHOUT scrubbing (`resp.Trailer` loop has no
  ReplaceAll); no Content-Encoding decode (gzip/deflate/brotli echo
  bypasses); no base64/URL/JSON-escape/Unicode variants of the secret
  are scrubbed; error pages from upstream are not special-cased (they
  go through the same body scrub — literal bytes only).
- Classification: implements case-A (literal-byte) only; cases B
  (reversible encoding) and D (derived leakage) are NOT covered.
  Status: **OPEN, correctly scoped to P1.**

---

## J. Network boundary

Verified live (non-root, proxy-level controls):

- CONNECT private/loopback/link-local (127.0.0.1, ::1, 169.254.169.254,
  10.x, 192.168.x, 0.0.0.0, [::ffff:127.0.0.1]) → **403**
- CONNECT non-443 → **403**; CONNECT example.com:443 → **200 + real transit**
- no token / wrong token → **407** before any processing
- Plain-HTTP proxying functional (http://example.com → 200)

Not re-verified (requires root/netns — Phase-0 verified, still
assumption-dependent): netns default-deny, veth isolation, QUIC/UDP-443
block, DNS tunneling, iptables idempotence, FORWARD/IPv6 posture,
same-bridge L2. Deployment assumptions stand as documented in
`docs/OVARA_2_PHASE0_CLEANROOM_BASELINE.md` — boundary remains
**PARTIALLY VERIFIED** (topologies tested in Phase 0 only).

---

## K. Complete finding matrix

| # | Class | Live result | Status |
|---|---|---|---|
| SEC-0016 | fabricated approval→RCE | dead at 3 layers | VERIFIED |
| SEC-0017 | open defaults/fail-open load | fails closed | VERIFIED |
| SEC-0018 | flat token root | role split enforced | VERIFIED |
| SEC-0020 | unauth policy takeover | operator-only | VERIFIED |
| SEC-0005 | resource dropped | canonical parser | VERIFIED |
| SEC-0010 | matcher bypasses | canonical+strict | VERIFIED |
| SEC-0008 | unauth credentialed proxy | 407-first | VERIFIED |
| RT-V1 | space-truncation | fixed+verified | VERIFIED |
| RT-V2/V3 | null/dup resource | rejected | VERIFIED |
| RT-V5 | dead git-ref rules | fixed | VERIFIED |
| RT-D | IPv6 unspecified bypass | fixed | VERIFIED |
| RT-B | duplicate approvals | idempotent | VERIFIED |
| ID-A | self-asserted identity | **WORKS** | **OPEN — P1** |
| ID-B | cross-agent approval create | **WORKS** | **OPEN — P1** |
| ID-C | containment poisoning | **WORKS** | **OPEN — P1** |
| ID-D | approval GET no-ownership | **WORKS** | **OPEN — P1** |
| ID-E | receipt ownership | not reachable | n/a (operator-only) |
| ID-F | unsigned delegation | self-mint valid | **OPEN — P1** |
| LEASE | subject not bound | confirmed gap | **OPEN — P1** |
| SEC-0001 | credential reflection | literal-only | **OPEN — P1** |
| SEC-0002 | receipt completeness | truncation/rewrite undetected | **OPEN — P1** |
| BNDY | netns boundary | Phase-0 verified, unretested | PARTIAL |

---

## L. Proof-boundary classification

| Property | Verdict | Why |
|---|---|---|
| Policy enforcement | VERIFIED IN TEST ENVIRONMENT | canonical parser+matcher, live battery; single-tenant single-file model |
| Identity authenticity | **NOT PROVEN** | subject_id is caller-supplied; credential↔subject unbound |
| Credential isolation | VERIFIED IN TEST ENVIRONMENT | literal-byte scrub works; encodings/trailers open (SEC-0001) |
| Network containment | PARTIALLY VERIFIED | proxy CONNECT/SSRF live-verified; netns topologies Phase-0 only |
| Approval integrity | VERIFIED IN TEST ENVIRONMENT | provenance+binding+idempotency live-verified |
| Execution integrity | VERIFIED IN TEST ENVIRONMENT | executor registry closed; opt-in flag; no API path |
| Receipt integrity | PARTIALLY VERIFIED | entry+link+sig proven; truncation/rewrite undetected |
| Receipt completeness | NOT PROVEN | no external anchor; batch-check receipt parity gap |
| Anti-forensics | NOT PROVEN | events exist but attacker-controllable history (ID-C) |
| Delegation integrity | **FAILED** | hash-only chains, self-mintable |
| Configuration safety | VERIFIED IN TEST ENVIRONMENT | fails closed; secure defaults; explicit unsafe flags |

---

## M. Exact remaining P1 findings

1. **ID-BIND-1 (HIGH):** `agent_identity.subject_id`+`issuer` are
   caller-asserted; approvals/decisions/receipts record unverified
   identity. All cross-agent attacks (A/B/C) derive from this.
2. **ID-OWN-1 (MED):** `GET /v1/approval/{id}` has no object-level
   authorization — any agent token reads any approval.
3. **ID-DELEG-1 (HIGH):** delegation chains are hash-integrity only;
   no signatures, no issuer authentication → self-mintable.
4. **LEASE-BIND-1 (MED):** lease.subject not cross-checked against the
   authenticated principal / agent_identity.
5. **BATCH-EV-1 (MED):** batch-check decisions lack the per-request
   receipt/event trail of single checks (evidence parity gap).
6. **SEC-0001 (HIGH):** credential reflection — encodings + trailers.
7. **SEC-0002 (HIGH):** receipt completeness — no anchoring;
   truncation/rewrite-resign undetected.
8. **KEY-1 (MED):** issuer private keys live in deployment dirs
   (`var/issuer.key`); compromise → forge valid leases.
9. **COSMETIC:** divergent `agent_identity` on approval-create is
   silently rebound rather than 400'd like other fields.
10. Phase-0 deferred: SEC-0003/0004-parent/0006/0007/0009/0011–0015/0019/0021.

---

## N. P1 identity implementation specification (SPEC ONLY — do not implement)

### N.0 Core invariant (mandatory)

> **INV-IDENT-1:** An identity used for policy, approval, execution,
> and evidence ownership MUST be derived from an authenticated trust
> root and MUST NOT be controlled solely by caller-supplied metadata.

Supporting invariants:

- **INV-APPR-1:** an approval is owned by the authenticated principal
  that owns its decision; cross-principal reads/creates are denied
  unless explicitly delegated and recorded.
- **INV-DELEG-1:** every delegation hop is signed by its issuer's key;
  the chain root must be a configured trust root; hash ≠ signature.
- **INV-LEASE-1:** a presented lease is valid only if
  `lease.subject == authenticated principal`; a lease for another
  subject is evidence of misuse → deny + security event.
- **INV-RCPT-1:** evidence objects are owned by the principal that
  produced them; agent reads are scoped to own objects; operator reads
  are global.
- **INV-ROLE-1:** operator/agent domains remain structurally separate;
  no credential may escalate its own domain.

### N.1 Authenticated principal model

Introduce `Principal` as a first-class server-side object:

```
Principal {
  principal_id   // server-assigned, stable, e.g. ag_<uuid>
  credential_id  // fingerprint of the credential used (sha256(token))
  role           // agent | operator | verifier(?) 
  display_name   // optional operator-set label
  created_at, disabled_at
}
```

- `agent_tokens` entries map to Principal records at config load
  (or a principals file for multi-agent deployments). Each token =
  one principal — token rotation ≠ identity rotation.
- Middleware stamps `Principal` (not just `Role`) into request context.
- `auth.PrincipalID(r)` replaces stringly-typed identity everywhere.

### N.2 Canonical agent identity

`agent_identity` in ActionRequest becomes **advisory metadata**
(display/hints), never authoritative:

- The server resolves `subject := PrincipalID(ctx)`.
- If caller supplies `agent_identity` and it disagrees with the
  resolved principal → reject with `identity_mismatch` + security
  event (not silent rebind — callers must not smuggle).
- If omitted → principal used. If supplied and consistent → accepted
  (compat shim, removable later).
- `issuer` field in agent_identity is retired from trust decisions;
  issuer semantics live only in leases (N.3).

### N.3 Lease model

Leases remain ed25519-signed; extend the signed payload to include
`principal_id` and `audience` (gateway_id):

```
payload = lease_id | issuer | principal_id | allowed_actions |
          resource_scope | expiry | delegation_depth | issued_at | audience
```

- `lease.principal_id` must equal the authenticated principal → else
  `lease_subject_mismatch` deny (INV-LEASE-1).
- `audience` must equal this gateway's identity → cross-gateway replay
  dead.
- `trusted_issuers` stays issuer→pubkey config; add issuer metadata
  (created_at, rotated_at, revocation list).
- Leases become **required for privileged action classes** (shell/
  exec/git/host-level), optional for `http.request` — configurable
  per action_type via policy (`require_lease: true` rule field).

### N.4 Approval binding

Extend the provenance model:

- Decision cache entries record `principal_id` of the requester.
- `/v1/approval/create` additionally requires
  `caller.principal_id == decision.principal_id` → else
  `cross_principal_approval` deny + security event (kills ID-B).
- Approval object gains `owner_principal_id`; `GET /v1/approval/{id}`
  requires `caller == owner || operator` (kills ID-D).
- Continuation inherits `owner_principal_id`; execution checks it
  against the continuation record (defense in depth).

### N.5 Receipt/evidence ownership

- Every receipt/decision record stores `principal_id`.
- Agent-scoped reads (if ever added) filter by owner; today they stay
  operator-only (no change needed for correctness).
- Batch-check emits per-item decision records + receipts (parity with
  single check — kills BATCH-EV-1).

### N.6 Delegation model

Replace hash chains with signed hops:

```
DelegationHop {
  issuer_principal | issuer_key_id
  delegatee_principal
  scope { action_types, resource_patterns, max_depth, expiry }
  nonce, issued_at
  signature = ed25519(issuer_key, canonical(hop fields + prev_sig))
}
```

- Each hop signed by the *delegating* principal's key; root issuer
  must be in `trusted_issuers` or be a gateway-registered principal.
- Chain verification: root authenticity → each signature → scope
  narrowing monotonic (child ⊆ parent) → expiry → depth ≤ max_depth.
- Replay: per-chain nonce cache (reuse decision nonce machinery);
  expired/replayed → deny.
- Self-issued hop where issuer == delegatee → reject (INV-DELEG-1).

### N.7 Issuer trust + key protection (KEY-1)

- `trusted_issuers` gains `rotated_at` + `revoked_after` fields;
  config hot-reload or operator endpoint for rotation.
- Issuer private keys: move to `var/` with 0600 (already), document
  KMS/HSM delegation as the production path; add
  `issuer_key_source: file|env|kms` config (file default, warn).
- Key rotation procedure: new issuer ID + overlap window where both
  keys verify; revoke old via `revoked_after`.

### N.8 Revocation + expiry

- Lease revocation exists (`capabilities` store) — extend to
  principal-level disable (`disabled_at` on Principal → all requests
  deny).
- Approvals: expired approvals cannot resolve or execute (exists —
  verify continuation expiry is enforced at execute time, not just
  queue pickup).
- Nonce cache: keep 5-min replay window; extend to lease nonces.

### N.9 Cross-agent isolation

- Trust/shield state keyed by `principal_id`, never subject_id claims.
- All history/decision/trust records store principal_id; migration:
  subject_id strings remain as display metadata only.
- Containment actions (shield restrict) target principals; a caller
  cannot restrict another principal via identity fields (kills ID-C —
  restrict is already operator-only, but trust-accruing requests must
  accrue to the real caller).

### N.10 Operator/agent boundaries

Unchanged structurally; principal model makes it explicit: role is a
property of the credential→principal mapping, not of request metadata.

### N.11 Batch API authorization

- batch-check: per-item decisions stored with principal_id (parity);
  batch approval-create: iterate the same provenance check per item —
  no batch bypass of ownership.
- Batch size caps exist (500) — keep.

### N.12 Persistence model

- `var/principals.json` (or embedded in config for v1): principal_id ↔
  credential fingerprint mapping, created/disabled timestamps.
- Decision cache remains in-memory with TTL (10m) — approvals must be
  created within decision TTL; document that expired decisions require
  re-check (already the behavior).
- Approvals/trust state: in-memory today; P1 keeps in-memory but adds
  durable event journal entries for approval lifecycle (audit trail
  already exists via event store — extend event types).

### N.13 Failure modes

- Unknown principal → 401 (unchanged).
- Principal disabled → 403 `principal_disabled`.
- Identity mismatch → 400 + `security.violation` event.
- Lease subject mismatch → 403 + `security.violation` event.
- Missing lease where required → deny `lease_required`.
- Delegation verification failure → deny `delegation_invalid`.
- Decision TTL expired → 404 on approval create (existing fail-closed).

### N.14 Security invariants (testable)

| Invariant | Test |
|---|---|
| caller cannot mint identity | token-A claims B → 400 |
| cross-principal approval create | B creates on A's decision → 403 |
| approval GET foreign object | → 403 |
| lease subject mismatch | A's lease under B → 403 |
| forged delegation | unsigned/garbage root → deny |
| self-delegation | issuer==delegatee → deny |
| chain scope widening | child ⊄ parent → deny |
| replayed delegation nonce | → deny |
| disabled principal | all routes → 403 |
| lease required action w/o lease | → deny |
| agent→operator metadata escalation | any field → ignored/400 |

### N.15 Implementation order (suggested, not committed)

1. Principal model + middleware stamping (foundation)
2. agent_identity advisory + mismatch rejection (INV-IDENT-1)
3. Approval ownership (create + GET) (INV-APPR-1)
4. Trust keyed by principal (kills ID-C)
5. Lease subject binding + audience (INV-LEASE-1)
6. Signed delegation hops (INV-DELEG-1)
7. require_lease for privileged action types
8. Batch evidence parity (BATCH-EV-1)
9. Issuer rotation/revocation metadata (KEY-1)
10. Then SEC-0001/0002 (credential encodings, receipt anchoring)

---

## O. Assumptions / deployment-dependent claims

- netns/firewall boundary classes rely on Phase-0 verification; not
  re-verified (non-root). Boundary claims remain PARTIALLY VERIFIED.
- Single-tenant gateway: no tenant model exists; "cross-tenant" tests
  are N/A by construction — not claimed as a control.
- The second agent token was a disposable-deployment fixture; repo
  code unchanged for it.
- `ovara run` rewrites config.json on startup — flag persistence
  verified by direct read-back.
- All findings recorded against in-memory state (approvals/decisions/
  trust) — persistence model is documented in N.12.
- No secrets, tokens, or private keys appear in this report or were
  printed during testing (tokens read from disposable files via shell
  variables only).

---

# P1 IDENTITY REMEDIATION — IMPLEMENTATION STATUS

(Added post-implementation. Original audit findings above are
preserved unchanged; this section records what was fixed and the
evidence. Baseline: P0.5 remediation on 7fc1b68, uncommitted working
tree + P1 changes.)

## Fixed findings

| Finding | Status | Fix |
|---|---|---|
| ID-BIND-1 self-asserted subject_id | FIXED | `bindIdentity` on check+batch normalizes subject to the credential-derived principal; mismatch → 400 `identity_mismatch` + security event |
| ID-OWN-1 cross-agent approval create | FIXED | `handleCreate` requires `caller principal == decision.principal` (or operator) → 403; approval `AgentID` copied from cached request |
| ID-OWN-1b approval GET enumeration | FIXED | `GET /v1/approval/{id}` returns 404 for foreign IDs (existence-hiding); list endpoints were already operator-only |
| ID-DELEG-1 hash-only delegation | FIXED | signed hops (ed25519 vs `trusted_issuers`), chain linkage via prevSig, subject binding, non-amplification, expiry, audience, mandatory nonce replay |
| LEASE-BIND-1 lease.subject unbound | FIXED | evaluator denies `lease.Subject != normalized principal`; audience field added to signed payload + `SetExpectedAudience(gatewayID)` wired at startup |
| BATCH-EV-1 batch evidence parity | FIXED | shared `recordDecision` path — identical receipt/event/cache treatment per item; per-item `bindIdentity` |
| (new) `require_lease` | ADDED | `policy.Rule.RequireLease`: lease-less match on an allow rule → escalate `lease_required` (not allow); invalid lease → deny |
| KEY-1 issuer registry | PARTIAL | `trusted_issuers` now also roots delegation hops; rotation metadata still open |

## Implementation summary

- Principal: `auth.PrincipalID(r)` = `(ag_|op_) + sha256(token)[:16]`,
  stamped once by middleware (internal/auth/principal.go).
- Normalization: `Handler.bindIdentity` before evaluation on
  `/v1/runtime/check` and per-item on `batch-check`; missing issuer
  stamped with the gateway enrollment identity (advisory).
- Decision binding: normalized request is what the decision cache,
  receipts, events, trust/shield, drift and chain detectors see.
- Approval binding: ownership check on create + 404-ownership on GET;
  `agent_id` divergence remains a 400 tamper.
- Delegation: `models.Authority` extended (actions, resource_scope,
  audience, expires_at, nonce, signature);
  `Validator.ValidateDelegationChain(chain, subject, seenNonce)`
  verifies signatures, linkage, non-amplification, expiry, audience,
  subject binding; evaluator replays chain nonces via `deleg:`-
  namespaced nonce cache.
- SDK: `DelegationAuthority`/`DelegationChain` extended with the new
  wire fields.

## Test evidence

Unit/integration (all in `runtime/gateway`):

- `internal/handlers/identity_redteam_test.go` — 11 live-stack tests
  through real middleware+mux: matching/foreign/missing identity,
  cross-agent approval create (403) + GET (404), lease subject
  mismatch, self-minted delegation, mixed-owner batch (400),
  batch parity, agent-on-operator-route (403), forged token (401),
  subject mutation after decision (400), operator span, containment
  poisoning dead.
- `internal/identity/delegation_redteam_test.go` — 16 crypto-level
  tests: valid chain, unsigned, unknown issuer, tampered hop,
  subject mismatch, action/resource/expiry expansion, expired hop,
  nonce replay, self-delegation, broken linkage, wrong audience,
  missing nonce, narrowing allowed, reordered hops.
- `go test ./...` — all packages green (28).

Fresh clean-room (`/tmp/p1-cleanroom`, new init/keys/tokens, gateway
:18333, `auth_enabled`, `fail_closed`, 1 op + 2 agent tokens):

- 27-case battery: all identity invariants PASS live (self-asserted
  subject 400; cross-agent approval 403/404; lease foreign/wrong-
  audience/tampered deny; delegation unsigned/forged/expired/wrong-
  audience/subject-mismatch/replay deny; valid signed chain allows;
  mixed batch 400; operator routes 403; forged token 401; claimed
  identity leaves no trust state).
- `require_lease` live: no-lease → escalate `lease_required`;
  valid bound lease → allow; foreign lease → deny.

## Remaining / deferred (unchanged scope)

- SEC-0001 credential reflection (trailers/encodings) — OPEN, P1
  other stream.
- SEC-0002 receipt trust-root, SEC-0003 truncation/anchoring —
  OPEN, evidence stream.
- Token expiry/revocation lifecycle — DEFERRED (bearer tokens are
  membership-only today; see IDENTITY_MODEL §14).
- Per-agent signing keys / onward delegation — DEFERRED (only
  registry issuers can delegate hops).
- Agent-facing evidence endpoints — still operator-only by design;
  evidence ownership model documented for later.
- Internal (non-HTTP) `evaluator.Evaluate` callers don't run
  `bindIdentity` — they produce no decisions today; documented
  invariant for future callers.

---

# P1.1 — Delegation Security Remediation (appendix, history preserved)

Date: 2026-09-18. Baseline: `7fc1b68` + uncommitted P0.5/P1 tree.
Scope: F-1, F-2, F-3, F-7 only. F-4 (credential lifecycle) remains
DEFERRED by explicit instruction.

## Architectural decision

**Delegation is a CAPABILITY, not an attestation.** Chosen because it
is implementable without weakening the boundary: the chain narrows the
request's authority (terminal `actions`/`resource_scope` must cover the
request) and cannot lift policy, trust, lease, or approval gates. A
signature proves "a trusted issuer signed this object"; the evaluator
additionally proves "this request is inside the granted capability".

## F-1 remediation — signed replay identity

- `DelegationChain.nonce` REMOVED (was unsigned → proven replay bypass).
- Replay identity is now the terminal hop's SIGNED `nonce`, inside the
  canonical signature payload — mutating it invalidates the signature.
- Replay key = `sha256(lp(issuer) || lp(nonce))` — canonical tuple, no
  pipe-boundary collision (`"a|b","c"` ≡ `"a","b|c"` under naive join).
- Keyed into a DEDICATED evaluator map (`delegNonceCache`), separate
  from request nonces — previously a shared `"deleg:"`-prefixed key
  space allowed a client to forge the key as a request nonce.
- The mark is applied only AFTER full chain validation — a forged
  chain presenting a victim's nonce cannot poison the cache
  (replay-poisoning DoS found and fixed during this pass).
- Guarantee (honest): process-local, time-bounded (5-minute window),
  non-persistent — the same chain is accepted again after a restart
  or after the window. Verified live.

## F-2 remediation — terminal capability enforcement

`TerminalCapability` resolves the effective scope (last non-empty
`actions`/`resource_scope`; hops may only narrow or inherit). After a
valid chain, the evaluator requires `request.action ∈ cap.actions` and
`cap.scope` covers `request.resource`, else deny
`delegation_scope_mismatch`. Live-verified: a `shell` chain denies a
`deploy` request; an `api.github.com/*` chain denies `evil.example`.

## F-3 remediation — restricted scope grammar

New `internal/identity/scope.go`: `*` | `[METHOD] url[*]` | `literal[*]`.
URL forms canonicalize via `policy.CanonicalResource`; scopes reject
queries, fragments, dot segments (raw/encoded), mid-string `*`, and
uncanonicalizable forms. Containment = canonical literal prefix within
one domain + method equality. The three proven bypasses (query smuggle,
scheme-wrap, traversal) are regression-tested as rejected; a property
test asserts `scopeContains(P,C) ⇒ ∀x: matches(C,x) → matches(P,x)`
over a generated matrix.

## F-7 remediation — canonical payload

New `internal/identity/canon.go`: length-prefixed encoding
(`u32be len || utf8`, `u64be` ints, `u32be count` for arrays) replaces
pipe/`%v` joining. Covers issuer, subject, audience, scope, actions,
expiry, delegated_at, nonce, prev-signature. Python SDK
`ovara_sdk/canon.py` mirrors it; cross-language vectors are checked in
(`canon_vectors_test.go`, `sdk/python/tests/test_canon.py`) including a
Python-signed chain verified by the Go validator.

## Additional findings fixed during remediation

- F-1a: replay mark ran BEFORE signature verification → nonce-poisoning
  DoS. Moved post-validation; regression test added.
- F-1b: `"issuer|nonce"` pipe key had a field-boundary collision →
  hashed canonical tuple.
- F-1c: delegation keys shared the request-nonce map → dedicated map
  (request nonces are client-chosen strings; any prefix is forgeable).

## Tests added

`internal/identity/delegation_redteam_test.go` (rewritten): DELEG-01..36
— forgery, all-field mutation invalidation, replay ×3 forms, nonce
poisoning, action/expiry/audience expansion, scope grammar + bypass
regressions + property test, canonical collisions, linkage splice,
untrusted intermediate, expiry, subject binding, missing nonce,
narrowing-allowed, invalid-scope rejection.
`internal/evaluator/delegation_capability_test.go`: DELEG-37..44 —
in-scope allow, wrong action/resource/method/audience/subject/expiry
denied, policy-deny not lifted, evaluator-level replay + mutated nonce.
`internal/identity/canon_vectors_test.go`: byte-vectors + Python-signed
chain verification.

## Clean-room results (/tmp/p11-cleanroom — fresh keys/tokens/state)

| case | result |
|---|---|
| valid chain, in-scope | allow (policy_allow) |
| valid chain, audience=gw | allow |
| forged signature | deny identity_invalid |
| mutated nonce | deny identity_invalid |
| scope smuggle (wrap/traversal/query) | deny identity_invalid |
| wrong audience | deny identity_invalid |
| expired | deny identity_invalid |
| foreign subject | deny identity_invalid |
| terminal action expansion | deny delegation_scope_mismatch |
| terminal resource outside | deny delegation_scope_mismatch |
| replay (same chain, /check) | deny identity_invalid |
| replay via /batch-check | deny identity_invalid (shared cache) |
| same chain after RESTART | allow → then deny (process-local, documented) |
| repeated violations | escalate containment_active (defense in depth) |

## Claim matrix (delegation)

| claim | status |
|---|---|
| authenticity | VERIFIED IN TEST ENVIRONMENT |
| issuer authenticity | VERIFIED IN TEST ENVIRONMENT |
| subject binding | VERIFIED IN TEST ENVIRONMENT |
| non-amplification | VERIFIED IN TEST ENVIRONMENT (restricted grammar + property test) |
| replay protection | PARTIALLY VERIFIED — signed identifier, post-verify marking, separate cache; process-local, 5-min window, NOT persistent across restart |
| request authorization (capability) | VERIFIED IN TEST ENVIRONMENT |
| canonicalization | VERIFIED IN TEST ENVIRONMENT (vectors byte-identical Go↔Python) |
| expiration | VERIFIED IN TEST ENVIRONMENT |
| audience binding | VERIFIED IN TEST ENVIRONMENT (mismatch denies; empty audience = issuer-scoped unbound) |

## Remaining limitations

- Replay window is 5 min / in-memory — cross-restart replay possible.
- Empty audience hop = valid at any gateway (issuer's signed choice).
- Multi-hop live testing used one trusted issuer (single-tenant);
  two-hop non-amplification is unit-tested, not clean-room-tested.
- F-4 credential lifecycle remains DEFERRED.

---

## P1.1 Integration Gate (adversarial verification)

Fresh two-issuer clean-room (`/tmp/p11-gate`): issuer-A and issuer-B both
in `trusted_issuers`; live `A → B → C` chain verified end-to-end with the
terminal subject as authenticated principal. 34/34 live cases passed:

- Valid multi-hop → allow; untrusted intermediate (A→X→C), terminal
  subject ≠ principal (A→B→X), forged-subject hop → all deny.
- All 12 mutations (either signature, subjects, issuers, linkage,
  audience, expiry, resource, action, nonce) deny.
- Capability matrix: in-scope GET allows; POST, wrong path, wrong host,
  non-default port, wrong scheme deny; explicit `:443` equals default.
- Delegation + lease + policy: valid triple allows; each independent
  break denies; policy escalation is NOT lifted by valid credentials.
- Replay: first presentation allows, exact replay denies, mutated
  signed nonce denies, replay via batch endpoint denies. Process
  restart re-accepts a chain once (documented process-local limitation).
- Empty audience verified live at TWO gateways: `audience=""` is
  genuinely unscoped — valid at any gateway (issuer's signed choice),
  not bound to the current gateway. Explicit audience is enforced.

### Defect found and fixed during the gate

`CanonicalResource` normalized on `u.EscapedPath()`, so
`https://host/foo/%2e%2e/bar/x` kept `%2e%2e` literal and passed a
`/foo/*` scope while its *decoded* path `/foo/../bar/x` escapes it for
any percent-decoding downstream. Reproduced live (ALLOW before fix).
Fixed at the shared choke point — decoded `.`/`..` segments are now
rejected fail-closed before normalization — covering policy matching
and delegation scope matching. Regression tests added
(`TestMatchResource_CanonicalAttacks`).

Observed canonical equivalences (not bypasses): URL fragments are
dropped (never part of authorization identity), repeated `/` collapse,
explicit default ports normalize. `nil` vs `[]` actions produce
identical bytes AND identical semantics (both empty = inherit).
