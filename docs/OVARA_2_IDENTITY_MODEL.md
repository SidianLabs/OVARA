# Ovara 2.0 — Identity Model (P1)

Status: implemented (P1 identity authority workstream).
Baseline: P0.5 remediation on `7fc1b68`.

The core rule of this document:

> "the caller claims to be X" is untrusted input.
> "the security boundary authenticated X" is a security fact.
> Every authorization decision uses the second.

## 1. Principal model

The canonical internal identity is the **principal ID**:

```
principal_id = (ag_|op_) + hex(sha256(credential))[:16]
```

| Field | Realization |
|---|---|
| principal_id | 18-char role-prefixed credential hash — stable across restarts, unambiguous, never caller-supplied |
| principal_type | `ag_` = agent, `op_` = operator. The prefix is part of the ID: a dual-listed token still produces a distinct principal per role |
| trust_domain | single-tenant: the configured token registry of this gateway |
| credential binding | the bearer token itself; the ID is a one-way function of it |
| issuer | the gateway's enrollment identity (stamped on normalized requests when the caller omits `agent_identity.issuer`) |
| status / expiry | none — bearer tokens are non-expiring today (see Limitations) |

There is no service/system principal type; internal callers are
addressed in §Limitations.

## 2. Authentication

`auth.Middleware` (internal/auth/middleware.go) resolves the bearer
token to a role (`roleFor`: operator list first, then agent list —
a dual-listed token resolves operator, the *safe* direction for
privilege, and the principal ID still carries the `op_` prefix so
identity stays unambiguous).

On success the middleware stamps two context values:

- `ctxKeyPrincipal` — the role string (`auth.Principal(r)`)
- `ctxKeyPrincipalID` — the canonical principal (`auth.PrincipalID(r)`)

Both are derived **once**, at the trust boundary, from the same
authenticated token. Handlers never re-derive identity.

Fail-closed: `auth_enabled=true` + zero tokens denies everything;
invalid/unknown token → 401; agent token on an operator route → 403.
`agentAllowed()` is an allowlist — any new route is operator-only
until explicitly added.

## 3. Identity resolution — bindIdentity

`Handler.bindIdentity` (internal/handlers/runtime.go) runs on every
`/v1/runtime/check` and per-item on `/v1/runtime/batch-check`,
**before** evaluation, decision caching, trust scoring, lease and
delegation checks, receipts, and events:

```
principalID := auth.PrincipalID(r)
subject supplied && subject != principalID
        → 400 identity_mismatch  (deterministic rejection)
        → security-violation event emitted
otherwise
        req.AgentIdentity.SubjectID = principalID
        req.AgentIdentity.Issuer  ||= gateway identity (advisory)
```

Consequence: downstream code paths (evaluator, trust/shield, drift,
chain detector, receipts, decision cache, approvals) all observe one
identity — the authenticated principal. Caller fields
(`agent_identity.subject_id`, `agent_id`, `owner`, …) are advisory
metadata; where they conflict with the principal they are rejected,
not silently rebound.

## 4. Decision binding

Each decision is produced by the evaluator from the normalized
request and stored in the server-side **decision cache**
(`recordDecision`, shared by check and batch):

```
decision_id → (normalized ActionRequest, DecisionResponse)
```

The cached `agent_identity.subject_id` IS the principal — so
decision ownership is never inferred from caller metadata. Receipts
and events emitted in the same path carry the same subject. Batch
items get identical treatment (evidence parity; `recordDecision` is
the single path).

## 5. Approval binding

Creation (`handleCreate`):

1. `decision_id` must exist in the server cache (fabricated → 404).
2. **Ownership**: `caller principal == decision.principal`, unless
   the caller is an operator → otherwise 403.
3. Decision must have escalated → otherwise 409.
4. Caller-supplied `action_type`/`resource`/`environment`/`agent_id`
   are compared to the cached request — divergence → 400.
5. Idempotent per decision; denied decisions can't mint a second.
6. The approval's `AgentID` is copied from the cached request —
   i.e. the authenticated principal — never from caller JSON.

Retrieval (`GET /v1/approval/{id}`): agents may read only approvals
whose stored `AgentID` equals their principal; foreign or guessed IDs
return **404** (existence-hiding, consistent). Operators see all.
List endpoints (`/v1/approvals`, `/v1/approval/pending`,
`/v1/approval/{id}/resume`, approve/deny) are operator-only by route
allowlist.

## 6. Cross-agent isolation

Because every per-agent state object is keyed by the normalized
subject (trust/shield store, drift state, chain detector records,
decision cache, approval `AgentID`), and `bindIdentity` rejects
foreign subjects before evaluation, agent A cannot:

- mint decisions, approvals, or receipts under B's identity;
- poison B's containment/trust state;
- read B's approvals;
- spend B's leases or delegations (subject binding, §7–8);
- reach B's state through batch items (per-item binding; a foreign
  subject rejects the batch).

Operators span agents only via the operator credential.

## 7. Lease model

`CapabilityLease` binds: lease_id, issuer (must be in
`trusted_issuers`), subject, allowed_actions, resource_scope, expiry,
issued_at, **audience**, delegation_depth, revocation handle,
ed25519 signature over all of it.

At evaluation (evaluator.go):

- revocation check → `capability_revoked`
- `ValidateCapabilityLease` — required fields, expiry, ed25519 over
  `…|IssuedAtUnix|Audience` against the issuer's registry key
- **subject binding**: `lease.Subject` must equal the normalized
  principal — a lease minted for another subject denies
  (`capability_not_allowed`); a lease with no bindable principal
  denies too
- scope check — action ∈ allowed_actions, resource ∈ scope

`VerifyKey` inside the lease is ignored for trust decisions —
verification uses the registry only.

`require_lease` on a policy rule (`policy.Rule.RequireLease`) makes
the matched allow conditional: no lease → **escalate**
(`lease_required`), invalid/mismatched lease → deny, valid bound
lease → allow.

### Audience

`Validator.SetExpectedAudience(gatewayID)` is wired at startup from
the enrollment identity. A lease whose `audience` differs from this
gateway fails — a credential minted for gateway G cannot be replayed
at gateway H. (Empty-audience leases on an audience-configured
gateway also fail: an unbound lease is not audience-bound.)

## 8. Delegation model — capability semantics (P1.1)

**Decision (P1.1): delegation is a CAPABILITY, not an attestation.**
A valid chain does not merely prove "an issuer signed something" — it
grants a bounded capability, and the evaluator enforces that capability
against the actual request. The chain can only narrow the request's
authority; it can never lift policy, trust, lease, or approval gates.

### Semantics

`DelegationChain` = ordered signed hops. There is **no chain-level
nonce** (P1.1 F-1: an unsigned replay identifier was proven bypassable;
the replay identity is now the terminal hop's *signed* nonce).

Each `Authority` hop:

```
issuer        root hop: an id in trusted_issuers;
              later hops: previous hop's subject_id (chain linkage)
subject_id    delegatee; final hop's subject must be the
              authenticated principal
actions       delegated action scope (empty/"*" = inherit parent)
resource_scope delegated resource scope (""/"*" = inherit)
audience      must match this gateway's identity when set;
              empty = issuer-chosen, valid at any gateway
expires_at    honored at every hop; must not exceed parent's
nonce         hop-level nonce — inside the signed payload
delegated_at  assertion time — inside the signed payload
signature     ed25519 over the canonical (LP-encoded) hop payload,
              which ends with the PREVIOUS hop's signature hex —
              reordering or splicing invalidates signatures
```

### Canonical signed payload (P1.1 F-7)

Signatures cover a length-prefixed binary encoding
(`internal/identity/canon.go`, mirrored byte-for-byte by
`sdk/python/ovara_sdk/canon.py`):

```
lp(issuer) lp(subject_id) lp(audience) lp(resource_scope)
lparr(actions) i64(expires_at) i64(delegated_at)
lp(nonce) lp(prev_signature_hex)
```

Every security-relevant field is inside the signed bytes; the encoding
is unambiguous by construction (no pipe-joins, no `%v` formatting —
field and array boundaries are length-delimited). A signature
identifies exactly one semantic object.

### Scope grammar (P1.1 F-3)

Delegation scopes use a restricted grammar (`internal/identity/scope.go`):

```
scope  := "*"                          unbounded / inherited
        | [METHOD " "] <url> ["*"]     URL scope; trailing "*" = prefix
        | <literal> ["*"]              non-URL literal (no space, no "://")
```

URL forms canonicalize through `policy.CanonicalResource` (scheme/host
lowercase, default-port drop, dot-segment cleanup, userinfo rejected).
Scopes additionally reject: query strings, fragments, dot segments
(raw or percent-encoded), mid-string `*`, spaces in literals, and
anything that fails canonicalization. Containment is prefix
containment on canonical literals within one domain (URL vs literal)
with method matching — `scopeContains(P,C)` means every resource
matched by C is matched by P; anything unprovable is rejected.

### Verification (`Validator.ValidateDelegationChain`)

- every hop's signature verifies against `trusted_issuers[issuer]` —
  a caller cannot mint a hop (a hash is not authentication);
- `issuer[i+1] == subject[i]` — only trusted issuers can pass
  authority onward (the intermediate subject must itself be in the
  registry to sign the next hop);
- non-amplification: `child.actions ⊆ parent.actions`,
  `scopeContains(parent, child)`, `child.expiry ≤ parent.expiry`
  (unset child fields inherit);
- no self-delegation (`issuer == subject` rejected);
- expiry and audience enforced per hop;
- replay: the terminal hop's signed nonce, keyed as
  `sha256(lp(issuer)||lp(nonce))` in a dedicated evaluator cache —
  checked only AFTER full cryptographic validation (a forged chain
  cannot poison a victim's nonce), separate from request nonces
  (a client cannot forge the cache key as a request nonce);
- final subject must equal the normalized principal — a chain
  minted for agent B is worthless to agent A;
- `chain_hash` (legacy field) is still verified when present.

### Terminal enforcement

After validation, the evaluator extracts the terminal capability
(last non-empty `actions` / `resource_scope` through the chain —
hops may only narrow or inherit) and requires:

```
request.action   ∈ cap.actions
request.resource ∈ cap.resource_scope   (canonical scope match)
```

A chain delegating `shell` cannot authorize `deploy`; a chain scoped
`https://api.example.com/*` cannot authorize `https://evil.example/`.
Mismatch denies with `delegation_scope_mismatch`. Policy, trust,
leases, and approvals then evaluate exactly as for an undelegated
request — the capability is a constraint, never a grant.

Result: delegation authority always descends from the configured
trust roots; an agent cannot self-mint, widen, extend, replay, or
spend a capability outside its terminal scope.

## 9. Capability / authorization model

Authorization resolves: `credential → role → principal → route
allowlist (transport) + object-level ownership (data)`. Privileged
actions additionally require `require_lease` — an issuer-signed,
audience-bound, subject-bound capability.

## 10. Batch authorization

`/v1/runtime/batch-check` runs `bindIdentity` per item — a batch is
exactly N single-checks under one credential. A foreign subject in
any item rejects the whole batch with 400 (no partial leakage of
which item was accepted). Evidence (`recordDecision`) is identical
per item.

## 11. Persistence / ownership

State remains in-memory by design (no DB added). Ownership map:

| Store | Owned by | Ownership established at |
|---|---|---|
| decision cache | decision.principal | normalized subject at eval time |
| approvals | `Approval.AgentID` | copied from cached request |
| trust/shield state | subject key | normalized subject |
| drift/chain detectors | subject key | normalized subject |
| receipts/events | subject in request | normalized subject |
| nonce cache | n/a (replay guard) | evaluator |
| lease/delegation | external issuer | trusted_issuers registry |

Migration note for future durable stores: persist `principal_id` on
every object at creation from the authenticated context — never from
the request body.

## 12. Security invariants → implementation

| INV | Implementation |
|---|---|
| 1 authenticated principal authoritative | `auth.PrincipalID` = sha256(token) + role prefix, stamped once |
| 2 self-asserted subject can't change identity | `bindIdentity` 400s mismatches |
| 3 decisions principal-bound | decision cache keyed off normalized request |
| 4 approvals inherit principal | `AgentID` copied from cached request |
| 5 approval unusable by another | create ownership check 403 |
| 6 approval unreadable by another | GET 404s foreign IDs |
| 7 lease subject == principal | evaluator subject binding |
| 8 delegation issuer authenticated | ed25519 vs trusted_issuers per hop |
| 9 delegation non-amplifying | per-hop subset checks |
| 10 cross-agent mutation denied | normalization + ownership checks |
| 11 batch parity | per-item bindIdentity + recordDecision |
| 12 operator-only stays operator-only | route allowlist + dual-list resolves operator |
| 13 expired/revoked credentials fail closed | unknown token → 401 (tokens don't expire — Limitations) |
| 14 metadata can't change identity | mismatch → 400, issuer advisory |

## 13. Operator/agent separation

Agent allowlist: `POST /v1/runtime/check`, `POST
/v1/runtime/batch-check`, `POST /v1/approval/create`, `GET
/v1/approval/{id}` (except `/v1/approval/pending`). Everything else —
policy mutation, trust-root/issuer config, approvals resolution,
continuations, evidence exports, shield controls, capability
revocation — is operator-only.

## 14. Known limitations

- **Tokens do not expire and are not individually revocable.** A
  leaked bearer token is valid until the deployment is re-keyed.
  `CredentialID`/expiry/status fields of the conceptual model are
  satisfied only by token-registry membership. Per-credential
  lifecycle is deferred work (SEC-0019 class).
- **No per-agent signing keys.** Principals authenticate by bearer
  token only; consequently delegation hops can only be issued by
  registry issuers (agents cannot delegate onward). This is a
  deliberate single-tenant simplification.
- **Delegation nonce window** = request-nonce TTL (5 min). Longer
  replay protection would need a dedicated store.
- **Advisory `agent_identity.issuer`** is not validated against
  trusted issuers — it carries diagnostics only. A caller claiming a
  foreign issuer does not gain or lose authority.
- **Old-format approvals** (pre-P1 `agent_id` strings) are
  unreadable by agents under the new ownership check; operators
  retain access. One-way migration.
- **`require_lease` escalates rather than denies** a lease-less
  request matching an allow rule — chosen so a human can approve.
  Invalid leases deny outright.
- Internal `evaluator.Evaluate` callers outside the HTTP path
  (e.g. trust-context generation) do not run `bindIdentity` — they
  produce no decisions/approvals. If a future caller creates
  decisions, it must normalize identity first.
- **Delegation replay protection is process-local and
  time-bounded** (5-minute window, in-memory): a chain's terminal
  nonce can be re-presented after a gateway restart or after the
  window lapses. Persistent replay state is deferred.
- **Delegation scope grammar is intentionally restricted** —
  prefix-only wildcards, no query/fragment, no dot segments. This
  is what makes the containment property provable; richer glob
  semantics are deferred rather than half-proven.
- **Empty audience is unscoped**: a hop signed without `audience`
  is valid at any gateway. This is the issuer's explicit choice,
  not an attacker vector (audience is signed).

## 15. Federation / key management (future)

- Principal record with `credential_id`, `status`, `expires_at`,
  rotation metadata — blocked on per-credential lifecycle.
- Per-agent signing keys would let delegatees chain onward (today
  only registry issuers can).
- Multi-domain trust: `trust_domain` field reserved; audience check
  already separates gateways.
- Anchored receipts and the receipt trust-root work are separate
  P1 streams (SEC-0002/0003) — out of scope here.
