# OVARA P2.3 — GATEWAY TRUST + REVOCATION PROPAGATION DESIGN

Status: DESIGN PHASE — no production code.
Closes: I6 (audience/gateway binding as a cryptographic property),
I20 (revocation propagation). Preserves every frozen invariant.
Companion: `OVARA_P2.3_THREAT_MODEL.md`, `OVARA_P2.3_SECURITY_DECISIONS.md`.

---

## 1. CURRENT GATEWAY TRUST — WHAT IT PROVES TODAY

`enrollment.json` holds a self-generated `gw_<ms><rand>` string.
Properties it provides:

- A stable *name* for audience matching, receipts, and logs.
- Persistence across restarts (atomic file write).

Properties it does NOT provide:

- Proof of possession — nothing demonstrates control of a secret.
- Uniqueness — a copied file IS the identity (T-ENROLL-CLONE is fully
  realized today).
- Cryptographic audience binding — `expectedAudience` is a string
  compare; the name is the only thing checked.
- Revocability — there is no gateway lifecycle at all.
- Externally verifiable evidence — receipts are HMAC'd with a
  symmetric config key; a verifier needs the secret itself.

Verdict: gateway identity today is a **filesystem/trust-domain
membership property** (as documented at P2.2 freeze). I6 holds only
within the assumption that nobody clones the filesystem.

## 2. GATEWAY IDENTITY ARCHITECTURE

### 2.1 Options compared

| | A. Ed25519 software key | B. Certificate-backed | C. TPM/hardware | D. Software + attestation |
|---|---|---|---|---|
| Key generation | `crypto/ed25519`, local | CA issuance | TPM create+seal | hybrid |
| Key storage | file (trust domain) | file + chain | TPM NVRAM | file + TPM |
| Proof of possession | sign nonce | TLS client cert | PCR quote | quote |
| Rotation | re-key file + registry entry | re-issue cert | re-seal | mixed |
| Revocation | registry state | CRL/OCSP | EK revocation | mixed |
| Clone resistance | filesystem only | filesystem only | real (key non-exportable) | real |
| Offline | full | needs CA/CRL reachability or long certs | full | partial |
| Deployment cost | zero deps | PKI required | TPM required | both |
| Container/single-host | trivial | awkward | often unavailable | awkward |

### 2.2 The honest security statement

**Option A does NOT, by itself, stop a full-filesystem clone** — a
copied private key is as clonable as the copied JSON it replaces.
Anyone who claims otherwise is selling a name-check in new clothes.

What Option A actually buys (and why it is REQUIRED-BY-INVARIANT for
I6 as a *cryptographic* property):

1. **Naming vs possession separation** — audience binding becomes
   "does the responding gateway prove possession of the key bound to
   `gw_id` in the domain registry" rather than "does it print the
   right string."
2. **Signed evidence** — receipts/checkpoints/events signed with the
   gateway key are verifiable by third parties (required for future
   anchoring; HMAC cannot leave the trust domain).
3. **Lifecycle** — rotation/revocation become expressible; a stolen
   key can be killed without renaming the gateway.
4. **Clone *detection*** — a registry that sees two endpoints
   claiming the same `gw_id`+key can alert and fail closed; today a
   clone is *invisible*.

Clone resistance in the strict sense needs C (non-exportable key) or
D — deferred as a deployment-level hardening option, documented as a
residual: **within P2.3, a full-filesystem clone remains possible;
it becomes detectable rather than silently valid, and the key itself
becomes revocable.**

### 2.3 Recommended model

```
GatewayIdentity{
  ID            string   // gw_<id> — stable name, audience target (unchanged)
  KeyID         string   // gwk_<id> — current active key
  EnrollmentState        // local | enrolled | pending (unchanged)
  ...
}
GatewayKey{                       // new artifact
  KeyID       string
  GatewayID   string
  PublicKey   ed25519             // private half in gateway_key file (0600)
  State       string              // active | rotating | superseded | revoked
  IssuedAt    time.Time
  SupersededAt/RevokedAt *time.Time
}
```

- `gw_id` remains the audience target — delegation/lease canonicalization
  is UNCHANGED (audience is a string field; what changes is what the
  string *means*: an identity whose possession is provable, not a bare
  name).
- Private key file lives in the trust domain, mode 0600, atomic writes.
- PoP protocol: `sign(gw_id ‖ key_id ‖ challenge_nonce ‖ ts)` —
  verifiable by any holder of the registry's pubkey record.
- Gateway IDs generated on first boot stay random; registration binds
  the generated key to the claimed ID via PoP.

## 3. ENROLLMENT

### 3.1 Embedded mode (recommended baseline — matches every P2 store)

```
first boot → generate ed25519 keypair
           → register {gw_id, key_id, pubkey, state=active} in the
             domain gateway registry (JSONL+flock file, same pattern
             as replay journal / idregistry)
           → PoP self-check: sign+verify a nonce before going live
```

Registration conflicts: an existing `gw_id` with a DIFFERENT pubkey →
reject startup (fail closed — this is the clone/squat detector). Same
gw_id + same pubkey → idempotent re-join (restart path).

### 3.2 Enrollment authority

- Embedded mode: the operator writing the registry file IS the
  enrollment authority (same root as every other lifecycle op).
- A pre-provisioning path exists for ops: operator writes the gw_id +
  expected pubkey into the registry BEFORE first boot (TOFU pin); the
  gateway then MUST prove possession — a gateway that can't sign for
  a pinned key fails startup. This closes unauthorized-registration
  without any service.
- Service mode (control-plane enrollment, enrollment tokens, PoP
  challenge issuance): deferred — the `FederatedTrustClient` stub is
  the seam, not a commitment.

### 3.3 Removal

`state=revoked` on the gateway registry entry + revoke its active key.
A revoked gateway's PoP fails → its audiences are unanswerable →
delegations targeting it die at every OTHER gateway that checks PoP.
Local effect on the revoked gateway itself: it refuses to serve
delegation/lease evaluation (self-check at startup + periodic re-check).

## 4. AUDIENCE BINDING — THE CRYPTOGRAPHIC PROPERTY

Property: *a delegation minted for G1 authorizes only at an endpoint
proving possession of a key registered to G1.*

Test matrix (design):

| presentation | result |
|---|---|
| artifact for G1 at real G1 | ALLOW (rest of auth unchanged) |
| artifact for G1 at G2 (different key, different ID) | DENY — audience mismatch (name check still first) |
| artifact for G1 at clone claiming G1's ID but different key | DENY — registry PoP fails at that clone's own startup |
| artifact for G1 at full clone (same key file copied) | ALLOW AT THE CLONE — honest residual: indistinguishable; detection = duplicate check-in conflict, mitigation = TPM option |
| artifact for G1 with G1's key REVOKED | DENY — no active key can prove the audience |
| copied config/public key only (no private key) | DENY — possession required |

Mechanism is deliberately boring: the registry's `gw_id → active
pubkeys` map plus PoP at evaluation-relevant moments — startup
self-check, periodic re-verification, and a signed proof embedded
where a third party consumes evidence (receipts).

## 5. GATEWAY KEY LIFECYCLE

`GENERATE → ACTIVE → ROTATING → SUPERSEDED → REVOKED → DESTROYED`

- ROTATING: both old+new verify PoP for a bounded window (default 60s,
  same pattern as credential rotation) — receipts signed during the
  window carry `key_id` so verifiers pick the right key.
- SUPERSEDED: no longer signs; remains in the registry so historical
  signatures keep verifying (history is not rewritten — §6 invariant).
- REVOKED: verifies nothing going forward; historical signatures stay
  verifiable (a revoked signing key does not un-sign its past).

Artifact effects on rotation — all explicitly NO-OPs where possible:

| object | effect |
|---|---|
| delegations/leases (audience=gw_id) | none — audience binds to the IDENTITY, not the key |
| identity/credential registry | none — separate state machine |
| replay journal | none |
| receipts | new sigs use new key_id; old sigs verify via key history |
| approvals/continuations | none |

Key REVOCATION (theft): PoP fails for the revoked key → if no active
key remains, the gateway cannot authenticate its audience → startup
refusal / service halt (fail closed). Recovery = operator enrolls a
new key for the existing gw_id (key rotation path), never a silent
re-key.

## 6. ISSUER REVOCATION

### 6.1 Model (ratifies D-05's lean)

Signed-statement-capable store, embedded deployment:

```
RevocationEntry{
  ArtifactClass  string   // "issuer" | "delegation" | "lease" | "gateway-key"
  ID             string   // issuer_id | delegation presentation key | lease_id | key_id
  Epoch          uint64   // domain monotonic counter
  RevokedAt      time.Time
  Reason         string
  Actor          string   // operator identity that committed it
  Signature      []byte   // present when issued by an external authority;
                          // embedded mode: the file itself is the record
}
```

Storage: JSONL + flock + in-memory index — the proven P2.1/P2.2
pattern, one file per trust domain (`revocation_file` config).
Config-but-unopenable = startup refusal; never fall back to
"everything unrevoked."

### 6.2 Issuer revocation semantics (issuer A compromised)

- New presentations signed by A: deny at issuer check (after
  signature verify — a forged artifact needn't consult revocation;
  check order: crypto → revocation → semantics).
- A→B hop inside a longer chain: the hop fails → the whole chain
  fails (every hop must verify AND be unrevoked).
- A→B→C: dies entirely — there is no orphan-validity semantics
  (§8).
- Leases issued by A: issuer-class revocation covers them.
- Existing approvals referencing A-issued artifacts: historical
  records stand; execution blocked via claim-time re-check (§14).
- Running executions: not killed (documented non-goal).
- Receipts of past decisions: historically valid — revocation never
  rewrites evidence.

### 6.3 trusted_issuers relationship

Config map stays the trust root (add/remove key = restart) in
embedded mode; the revocation store adds the runtime kill layer
ON TOP — an issuer not in trusted_issuers already fails crypto; an
issuer in trusted_issuers + revoked fails revocation. Revocation
without config removal is therefore meaningful; config removal is
the heavier administrative action.

## 7. DELEGATION REVOCATION

**Key design choice**: revoke by the delegation's *presentation
identity* — exactly `sha256(lp(issuer)‖lp(nonce))` of the terminal
hop, the identifier P2.1 already consumes. Consequences:

- Zero canonicalization changes (RC1 chain format untouched —
  no `chain_id` field needed; the signed nonce IS the id).
- Revoking the artifact pre-first-use blocks the FIRST consume;
  post-use, P2.1 replay already blocks re-presentation.
- Revocation check slots into the evaluator where the replay key is
  already computed — one choke point, same ordering story.

Lease revocation: existing tracked-lease `IsRevoked` continues;
`revocation_file` gains `lease` class so untracked leases presented at
check time are consulted against the store by `lease_id` — closing
the "untracked lease can't be revoked" gap without changing RC1
validation order.

A revoked capability cannot authorize a NEW execution — enforced at
eval (deny) AND at continuation claim (§14).

## 8. CHAIN REVOCATION — DERIVED, NOT ASSUMED

Trust model: a chain is a sequence of signed hops; validity requires
EVERY hop to (a) verify cryptographically against its issuer's key,
(b) be within expiry, (c) satisfy non-amplification, (d) have an
issuer not revoked, (e) have its own presentation identity unrevoked.

Derived answers:

- Issuer A revoked ⇒ every hop A signed is dead ⇒ every chain
  containing such a hop dies, in ANY position. No orphan validity.
- Delegation A→B revoked (presentation key) ⇒ that artifact dies;
  a *different* delegation minted by A for B is a different
  presentation — unaffected (artifact-granular, not edge-granular).
- Edge-granular revocation (kill ALL A→B delegations) = issuer-class
  entry `delegation-edge: A→B` — optional extension, deferred unless
  threat model demands it (recorded in D-12).
- Intermediate SUBJECT identity suspension is NOT consulted mid-chain
  (issuers are keys, not identities — explicit rule). Terminal subject
  is authenticated → P2.2 covers it.
- B's identity suspended ⇒ B cannot authenticate ⇒ B's chains are
  unusable by B; a chain minted by A for C *through* B still works
  for C (B was a conduit, not a principal) — documented semantics.

## 9. REVOCATION STATE ARCHITECTURE — ALTERNATIVES

| | A denylist | B epoch/gen | C signed stmts | D central registry | E short-TTL only | F hybrid (recommended) |
|---|---|---|---|---|---|---|
| security | no freshness | monotonic proof | portable+auditable | strong consistency | weak kill | all properties |
| latency | low | low | low | network hop | none | low |
| offline | yes | yes | yes (cache) | no | yes | yes |
| growth | unbounded | counter+denylist | bounded by TTL of artifacts | centralized | zero | bounded |
| multi-gateway (same domain) | shared file | shared file | shareable | native | n/a | shared file |
| rollback risk | yes | detectable (epoch regress) | detectable | depends | n/a | detected at epoch layer |

**Recommended: F** — JSONL entries carrying a domain epoch; the file
is the denylist, the epoch is the freshness witness, signatures make
entries portable when an external authority later exists. Same
artifact family as P2.1/P2.2 (one pattern, three uses).

## 10. STALENESS SEMANTICS

States: `fresh` | `stale` | `unknown` | `unavailable` | `regressed`

Embedded mode (P2.3 implementation target): the store is a local file
under flock — reads see the last committed write; staleness inside a
domain is effectively zero by construction. `unavailable` (open/
parse failure) → startup refusal; mid-run failure → deny.

For the documented future external mode (and for any cached view):
`staleness_budget` default 30s (D-10), capability-bearing requests on
a stale view → ESCALATE (D-03), never silent allow; plain requests →
continue (revocation protects capabilities, not base auth) — with the
documented caveat that this boundary accepts credential-check
staleness D-02 style.

`regressed` (epoch moves backward — rollback signature): fail closed
+ CRITICAL event; never silently accept a younger view.

`min_epoch` on requests (from P2 design §9.2): a caller may cite the
epoch its authorization context depends on; a gateway below it
denies/escalates — protects "approve at G1, execute at G2" flows.

## 11. MULTI-GATEWAY TRUST DOMAIN

CURRENT TRUST DOMAIN (implemented): **one filesystem** — processes
sharing `revocation_file`, `replay_file`, `identity_registry`,
`gateway_registry` via flock. This is the same boundary P2.1 and
P2.2 already define. Multiple gateways in one domain share state
files; each keeps its own `gw_id`+key in the domain gateway registry.

FUTURE TRUST DOMAIN (designed, not built): gateways in separate
filesystems replicating signed revocation statements + epochs — the
statement format is chosen NOW so it travels; replication/consensus
is explicitly not implemented. Audience binding keeps cross-domain
artifact misuse denied by construction even if replication lags.

Split-brain inside the implemented domain: not expressible — one
file, one lock. Between domains: each domain consumes independently;
cross-domain replay is stopped by audience mismatch, NOT by shared
consume state — documented, consistent with P2.1's non-claim.

Gateway addition: registry entry + PoP. Removal: revoked entry +
key revoked. Disagreement about issuer revocation between gateways
of one domain: impossible (shared file). Between domains: each
domain's own epoch — requests carry `min_epoch` when they care.

## 12. DISTRIBUTED REPLAY INTERACTION

P2.1's guarantee stands unchanged: at-most-once within the shared-
journal domain. P2.3 does NOT extend it.

G1 consumes presentation X; X arrives at G2:

- Same domain (shared journal): ALREADY_CONSUMED — deny.
- Different domain: G2's journal has no record of X. G2's answer
  depends on audience: if X's terminal hop names G1's gw_id →
  audience mismatch → deny (G2 can't even prove the audience).
  If X is unscoped (empty audience — a documented issuer choice) →
  G2 may consume it: at-most-once becomes at-most-once-PER-DOMAIN,
  which is exactly the P2.1 claim and no more. Honest consequence:
  unscoped-audience single-use capabilities are single-use per
  domain, not globally — documented; mitigation = issuers should
  scope audiences (recommendation, not enforcement change).

## 13. CREDENTIAL / IDENTITY / ISSUER / GATEWAY REVOCATION — THE FOUR LAYERS

| event | credential | identity | delegation objects | lease objects | gateway |
|---|---|---|---|---|---|
| credential revoked | dead | active | usable via other live creds | usable | — |
| identity suspended | all 401 | dead | unusable | unusable | — |
| issuer revoked | — | — | every chain with its hops dies | its leases die | — |
| delegation revoked | — | — | that presentation dies | — | — |
| lease revoked (id) | — | — | — | that lease dies | — |
| gateway revoked | — | — | its audiences unanswerable | its audiences unanswerable | PoP fails, refuses service |
| gateway key revoked | — | — | (identity unaffected) | (identity unaffected) | new key required |

Four layers, four state machines, zero conflation — each row above is
a test case.

## 14. APPROVAL + CONTINUATION — EXECUTION-TIME RE-CHECK

P2.2 established: every claim/execute path passes identity-state
validation. P2.3 extends the SAME enforcement point:

At claim (orchestrator `drainQueue`) and at synchronous `execute`:
1. identity active? (exists — P2.2)
2. revocation state of recorded artifact ids: `lease_id` and the
   delegation presentation key recorded on the continuation at
   creation → consult revocation store → non-active → requeue/409
   (matching the P2.2 gate's semantics, never silent-skip).
3. `min_epoch` on the originating request, if present, vs current
   domain epoch.

Continuation schema addition (metadata, not a format break):
`capability_ids = {lease_id?, delegation_key?}` — recorded when the
continuation is created from the decision context. Approvals pending
when revocation lands: deny/stay-pending via the same check at resume
time; approvals never become a bypass around issuer/capability death.

## 15. PROXY

- Today: `gateway_url` + bearer token; plain HTTP; no pinning.
- P2.3: optional `gateway_pubkey` (hex ed25519) config pin —
  on startup the proxy challenges the gateway for a PoP over a
  nonce and fails closed on mismatch. Without the pin: URL+token
  trust, documented as such (no silent upgrade claimed).
- Gateway revoked/unavailable: proxy already fails closed on gateway
  errors (no transit without a decision) — semantics unchanged;
  revocation of the gateway makes PoP fail → transit denied.

## 16. RECEIPTS

Additive fields (backward-compatible; HMAC retained during
transition):

- `gateway_id` — which identity decided (exists implicitly; make
  explicit)
- `gateway_key_id` — which key signed → verifier picks pubkey from
  key history
- `trust_epoch` — domain revocation epoch at decision time → a
  receipt can be judged against the revocation view that produced it
- `gateway_sig` — ed25519 signature over the receipt's canonical
  fields (third-party-verifiable evidence; the property anchoring
  later needs)

Explicit non-claims: receipts remain internally signed evidence, not
externally immutable; anchoring is a later milestone; this format
change exists so anchoring is not blocked by a symmetric-only
signature.

## 17. ATTACK MATRIX

| # | attack | precondition | expected | P2.3 control | residual |
|---|---|---|---|---|---|
| 1 | copied filesystem (enrollment+key) | fs read | detectable not silent | duplicate-ID check-in conflict → alert/deny | clone executes until detected; TPM defers |
| 2 | copied config only | config read | deny | no private key → PoP fails | — |
| 3 | copied private key | targeted theft | deny+revocable | key revocation kills PoP | pre-revocation window |
| 4 | stolen enrollment credential | op cred leak | deny | operator-token scope unchanged; pinned-key enrollment | service mode TBD |
| 5 | enrollment replay | intercepted registration | deny | idempotent same-key re-join only; differing key rejected | — |
| 6 | duplicate gateway ID | squat attempt | deny | registry conflict → startup refusal | — |
| 7 | key rotation mid-flight | scheduled | seamless | grace window both keys verify; receipts carry key_id | — |
| 8 | revoked gateway | admin action | dead | PoP fails everywhere; self-halt | in-flight executions finish |
| 9 | compromised issuer (not yet revoked) | key theft | window | revocation statement ends it | window bounded by propagation |
| 10 | revoked issuer presented | post-revocation | deny | eval check order | — |
| 11 | revoked parent delegation | artifact revoked | deny | presentation-key revocation | — |
| 12 | revoked child delegation | artifact revoked | deny | same mechanism | — |
| 13 | stale revocation view | external mode lag | escalate | staleness budget + degrade-safe | embedded mode: n/a |
| 14 | network partition | external mode | escalate/deny | never silent-allow on capabilities | plain requests continue |
| 15 | split-brain gateways | separate domains | domain-scoped deny | audience binding | unscoped artifacts: per-domain once |
| 16 | rollback trust state | restore old files | detect+deny | epoch regression → fail closed | pre-epoch backup: documented |
| 17 | gateway impersonation | claims gw_id | deny | pinned-key or differing-key rejection | — |
| 18 | audience substitution | G1 artifact at G2 | deny | name-check then PoP-scoped meaning | full clone: §4 row 4 |
| 19 | cross-gateway replay | X at G2 | deny | audience mismatch or shared journal | unscoped artifacts per-domain |
| 20 | stale approval | approve-then-revoke | deny at execute | claim-time re-check | — |
| 21 | stale continuation | queue-then-revoke | deny at execute | claim-time re-check | in-flight runs to timeout |
| 22 | revoked capability + queued exec | cap revoked post-queue | never executes | claim-time re-check | — |
| 23 | revoked issuer + queued exec | issuer revoked post-queue | never executes | claim-time re-check | — |
| 24 | cred revoked + delegation | P2.2 semantics | 401 | auth boundary | objects live for identity |
| 25 | identity suspended + delegation | P2.2 semantics | 401 | auth boundary | — |

## 18. FORMAL INVARIANTS

| # | Property | Threat | Assumption | Enforcement | Verification | Failure mode |
|---|---|---|---|---|---|---|
| G1 | only key-proven endpoints answer for a gw_id | impersonation | registry file integrity | PoP+registry | challenge tests | startup refusal |
| G2 | one active identity per gw_id per domain | clone/squat | shared registry | conflict detection | dup-register → deny | deny + alert |
| G3 | audience = provable identity, not name | substitution | key bound in registry | validator+PoP | audience matrix | deny |
| G4 | enrollment needs operator authority + PoP | unauthorized gw | operator token | registry write+PoP | enroll tests | refuse start |
| G5 | key lifecycle deterministic; history preserved | theft/rotation | registry | key state machine | rotate/revoke tests | refuse start |
| G6 | revoked issuer never verifies post-propagation | compromise | domain store | eval check order | revoke→deny e2e | deny |
| G7 | revoked capability never authorizes new execution | replay-escape | domain store | eval + claim re-check | revoke→deny e2e | deny |
| G8 | revocation propagates within domain ≤ flock-commit | suppression | filesystem | shared file | same-domain tests | deny |
| G9 | stale/unavailable trust state degrades safe | partition | clock | budget+escalate | stale drills | escalate |
| G10 | no split-brain within a domain (one file) | split-brain | shared fs | flock | topology doc | n/a by construction |
| G11 | epoch regression detected | rollback | stored epoch | monotonic check | rollback drill | fail closed + CRITICAL |
| G12 | cross-domain artifacts never silently honored | confusion | audience scoping | validator | cross-domain e2e | deny |

## 19. WHAT THIS DESIGN DOES NOT CLAIM

- Clone-proof identity (needs TPM — deferred).
- Global at-most-once capability consume (per-domain only).
- Real-time cross-domain revocation (no replication implemented).
- Externally immutable receipts (anchoring deferred; format ready).
- Termination of running executions on revocation.
