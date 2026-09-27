# Cross-Domain Action Lineage (demo scope)

**The gap.** A receiving party today cannot answer: *which chain of
authority produced this incoming agent action, and is it still valid?*
Intra-domain OVARA answers this for itself (signed receipts, chained
journals, delegation narrowing, claim-time revalidation) — but the
artifacts are stored evidence, not portable proof. Across domains there
was nothing: a counterparty had to trust the caller's claim of "my
gateway allowed this." This is the authority-provenance hole the July
2026 agent-intrusion landscape exposed: a receiving domain (Hugging
Face) had no way to ask the sender's domain "show me the authority
chain" and verify the answer offline. Honest scope note: that incident's
foothold was exploitation of unauthenticated surfaces — lineage gates
the *credentialed* slice (e.g. the hijacked third-party accounts used
as relay/staging), not an injection that presents no authority at all.

**The claim this document defines.**

> An OVARA-verified party can prove where an action's authority came
> from — decision, presented delegation, approval — *offline*, even if
> the issuing domain is later hostile.

The verifier needs no contact with the issuing domain, no shared
database, and no live network: only a **lineage bundle** (the
attestation) and a **trust anchor** (pinned keys + a revocation
snapshot). The transparency ledger turns each emitted stage into a
registered, linear, irrevocable statement (SCITT RFC 9943 semantics)
so later equivocation is visible to audit.

## 1. The lineage record — `lineage.Bundle`

One signed artifact, re-emitted and enriched at each authority
boundary. A decision emits `stage=decision`; an operator approval
re-emits `stage=approval`; an execution dispatch re-emits
`stage=execution`. Each emission supersedes the prior bundle for the
same `decision_id` and registers its own digest on the ledger, so the
ledger carries the lineage as a *timeline* and the final bundle is
self-contained.

```json
{
  "v": 1,
  "lineage_id": "lin_…",
  "domain_id": "dom-A",
  "stage": "execution",          // decision | approval | execution
  "issued_at": "…",
  "action": { "action_type": "github.push", "resource": "repo:x",
              "agent_id": "agent-7", "environment": "production",
              "request_digest": "sha256:…" },  // binds THIS request instance
                                               // (fields + nonce + issued_at)

  "receipt":     { /* models.Receipt, edsig_v1-signed at eval */ },
  "capability_lease":   { /* models.CapabilityLease as presented */ },
  "delegation_chain":   { /* models.DelegationChain, per-hop sigs */ },
  "approval":    { /* approval.ApprovalRequest, status approved */ },
  "approval_env":{ /* record.Envelope — the approver-signed journal
                        line that minted the approval */ },
  "execution":   { "continuation_id": "…", "execution_id": "…",
                   "state": "succeeded" },

  "inclusion":   { "ledger_domain": "…", "seq": 42, "parent": "…",
                   "digest": "<sha256>", "key_id": "…",
                   "sig": "lininc_v1:<hex>" },

  "gateway_id": "gw-…", "gateway_key_id": "…",
  "sig": "lin_v1:<hex>"          // Ed25519, gateway journal key
}
```

Rules:

- **Every element is already a signed artifact.** The receipt carries
  `edsig_v1` (Ed25519 over `receipt.SignedPayload`); each delegation
  hop carries its own signature (registry-verified); the approval is
  bound by `approval_env`, the journal envelope signed under the
  *approver-root* key (C2-B A1) — not the gateway key. The bundle
  doesn't re-mint these; it composes them and signs the composition.
- **`sig` covers everything except `inclusion`** (which cannot exist
  before registration). Domain-separated `OVARA-LINEAGE-BUNDLE-V1`,
  lp-framed — same canonical convention as `record`/`identity`.
- **The registered digest covers the *signed* statement** (bundle
  with `sig`, without `inclusion`): `sha256(json.Marshal(b sans
  inclusion))`. SCITT's transparent statement = signed statement +
  receipt; ours is the same shape with JSON instead of COSE/CBOR.
- `approval_env` is the C2-B A1 provenance primitive exported
  verbatim: the verifier resolves `env.key_ref` against pinned
  approver-role keys and verifies the envelope signature, proving the
  approval was minted by the approver root — a stolen `gateway.key`
  cannot manufacture it (the same attack the receipts-only design
  could not answer).

## 2. The publishing seam — transparency ledger

SCITT RFC 9943 roles mapped to this implementation:

| SCITT concept | This design |
|---|---|
| Signed Statement | a `Bundle` (sig, sans inclusion) |
| Transparency Service | `lineage.Ledger` — an append-only, Ed25519-signed, hash-chained journal under its own root key (the same `record.Journal` machinery every authority store uses) |
| Registration | `Ledger.Register(digest)` → appends `{seq, parent, digest}` |
| Receipt / Transparent Statement | `Inclusion` — ledger countersignature over `OVARA-LINEAGE-INCLUSION-V1 ‖ lp(ledger_domain) ‖ lp(digest) ‖ u64(seq) ‖ lp(parent)` |
| Verifier | `lineage.Verify` (offline) |

The demo ledger is local and file-backed (`lineage_ledger_file` +
`lineage_ledger_key_file`). It is deliberately *not* the gateway's own
journal: the ledger is a third party to the lineage — a separate
signing root. In production it is a remote service (SCRAPI-style
submit/receipt endpoints); the `Publisher` interface
(`Register(digest) → Inclusion`) is the seam, so swapping in an HTTP
transparency service changes the transport, not the format or the
verifier.

A **single inclusion proves "the ledger vouched this digest at
position N with parent T."** Chain-level properties (ordering,
non-rewritten history, no forks) are the *audit* path — the ledger's
own journal is inspectable via the same fold as every OVARA store,
and anchored per the tip-ledger scheme. An honest limit, not a hidden
one (see §5).

## 3. Emission (domain A)

Three call sites, all evidence-not-authorization (a failed emission
logs `SECURITY:` and never blocks the boundary — the same posture as
receipt persistence; the alternative is claiming transparency that
didn't happen):

1. **`recordDecision`** → `EmitDecision(req, receipt)` — binds the
   evaluated request's presented authority (lease + delegation chain,
   as received) to the freshly signed receipt.
2. **`handleApprove`/`handleDeny`-equivalent resolve path** →
   `EmitApproval(decision_id, approval, envelope)` — binds the
   approval record and its approver-signed journal envelope.
3. **orchestrator dispatch** → `EmitExecution(decision_id, execRef)`
   — binds the dispatch (continuation + execution record).

Each `Emit*` resolves the latest stored bundle for the `decision_id`
in the emitting domain's `lineage` journal (itself a signed,
tip-ledgered store), clones it forward, stamps the new stage, signs
(`lin_v1:<hex>` under the gateway journal key — custody-compatible:
a `record.RemoteSigner` keeps the key off-box), registers the digest,
and stores the final artifact.

Operational preconditions for each stage (verified e2e):

- **decision** — only emitted when the receipt persisted; requires all
  three `lineage_*` config paths AND durable gateway trust
  (`gateway_registry_file` + `gateway_key_file`) or startup fails.
- **approval** — the envelope comes from the signed approvals journal,
  so `approvals_file` must be set (an in-memory store has no envelopes
  → emit fails, logged, never blocks). Without an approver root
  (`approver_key_file`/`_pubkey` or the remote signer) bundles still
  emit, but the envelope is gateway-signed and `Verify` rejects at
  layer 7 — *verifiable* approval provenance needs the approver root.
- **execution** — requires a registered executor for the action type:
  no executor → the continuation requeues, no dispatch, no stage-3
  bundle.
- A stage emit for a decision with no prior decision bundle (its
  decision-stage emission failed earlier) refuses before
  sign/register — an unbound bundle would be unverifiable and
  unfoldable anyway.

## 4. The verifier contract (domain B) — `lineage.Verify(bundle, anchor)`

B pins a **trust anchor** — exported out-of-band (registry/anchor sync,
not from the artifact):

```go
type Anchor struct {
    DomainID      string                        // expected issuing domain
    GatewayKeys   map[string]ed25519.PublicKey  // gwid|keyid → pub
    IssuerKeys    map[string]ed25519.PublicKey  // trusted issuers
    ApproverKeys  map[string]ed25519.PublicKey  // approver key_id → pub (usable set)
    LedgerKeys    map[string]ed25519.PublicKey  // ledger domain → pub
    ExpectedAudience string                      // the audience hops/lease were minted for
    Revocations   map[revocation.Pair]bool      // revocation snapshot
    Epoch         uint64                        // snapshot epoch (informational)
}
```

Offline pass, fail-closed, first failure names the layer.

0. **request binding** (`VerifyDelivered`, receiver-side only) — the
   receiver recomputes `sha256` over the request IT actually received
   (action fields + nonce + issued_at, canonical `RequestDomain`
   preimage) and compares it to `action.request_digest`. Absent or
   mismatched → reject at `request`. Without this layer the bundle
   proves "domain A adjudicated an action of this shape"; with it,
   "domain A adjudicated THIS action" — a replayed bundle over a
   fresh nonce fails. `Verify` alone (steps 1–8) deliberately stays
   request-agnostic for evidence-only audits.

1. **shape/domain** — v, stage, domain == anchor.DomainID, action
   fields present. (A bundle from another domain cannot be replayed
   against B's anchor.)
2. **inclusion** — recompute `sha256(bundle sans inclusion)` ==
   `inclusion.digest`; resolve `inclusion.ledger_domain` in
   `anchor.LedgerKeys`; verify the countersignature.
3. **bundle signature** — resolve `(gateway_id, key_id)` in
   `anchor.GatewayKeys`; Ed25519-verify the canonical payload.
   Keys embedded in the artifact are never trusted — hints only.
4. **receipt** — `receipt.VerifySignature` (the existing edsig path)
   under the same resolved key; action fields must match `action`.
5. **delegation** — the *same* `identity.Validator` the evaluator
   runs: per-hop signatures under `anchor.IssuerKeys`, chain linkage,
   non-amplification, expiry, audience == `ExpectedAudience`, terminal
   subject == `action.agent_id`. Replay protection of the request
   itself is the receiver's `request_digest` recompute (step 0) —
   the lineage proves the chain *as evaluated* for that instance.
6. **lease** — same validator: signature under issuer key, subject
   binding, expiry, `ValidateCapabilityLeaseScope` covers the action.
7. **approval** (when present) — `status == approved`; decision /
   action / resource / agent context match; `approval_env` present
   with `key_ref.gateway_id == "approver"`; the key_id must resolve
   in `anchor.ApproverKeys` — a key that was revoked *before the
   snapshot* is absent there, so a revoked approver key mid-lineage
   **fails here**; the envelope signature verifies over
   `record.SigningPayload`, and `env.payload` must byte-equal the
   marshaled approval.
8. **revocation view** — every derivable revocation pair (lease id,
   per-hop presentation keys and issuers — `identity.ChainRevocationIDs`,
   plus the approval's recorded pairs) checked against
   `anchor.Revocations`: any hit → reject. This is the "is it still
   valid?" half — validity is judged under B's pinned view, not A's
   say-so.
9. **accept** — `Verdict{Accept: true, Layers: […]}` names every layer
   passed; rejection names the failing layer and why.

"The chain produced the action" is established by the composition:
bundle sig binds receipt+materials ⇒ receipt is A's own signed
decision ⇒ presented authority passes the real eval-side validator ⇒
approval (if required) is approver-root-proven ⇒ the whole statement
was ledgered — all under B's pinned keys, zero trust in A's honesty.

## 5. Honest limits — what this does NOT solve

- **Counterparty adoption.** Value requires counterparties to emit
  bundles AND receiving parties to verify. A domain that doesn't run
  this emits nothing; B's honest answer is "no lineage," not "trusted."
- **A compromised issuer/gateway root still poisons its own domain.**
  Lineage shows the chain faithfully; it cannot show the root was
  honest while signing it. The mitigation is boundary-only: the
  approver-root split (C2-B A1/A2) shrinks what a stolen gateway key
  can fabricate, and the revocation view lets B act on
  post-compromise kills — but a key trusted at snapshot time that was
  already malicious writes a valid-looking chain. Revocation is the
  correction mechanism, not the prevention one.
- **Ledger availability is a new dependency.** Emission fails open
  (logged) — a bundle can exist without inclusion, and verifiers that
  require inclusion reject it. The ledger is a *third-party*
  dependency for the verify side as well: B trusts the pinned ledger
  key. A lying ledger can mint inclusions for arbitrary digests —
  it cannot forge bundle signatures, so the blast radius is "claims
  of registration," not "claims of authority."
- **The pinned view goes stale.** `Revocations`/`ApproverKeys` are a
  snapshot: B must refresh anchors on a cadence it chooses, or accept
  that "still valid" means "valid as of epoch E." Cross-domain
  anchor/revocation sync transport is out of scope here.
- **Replay/freshness of the presented chain** is unverifiable
  offline (the hop-nonce protocol runs at eval inside A). B sees that
  A validated the chain, not that the chain wasn't replayed from a
  stolen artifact — though every hop signature is still required to
  verify. The *request* side is bound: `request_digest` commits to
  the request's nonce+issued_at, so a replayed bundle over a fresh
  request fails `VerifyDelivered` — but the digest covers the
  declared request fields, not the wire bytes beyond them; a
  counterparty whose request shape differs must map the same fields.
- **Execution truth.** Like receipts, the lineage attests the
  authority boundary crossed, not what the executor's bytes actually
  did (RVI-class limitation — unchanged).
- **Not COSE/CBOR.** The format is JSON+Ed25519, not SCITT's wire
  encoding: this is the *architecture* (statement → registration →
  receipt → verify), not wire compatibility with a real transparency
  service. Interop requires the Publisher seam to emit COSE receipts
  — a transport adapter, explicitly deferred.

## 6. Demo

`internal/lineage/lineage_test.go` builds two domains in-process:
domain A's gateway emits lineage through decision → approval →
execution against a file-backed ledger; domain B verifies the final
bundle offline. The adversarial suite asserts forged bundle, truncated
chain, untrusted issuer, revoked-approver mid-lineage, tampered
inclusion, wrong-domain presentation, and a mismatched/stripped
`request_digest` each reject at the named layer, and the honest
bundle accepts.

`cmd/linverify` is the receiver-side CLI: `linverify -bundle b.json
-anchor a.json [-request r.json]` prints the layered verdict JSON and
exits non-zero on reject. The anchor file is the JSON form of
`Anchor` — `domain_id`, `gateway_keys` (`"gwid|keyid": hex-pub`),
`issuer_keys`, `approver_keys` (`key_id`), `ledger_keys`
(`ledger_domain`), `expected_audience`, `revocations`
(`[{class,target}]`), `epoch`. With `-request` it runs
`VerifyDelivered`, adding the `request` layer over the request the
receiver actually got. The wire form is `lineage.AnchorFile` — shared
between the exporter and linverify, so the format is defined once.

`gwctl export-anchor` is the hand-off seam that produces the anchor
file — no hand-assembly of pins:

```
gwctl export-anchor --registry gateway_registry.json \
    --ledger-key lineage_ledger.key [--gateway-id G] \
    [--config config.json] > anchor.json
```

It folds the domain registry for the derived `domain_id`, the
currently-usable gateway keys, the approver pins, the revocation
snapshot, and the journal-seq `epoch`; reads the lineage ledger's
public key out of its private key file (`--ledger-key`, strictly
read-only); and pulls issuer pins from the gateway config's
`trusted_issuers` (`--config`). `expected_audience` is the gateway
identity the ledger/bundles attribute to. Only keys usable at export
time are pinned — what a receiver holds is a snapshot of the domain's
trust view, refreshed on whatever cadence B chooses; the export never
mints or guesses keys it cannot derive, and an absent pin is a hard
absence, not a silent skip.

`scripts/lineage_two_domain.sh` (`make demo-lineage`) is the runnable
version of this section's story with real processes: it boots domain
A's gateway on throwaway state (approver root pinned via `gwctl
genkey`), runs one shell action through check → approval →
orchestrated execution, extracts the execution-stage bundle (each
stage enriches the decision bundle, so the final one carries every
layer), exports B's pinned anchor, then proves:

- honest bundle + delivered request → ACCEPT under `VerifyDelivered`,
- a same-length tamper → REJECT at `inclusion` (the statement digest
  covers every signed byte),
- a nonce-swapped delivered request → REJECT at `request`,
- `gwctl retire` + a fresh export → REJECT at `signature` (the key is
  no longer pinned),
- the pinned anchor → still ACCEPT — B proves the history it saw even
  after the key that signed it is dead.

The second domain needs no gateway of its own: B's side is `gwctl
export-anchor` + `linverify` over the two artifacts — verification is
offline by design.
