# v1 → redesign migration map (feat/ovara-redesign)

The redesign lives inside `runtime/gateway/` — same Go module, new
`core/` packages. v1 surfaces stay until merge; both are exercised.

| v1 surface | redesigned | status |
|---|---|---|
| `POST /v1/runtime/check` (unsigned ActionRequest) | `POST /v2/runtime/check` (edsig_v2-signed decide.Request) | live, verified |
| policy.json allow/deny + trust tiers | core_policy.json total-order rules (deny>escalate>require_cap>allow>default) | live |
| capability leases (`capabilities_file`) | attenuable block-chained tokens w/ epoch revocation | core pkg |
| receipts.jsonl (Ed25519, co-located anchors) | core_audit.jsonl write-ahead + signed Merkle checkpoints → anchor dir | live |
| proxy `gateway.Check` → /v1 | `SetRequestKey` → signed /v2 when `request_key_file` set | live |
| unsigned/decorative nonce | nonce inside signature + replay guard | live (see RT-R1) |
| 14-type open action vocabulary | closed 26-type vocab + canonical form enforced at engine | live |

## Agent-visible changes

- Requests must carry `signature: edsig_v2:<hex>` over
  `RequestCanonical()` (action + token + nonce + issued_at).
- Action must be in canonical form — sign AFTER canonicalizing, or the
  engine denies ("not in canonical form").
- ActorID is credential-derived; the wire value is overwritten
  server-side.
- Reason classes are coarse by design (deny_capability /
  deny_policy / deny_parse …) — operator detail lives in the audit.

## Operator-visible changes

- Config: `core_enabled`, `core_audit_file`, `core_anchor_dir`,
  `core_audit_key`, `core_actor_keys`, `core_issuer_keys`,
  `core_policy_file`. Enabled-without-key/file = startup refusal.
- Selftest runs at boot when enabled; failure refuses to serve.
- Anchors: signed Merkle checkpoints written to `core_anchor_dir`
  (off-host sink interface: `audit.Sink`).

## Retained v1 components

- MITM executor proxy machinery (CONNECT/ca/creds/receipts) — it now
  signs onto the core engine; the trust domain is unified.
- v1 endpoints stay for the differential corpus + rollback window.
  Removal is a post-merge cleanup decision.

## Residual gaps (honest)

- RT-R1: in-memory replay guard — replay within 60s across a restart.
- RT-R2: `action.Env` self-asserted for non-proxy callers.
- Sandbox layer (netns/seccomp/Landlock) not built — needs Linux.
- `raw.unknown` actions: evaluatable, default-deny in sane policies —
  they exist to LOG spec-gap attempts.
