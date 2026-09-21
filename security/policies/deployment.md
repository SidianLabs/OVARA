# OVARA Security Policy Templates

> **Status: ASPIRATIONAL / TEMPLATE.** The items below describe a target
> deployment posture, not features that all exist today. Items marked
> **(implemented)** are in code; the rest are operator responsibilities or
> roadmap items. Do not cite this document as evidence a control exists.

## Gateway Deployment
- (implemented) Run as non-root user; no privileged escalation; drop all
  capabilities — see `security/apparmor` and `security/sandbox` templates.
- (implemented) Seccomp allowlist for container runtimes —
  `security/sandbox/seccomp-profile.json`.
- (template) AppArmor profile — `security/apparmor/ovara-gateway` is a
  starting template requiring per-deployment tuning.

## Control Plane
- (template) TLS 1.3 minimum for all listener surfaces.
- (template) mTLS for gateway-to-control-plane communication — NOT currently
  implemented in the gateway; terminate TLS/mTLS at a reverse proxy until it is.
- (template) API keys rotated every 90 days; secrets in a secrets manager,
  never in config maps.
- (implemented) Gateway bearer-token auth (`auth_enabled` + `operator_tokens`).

## Data at Rest
- (template) PostgreSQL: encryption at rest (LUKS or KMS) — operator concern.
- Receipt storage: receipts are **HMAC-SHA256 signed** (`sig_v1`), NOT
  AES-256-GCM encrypted. At-rest encryption of receipt files is an operator
  responsibility.
- (template) Backup encryption required.

## Audit
- (implemented) Decisions and lifecycle events are recorded in the gateway
  event store (`/v1/audit/export` for export) and receipts are signed.
- (template) "audit_log" table in the control plane — aspirational; today
  audit records live in the gateway event store and any collector pipeline
  (see `telemetry/`).
