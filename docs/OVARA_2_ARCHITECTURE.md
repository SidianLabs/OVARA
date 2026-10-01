# Ovara 2.0 — Proposed Architecture

Status: DESIGN (Phase B). Not implemented. Written against the actual
repository state — sections marked **[EXISTS]**, **[EXTEND]**, **[NEW]**,
or **[CONFLICT]** reflect what is real today, not what the spec wishes for.

## 1. Core thesis

> An autonomous agent may reason and act, but it must not be able to
> redefine the security boundary under which it acts.

Enforcement lives *outside* the agent environment. The agent's cooperation
is a usability feature, never a security property.

## 2. The five primitives

### A. Execution Identity — [NEW]

Every execution environment gets an immutable, operator-issued identity
record:

```json
{
  "execution_id": "exe_...",
  "agent_id": "agt_...",
  "tenant_id": "tnt_...",
  "image_digest": "sha256:...",
  "policy_version": "...",
  "boundary_version": "...",
  "issued_at": "...", "expires_at": "...",
  "parent_execution_id": null
}
```

- Issued by the **operator/Ovara at environment-creation time**, never
  self-asserted. Bound to the environment by what the environment *is*
  (netns name, container ID, image digest), not by what the agent claims.
- Consumed as `execution_id` on every event/receipt — the correlation key
  for `ovara timeline`.
- **[CONFLICT]** The current `AgentIdentity` (identity/internal/crypto) is
  a *cryptographic* identity for leases, not an environment identity. They
  are different concepts; do not conflate. Execution Identity is a
  deployment record; AgentIdentity is a signature-bearing principal.

### B. Mandatory Egress — [EXISTS, EXTEND]

- netns + nftables deny-all — implemented, tested live.
- docker `--internal` + DOCKER-USER + INPUT rules — implemented, tested live.
- Extend: IPv6 coverage for docker, capability-minimized agent launch
  (`ovara boundary agent-run` wrapper that applies cap-drop/seccomp
  instead of printing a recipe), `ovara doctor` verifying the boundary
  actually holds, escape-test suite as CI artifacts.
- **[CONFLICT]** Docker mode currently *prints* the hardened `docker run`
  recipe — it does not enforce it. A container launched without
  `--cap-drop ALL` on the same network still gets the network boundary
  (that part is enforced) but keeps full capabilities (process/fs
  boundary absent). 2.0 must wrap agent launch, not just document it.

### C. Credential Brokerage — [EXISTS, EXTEND]

- Today: env-var-backed host-glob bindings, HTTPS-only injection.
  Correctly absent from the agent by construction.
- Extend to a broker interface:

```go
type SecretProvider interface {
    Resolve(ctx context.Context, binding CredentialBinding) (http.Header, error)
}
```

  with providers: `env` (current), `file` (mounted secret dir), later
  Vault/KMS/OAuth-exchange. The injection path already isolates where
  secrets come from; the interface is a small diff.
- **[NEW REQUIREMENT — response scrubbing]** an allowed reflector host
  (httpbin.org/headers) can echo the injected `Authorization` back to the
  agent. The broker model must include optional **response-side
  redaction**: strip/scan upstream response bodies for the injected
  secret values before relaying to the agent. (Reflector-class exfil is
  currently open — see red-team findings.)

### D. Execution Provenance — [EXTEND]

- Today: proxy receipts cover `network_*` events only.
- 2.0: a **unified event schema** across proxy, gateway, boundary, broker:

```json
{
  "event_id": "...", "execution_id": "...", "tenant_id": "...",
  "timestamp_unixnano": ..., "event_type": "...",
  "severity": "info|warn|violation",
  "action": "...", "resource": "...", "decision": "...",
  "policy_version": "...", "boundary_version": "...",
  "prev_hash": "...", "signature": "sig_v1:..."
}
```

- One hash-chained event log per deployment (or per execution) — the
  receipt chain generalizes; existing `sig_v1` format is kept for
  network receipts, new event types join the same chain.
- `ovara timeline <execution_id>` renders the log as the forensic view.

### E. Independent Evidence — [EXISTS, EXTEND]

- Today: ed25519 `sig_v1` + `prev_hash` JSONL chain on the **host side**
  (already outside the agent's filesystem — correct placement),
  restart-resuming, fork-refusing, `-verify` offline, optional
  `OVARA_ANCHOR_FILE`/`OVARA_ANCHOR_URL` external anchoring.
- Extend: `ovara verify` as a first-class subcommand; anchor cadence +
  signed anchor records; document precisely what chain+anchor can and
  cannot prove (chain proves internal consistency; anchors bound history
  at anchor points; neither proves completeness if the boundary had a
  hole).
- **[DESIGN DEBT — deferred]** signing key co-located with chain and proxy
  process. Full key separation (KMS/HSM signer) is a v2.1 item; external
  anchoring is the interim mitigation and is documented as such.

## 3. New subsystem: Integrity Monitor — [NEW]

**Placement decision: host-side, always.** An integrity monitor inside
the agent environment would be self-defeating (the agent could kill it).
The monitor runs on the host, watching the agent environment from
outside:

- **Network posture**: periodic assertion of the boundary invariants —
  nft ruleset hash inside the ns/container matches what we installed;
  route table unchanged; no new interfaces; resolver config unchanged;
  no TUN/TAP devices. Violations → `boundary_violation` event + optional
  hard-kill of the environment.
- **Process posture**: Ovara proxy/gateway process liveness (PID,
  start-time — detects kill+restart); ptrace attachment detection
  (`/proc/*/status` TracerPid on Ovara processes); agent processes
  holding unexpected capabilities (`CapEff` scan).
- **Filesystem posture**: host-side watch (fanotify/inotify or periodic
  hash) on policy.json, proxy.json, config.json, var/*.key — the agent
  can't reach these anyway (they live on the host, not in the agent
  mount namespace), so this is really *operator/host* tamper detection.
  The agent-side equivalent (its own filesystem) is explicitly
  **untrusted** and not protected.
- Emits `integrity_*` events into the provenance chain. Fail mode:
  `CONTAINMENT NOT GUARANTEED` — the doctor/status surfaces it loudly.

## 4. Risk engine — [NEW, deliberately boring]

Deterministic, explainable, configured in policy — not a model:

```yaml
risk:
  unknown_destination: +30
  sensitive_host: +30
  prod_ref: +40
  credential_required: +20
  boundary_violation_context: +100
thresholds: { elevated: 30, escalate: 60, block: 90 }
```

Every decision emits `{"risk": N, "reasons": [...]}`. Maps to
allow/escalate/deny via thresholds. This is a scoring ruleset, not ML —
intentionally.

## 5. Approval binding — [EXTEND]

Approvals already bind to a continuation (agent, action, resource,
decision). 2.0 additionally binds the **request hash** (canonical
action-request digest) and policy version into the approval record and
the resume token, so an approval minted for request X cannot resume a
mutated request X'. Replay tests required.

## 6. Product surface — [EXTEND]

New subcommands on the single binary:

- `ovara doctor` — live diagnostics: boundary holds? DNS redirected?
  IPv6 off? caps absent? proxy reachable? creds not agent-visible?
  chain valid? → PASS/WARN/FAIL + `CONTAINMENT: VALID UNDER DOCUMENTED
  ASSUMPTIONS` or `NOT GUARANTEED`.
- `ovara verify <file>` — offline chain verification (moved from
  ovara-proxy -verify).
- `ovara timeline <execution_id>` — forensic view.
- `ovara boundary test` — non-destructive boundary self-check.
- `ovara redteam` — runs the escape suite against the live deployment.
- `ovara demo` — upgraded to the adversarial demo (agent inside a real
  boundary attempts the escape battery; results displayed as the spec's
  ATTEMPT/RESULT table).

## 7. What is explicitly out of scope for 2.0

- SAML production verification (needs XML-DSig lib — stays fail-closed)
- Postgres/SSH/gRPC data planes
- Kubernetes operator / Helm
- Dashboard wiring to live data
- KMS/HSM-backed signing (v2.1)
- gVisor/Firecracker tiers — architecture names the abstraction point
  (execution host) but does not implement it

## 8. Assumptions model

The system publishes `SECURITY_ASSUMPTIONS` (see THREAT_MODEL doc).
`ovara doctor` evaluates each assumption at runtime and degrades the
containment verdict when violated — never silently.
