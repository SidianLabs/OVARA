# Prior-art survey — capabilities, policy, provenance, audit, sandboxes

Status: **skeleton + first pass, 2026-10-06**. Rows marked `needs-check` have
not been re-read against primary sources this session; do not cite until
checked (log in `state/claims_ledger.md`). Novelty claims require this table
complete with primary-source links.

Columns: system · mechanism · what it binds authority to · known limits ·
relevance to OVARA v2.

## Capability tokens / ambient-authority replacements

| system | mechanism | binds | limits | relevance | status |
|---|---|---|---|---|---|
| Object capabilities (Cap'n Proto, E, seL4-style) | unforgeable references; holding ref = authority | possession of the ref | needs object-cap substrate; delegation must be designed in | core mental model for P4/P5 | needs-check |
| macaroons (Google) | HMAC-chained caveats; attenuate-only delegation | caveat chain | caveats are contextual; verifier must know each caveat language | attenuation semantics for leases | needs-check |
| Biscuit | datalog facts + attenuation, crypto-verified | signed token + datalog eval | adoption thin | strong candidate format for v2 tokens | needs-check |
| SPIFFE/SPIRE | workload identity via SVID (X.509/JWT) | workload identity, not per-action | coarse: identity not action authority | identity layer comparison | needs-check |
| UCAN | JWT-ish capabilities w/ delegation proofs | issuer chain | revocation weak | delegation chain prior art | needs-check |

## Policy engines / languages

| system | mechanism | binds | limits | relevance | status |
|---|---|---|---|---|---|
| OPA / Rego | general-purpose policy, data+input query | arbitrary JSON policy | termination analysis exists; not negative-capability-shaped | differential-test oracle; POLICY.md compiler target? | needs-check |
| Cedar (AWS) | entity/action/resource model, formal analysis | schema'd entities | principal/resource model may not map to agent+tool | static analysis features to steal | needs-check |
| POLICY.md (SidianLabs) | Markdown+YAML negative-capability manifest | capability verbs | TS engine only; no Go consumer today | required input format for v2 compiler | VERIFIED (repo read) |
| Sentinel / IAM conditions | embedded policy DSLs | vendor-specific | — | contrast only | needs-check |

## Provenance / supply chain / audit

| system | mechanism | binds | limits | relevance | status |
|---|---|---|---|---|---|
| SLSA + in-toto | attestation of build steps, signed | artifact↔build | build-time, not runtime actions | receipt/decision-record format analog | needs-check |
| Sigstore / Rekor | transparency log for signatures | public anchoring | needs a log operator or self-host | external anchoring option for journal | needs-check |
| Certificate Transparency | append-only public logs + gossip | cert issuance | HTTP-centric | tamper-evidence model for anchors | needs-check |
| Hash-chained journals (QDB-style, AWS QLDB) | Merkle-chained ledger | server-side history | operator must not control both ends | v1 chain already; external anchor gap known | VERIFIED (v1 audit) |

## Agent sandboxes / mediation for LLM agents

| system | mechanism | binds | limits | relevance | status |
|---|---|---|---|---|---|
| gVisor / Firecracker / Kata | userspace-kernel or microVM isolation | syscall/VM boundary | heavier; still needs a policy layer on actions | executor substrate candidates | needs-check |
| seccomp-notify / Landlock | syscall interposition / fs restriction | syscall granularity | no semantic action model | kernel enforcement candidates (P1) | needs-check |
| Agent guardrail frameworks (various) | prompt/tool-call filters | tool-call surface | bypassable below the surface | the baseline v2 must beat (System A) | needs-check |
| IFC / taint for LLM agents (e.g. CaMeL-style designs) | label data, gate effects by label | data provenance | LLM context mixing is lossy | provenance layer (brief §6.1.5) | needs-check |
| OpenAI/Anthropic agent sandboxes (public docs) | container + network policy | process boundary | mostly documentational | deployment patterns | needs-check |

## To add next pass

- MAP (micro-agent-protocol) spec vs. OVARA receipt format comparison
- MCP authorization spec status; ACP (Agent Client Protocol) surface
- Academic: ConfusedDeputy lineage; Kerckhoffs-style eval-aware testing prior art;
  AuditBench + strategic-dishonesty results once claims_ledger verifies them.
