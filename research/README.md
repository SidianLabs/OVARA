# Ovara Research

## Federated Identity Experiments

Exploring cross-organization machine identity without a central authority.

**Approach:**
- Ed25519-based self-issued identities
- Web of trust model for cross-org verification
- Trust path computation with configurable depth limits
- Revocation propagation via trust graph edges

**Findings:**
- DFS with depth limit of 10 provides good coverage (see `trust/internal/graph/`)
- Trust scoring works best when combining direct trust (0.7 weight) with path depth penalty (0.3 weight)
- Read-rich workloads benefit from periodic snapshot cache invalidation

## Trust Model Research

**Impact of federation topology on trust path quality:**
- Star topology: best latency, worst resilience
- Mesh topology: best resilience, highest path exploration cost
- Hub-and-spoke: balanced, recommended for multi-region deployment

## Performance Benchmarks

### Decision Latency (local, single gateway)
| Metric | Value |
|--------|-------|
| Policy-only decision | ~9.7 µs |
| With identity verification | ~10.7 µs |
| With trust-anomaly matching | ~10.7 µs |
| With capability lease | ~12.9 µs |
| Evaluator only (no HTTP) | ~2.7 µs |
| Load test p50 / p95 / p99 | ~340 µs / ~1.1 ms / ~1.9 ms |

### HMAC-SHA256 Signing
| Operation | Duration |
|-----------|----------|
| Receipt sign | ~620ns |
| Receipt verify | ~650ns |

### Throughput (local, single gateway)
- ~115,000 decisions/sec sustained (measured, loopback, 50-way concurrency)

Figures above are the current measured numbers from `docs/BENCHMARKS.md`
(Apple M4, Go 1.25). Earlier ~5–8µs figures were measured on a revision
without replay protection.
