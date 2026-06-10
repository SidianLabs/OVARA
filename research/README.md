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
| p50 | 5μs |
| p95 | 8μs |
| p99 | 12μs |
| Policy-only (no identity) | 3μs |
| Identity + lease verification | 7μs |
| Full trust evaluation | 5-8μs |

### HMAC-SHA256 Signing
| Payload Size | Duration |
|-------------|----------|
| 64 bytes | 598ns |
| 1KB | 750ns |
| 10KB | 2.4μs |

### Throughput (local, single gateway)
- 200,000+ decisions/sec sustained
- 50,000+ receipts/sec with signing
- Memory: ~40MB baseline, ~120MB under load

### Concurrency
- Handlers scale linearly to ~10,000 concurrent decisions
- Continuation sweeper maintains sub-50ms pause time with 50,000+ records
