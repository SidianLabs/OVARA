# Benchmarks

Measured on Apple M4 (`darwin/arm64`, Go 1.25), 2026-09-16. Two tiers:

- **Microbenchmarks** — in-process `testing.B` benchmarks of the decision
  pipeline. Not end-to-end, not network latency.
- **Load test** — real HTTP through `httptest.NewServer`, keep-alive
  connections, 50-way concurrency.

Reproduce:

```bash
cd runtime/gateway
go test -bench=. -benchtime=1s -count=3 -run='^$' ./internal/handlers/
go test ./tests/load/ -v
```

## Decision path (median of 3 runs)

Every request carries `nonce` + `issued_at` and passes replay/freshness
checks — this is the full production path.

| Benchmark | Latency | What it covers |
|-----------|---------|----------------|
| `RuntimeCheck_PolicyOnly` | ~9.7 µs | HTTP handler → validate → replay check → evaluate → respond (in-process `httptest`, no network) |
| `RuntimeCheck_WithIdentity` | ~10.7 µs | + agent identity verification |
| `RuntimeCheck_WithTrustAnomaly` | ~10.7 µs | + trust anomaly pattern matching |
| `RuntimeCheck_WithCapabilityLease` | ~12.9 µs | + capability lease validation |
| `Evaluator_Evaluate` | ~2.7 µs | Evaluator only, no HTTP |
| `Evaluator_Evaluate_Risky` | ~2.8 µs | Evaluator only, anomaly-matching input |

## HTTP throughput (real server, keep-alive)

`tests/load` with `Concurrency: 50`, 5s duration:

| Metric | Value |
|--------|-------|
| Throughput | ~115,000 decisions/sec |
| Error rate | 0% |
| p50 latency | ~340 µs |
| p95 latency | ~1.1 ms |
| p99 latency | ~1.9 ms |

## Cryptographic primitives

| Operation | Latency |
|-----------|---------|
| HMAC-SHA256 receipt sign | ~620 ns |
| HMAC-SHA256 receipt verify | ~650 ns |
| Decision cache put | ~39 ns |
| Decision cache get | ~40 ns |

## Notes and caveats

- **Not end-to-end.** `RuntimeCheck_*` uses `httptest.NewRecorder` in-process;
  add real network latency for deployed measurements. The load test uses a
  real socket on localhost but no TLS, no proxies.
- **Earlier figures.** README/delivery-report/website previously showed
  ~5–8 µs decision paths and ~1.3 µs evaluator calls, measured on an earlier
  revision without replay protection. Numbers above are current. Crypto and
  cache figures are unchanged.
- **Capacity planning.** Single gateway: ~115k decisions/sec on-loopback is
  the measured ceiling under the load test's request mix. Real deployments
  with TLS, network hops, and heavier policies will be lower — run
  `tools/benchmarks` against a live gateway for environment-specific numbers.
