# Ovara CLI Benchmarks

Run against a running gateway:

```bash
go run cmd/benchmark/main.go \
  --target http://localhost:8080 \
  --duration 30s \
  --concurrency 50
```

Reports:
- Decisions/sec throughput
- p50/p95/p99 latency
- Error rate
- Policy cache hit rate
- Memory usage

## Baseline

See [`docs/BENCHMARKS.md`](../../docs/BENCHMARKS.md) for verified numbers.
The previously listed baseline (200k decisions/sec, 5μs p50) was never
reproduced and has been removed — run the tool against a live gateway for
real figures.
