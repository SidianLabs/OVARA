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

## Baseline (local, single gateway)
| Metric | Value |
|--------|-------|
| Decisions/sec | 200,000+ |
| p50 latency | 5μs |
| p95 latency | 8μs |
| p99 latency | 12μs |
| Error rate | 0% |
| Memory | ~40MB |
