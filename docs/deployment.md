# Ovara Deployment Guide

## Overview

Ovara Runtime Gateway is a single-binary Go service that provides runtime trust infrastructure for autonomous systems. It intercepts agent actions, validates machine identity and capability leases, evaluates policy rules, computes trust signals, and produces cryptographic receipts.

## Prerequisites

- Linux (amd64/arm64) or macOS (arm64)
- Go 1.25+ (for building from source)
- 512 MB RAM minimum, 2 GB recommended
- Local filesystem for persistence (no external database required)

## Build

```bash
cd runtime/gateway
go build -o ovara-gateway ./cmd/server/
```

### Cross-compile for Linux

```bash
GOOS=linux GOARCH=amd64 go build -o ovara-gateway ./cmd/server/
```

## Configuration

Create `etc/config.json`:

```json
{
  "server_port": "8080",
  "gateway_id": "gw_prod_001",
  "gateway_name": "production-gateway",
  "gateway_version": "1.0.0",
  "policy_version": "v1-prod",
  "policy_file": "etc/policy.json",
  "policy_refresh_interval": 0,
  "fail_closed": false,
  "auth_enabled": true,
  "operator_tokens": ["sk_operator_token_here"],
  "receipt_signing_key": "your-secret-signing-key-min-32-chars",
  "decision_log_file": "var/log/decisions.jsonl",
  "events_file": "var/data/events.jsonl",
  "continuations_file": "var/data/continuations.jsonl",
  "execution_file": "var/data/executions.jsonl",
  "receipts_file": "var/data/receipts.json",
  "approvals_file": "var/data/approvals.json",
  "capabilities_file": "var/data/capabilities.json",
  "execution_working_dir": "/tmp/ovara-exec",
  "execution_stdout_limit_bytes": 1048576,
  "execution_stderr_limit_bytes": 262144,
  "sla_approval_max_age_min": 30,
  "sla_retryable_max_age_min": 60,
  "sla_executing_max_age_min": 5,
  "stuck_executing_sweep_interval_secs": 300,
  "stuck_executing_recovery_threshold_min": 30
}
```

## Directory Structure

```
ovara-runtime/
├── etc/
│   ├── config.json         # Gateway configuration
│   └── policy.json         # Policy rules
├── var/
│   ├── data/               # Persistent data stores
│   └── log/                # Decision and event logs
├── ovara-gateway           # Binary
```

## Running

### Direct

```bash
export OVARA_CONFIG=etc/config.json
export OVARA_ENVIRONMENT=production
./ovara-gateway
```

### systemd

```ini
# /etc/systemd/system/ovara-gateway.service
[Unit]
Description=Ovara Runtime Gateway
After=network.target

[Service]
Type=simple
User=ovara
Group=ovara
WorkingDirectory=/opt/ovara
Environment=OVARA_CONFIG=/opt/ovara/etc/config.json
Environment=OVARA_ENVIRONMENT=production
ExecStart=/opt/ovara/ovara-gateway
Restart=always
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

```bash
sudo useradd -r -s /bin/false ovara
sudo systemctl daemon-reload
sudo systemctl enable ovara-gateway
sudo systemctl start ovara-gateway
sudo journalctl -u ovara-gateway -f
```

### Docker

```dockerfile
FROM golang:1.25-alpine AS builder
WORKDIR /build
COPY . .
RUN cd runtime/gateway && CGO_ENABLED=0 go build -o /ovara-gateway ./cmd/server/

FROM alpine:3.20
RUN adduser -D ovara
COPY --from=builder /ovara-gateway /usr/local/bin/ovara-gateway
RUN mkdir -p /opt/ovara/etc /opt/ovara/var/data /opt/ovara/var/log && chown -R ovara:ovara /opt/ovara
USER ovara
WORKDIR /opt/ovara
EXPOSE 8080
CMD ["ovara-gateway"]
```

```bash
docker build -t ovara-gateway:1.0.0 .
docker run -p 8080:8080 \
  -v $(pwd)/etc:/opt/ovara/etc:ro \
  -v $(pwd)/var:/opt/ovara/var \
  -e OVARA_CONFIG=/opt/ovara/etc/config.json \
  ovara-gateway:1.0.0
```

## Health Checks

```bash
# Liveness
curl http://localhost:8080/ready
# {"status":"ready"}

# Health with SLA
curl http://localhost:8080/health
# {"status":"ok"}

# Runtime health with SLA diagnostics
curl http://localhost:8080/v1/runtime/health
# {"healthy":true,"sla":{"approvals_breaching":0,...}}

# Full status
curl http://localhost:8080/v1/runtime/status
```

## Scaling

Ovara is designed as a local-first single-binary gateway. For high availability:

1. Run multiple instances behind a load balancer
2. Each instance maintains its own local state (decisions, receipts, events)
3. Share policy via a shared filesystem (NFS) or config management
4. Use consistent operator tokens across instances

## Backup & Recovery

Back up the `var/` directory:
```bash
tar -czf ovara-backup-$(date +%Y%m%d).tar.gz var/
```

To recover stuck continuations after restart:
```bash
curl -X POST "http://localhost:8080/v1/continuations/recover-executing"
```

## Monitoring

Key metrics endpoint:
```bash
curl http://localhost:8080/v1/runtime/metrics
```

Track:
- `total_decisions`: Decision throughput
- `avg_latency_ms`: Policy evaluation latency
- `decision_counts.allow/deny/escalate`: Decision distribution
- `approvals_breaching`: Pending approvals exceeding SLA
- `executing_breaching`: Stuck executions exceeding SLA
- `queue_stats.queued`: Orchestrator backlog depth
