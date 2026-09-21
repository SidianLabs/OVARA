# Phase 73 — Infrastructure & Deployment Checkpoint

## Branch
`phase-73-infrastructure`

## Goal
Production deployment infrastructure: Terraform K8s manifests, Docker Compose for full stack, multi-region topology, Dockerfiles for all services.

## Deliverables

### 1. Terraform K8s Manifests (`infrastructure/terraform/`)
- **main.tf** — Terraform config, Kubernetes provider, random cluster suffix
- **control_plane.tf** — 2-replica deployment, service, secret for env vars, liveness/readiness probes
- **gateways.tf** — Regional gateway deployment (replicas configurable 3-20), HPA with 70% CPU target, ConfigMap for gateway JSON config, data volume
- **postgres.tf** — PostgreSQL deployment with PVC (50Gi), credentials secret, health check
- **regions.tf** — Multi-region topology: us-east-1 (5), us-west-2 (3), eu-west-1 (4), ap-southeast-1 (3)
- **networking.tf** — Ingress with TLS (cert-manager), NetworkPolicy isolation for control plane and gateways
- **outputs.tf** — Exported endpoints and configuration

### 2. Docker Compose
- **docker-compose.full.yml** (`infrastructure/`) — Full production stack: control plane, gateway, PostgreSQL, NATS, ClickHouse, SSO, compliance — all with health checks and persistent volumes
- **docker-compose.yml** (`runtime/gateway/`) — Lightweight dev stack: single gateway with local config

### 3. Dockerfiles
- **Gateway Dockerfile** — Multi-stage Go 1.25 build, Alpine 3.20 runtime, ca-certificates, tzdata, healthcheck, CGO_ENABLED=0 static binary
- **Control Plane Dockerfile** — Multi-stage TypeScript build, Node.js 22 Alpine runtime, production-only deps, non-root user

## Infrastructure Design

| Component | Replicas | CPU Request | CPU Limit | Memory |
|-----------|----------|-------------|-----------|--------|
| Control Plane | 2 | 250m | 1 | 512Mi |
| Gateway | 3-20 (HPA) | 500m | 2 | 1Gi |
| PostgreSQL | 1 | 500m | 2 | 2Gi |

### Security
- NetworkPolicy isolates control plane to gateway+ingress ingress, postgres egress
- Gateway isolated to ingress-only ingress, control-plane-only egress
- Secrets for database credentials, JWT, API keys
- TLS via cert-manager and Let's Encrypt

## Files Changed
- `infrastructure/terraform/` — 8 files (main, control_plane, gateways, postgres, regions, networking, outputs, variables)
- `infrastructure/docker-compose.full.yml` — new
- `runtime/gateway/Dockerfile` — new
- `runtime/gateway/docker-compose.yml` — new
- `cloud/control-plane/Dockerfile` — new

## Next Phase
Phase 74 — Federated Trust Network: cross-org identity federation, portable receipts, trust graph APIs

Co-authored-by: CommandCodeBot <noreply@commandcode.ai>
