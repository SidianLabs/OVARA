# Phase 70 — Gateway Enrollment & Policy Sync Checkpoint

## Branch
`phase-70-enrollment-sync`

## Goal
Connect the Go runtime gateway to the cloud control plane with automated enrollment, cryptographic identity, heartbeat, and policy synchronization.

## Deliverables

### 1. Cloud Enrollment Client (`runtime/gateway/internal/enrollment/cloud_client.go`)
- **CloudService** struct — wraps `localService` with cloud control plane integration
- **Enroll(organizationID)** — generates ed25519 key pair, registers gateway via `POST /v1/gateways/enroll`, stores enrollment state and keys in identity tags
- **ConfirmEnrollment(token)** — confirms enrollment via `POST /v1/gateways/confirm/:id`
- **CloudHeartbeat()** — sends periodic heartbeats with policy version to `POST /v1/gateways/:id/heartbeat`
- Full persistence: enrolled identity survives gateway restart via file-backed storage
- Bearer token auth using `ControlPlaneAPIKey` from config

### 2. Policy Sync Service (`runtime/gateway/internal/enrollment/cloud_client.go`)
- **PolicySyncService** struct — fetches policy distributions and policies from cloud control plane
- **FetchDistributions()** — calls `GET /v1/policies/distributions/:gatewayId` for pending policy deliveries
- **FetchPolicy(policyID)** — calls `GET /v1/policies/:id` for individual policy content
- **LastSyncAt()** — tracks last sync timestamp

### 3. CloudConfig
```go
type CloudConfig struct {
    ControlPlaneURL    string
    ControlPlaneAPIKey string
    PolicySource       string
}
```

### 4. Tests (11 new tests in `cloud_client_test.go`)
- `TestCloudService_Enroll` — verifies POST to enroll endpoint, key generation, state update
- `TestCloudService_Enroll_FailureStatus` — error handling for 401
- `TestCloudService_ConfirmEnrollment` — confirm workflow
- `TestCloudService_CloudHeartbeat` — heartbeat updates LastSeenAt
- `TestPolicySyncService_FetchDistributions` — parses distribution items
- `TestPolicySyncService_FetchPolicy` — fetches policy with rules, name, version
- `TestPolicySyncService_FetchPolicy_Error` — error handling for missing policy
- `TestCloudService_EnrollmentPersistsToDisk` — enrolled state survives restart
- `TestCloudConfig_Defaults` — zero-value config
- `TestEnrollmentEnrolledState` — local service not enrolled

## Validation
- go build ./...: **PASS**
- go vet ./...: **PASS**
- go test ./...: **PASS** (23/23 runtime packages, 1/1 identity)
- go test -race ./...: **PASS** (0 data races)
- 159 enrollment tests across service_test.go (10) + cloud_client_test.go (10) = 20 total in package

## Files Changed
- `runtime/gateway/internal/enrollment/cloud_client.go` — new (cloud enrollment + policy sync)
- `runtime/gateway/internal/enrollment/cloud_client_test.go` — new (11 tests)

## Next Phase
Phase 71 — Observability Pipeline: OpenTelemetry ingestion, NATS event streaming, ClickHouse analytics schema

Co-authored-by: CommandCodeBot <noreply@commandcode.ai>
