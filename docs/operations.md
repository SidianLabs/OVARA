# Ovara Operations Runbook

## Service Overview

The Ovara Runtime Gateway is a single-binary Go service providing:
- Runtime policy evaluation (allow/deny/escalate)
- Machine identity and capability lease verification
- Action execution orchestration (shell, exec, git)
- Cryptographic receipt issuance
- Trust scoring with anomaly detection

## Startup

The gateway starts immediately on `go run ./cmd/server/` or the compiled binary. On startup it:
1. Loads configuration from `OVARA_CONFIG` (default: `etc/config.json`)
2. Initializes enrollment (local or remote)
3. Loads policy rules
4. Starts file watchers for hot policy reload
5. Starts the continuation orchestrator (begins polling queued continuations)
6. Sweeps stuck executing continuations from previous crash
7. Starts the expiration sweeper
8. Begins listening on the configured port

## Health Monitoring

### Liveness: `GET /ready`
Returns `{"status":"ready"}` if the HTTP server is accepting requests.

### Health: `GET /health`
Returns `{"status":"ok"}` for basic health.

### Runtime Health: `GET /v1/runtime/health`
Returns:
```json
{
  "healthy": true,
  "sla": {
    "approvals_breaching": 0,
    "retryable_breaching": 0,
    "executing_breaching": 0,
    "approval_threshold_min": 30,
    "retryable_threshold_min": 60,
    "executing_threshold_min": 5
  },
  "queue_paused": false,
  "maintenance_mode": false
}
```

### Status: `GET /v1/runtime/status`
Full status dump including enrollment state, policy version, storage mode, event/continuation/execution counts, orchestrator queue depth, and shield state.

## Alerting Rules

| Metric | Threshold | Action |
|--------|-----------|--------|
| `approvals_breaching > 0` | SLA breach | Review pending approvals, notify operators |
| `retryable_breaching > 5` | Backlog | Check orchestrator, review executor health |
| `executing_breaching > 0` | Stuck execution | Run recover-executing endpoint |
| `queue_stats.queued > 100` | Queue backlog | Check available executors, increase poll rate |
| `shield_restricted_agents > 0` | Active containment | Review restricted agents |
| `/ready` non-200 | Service down | Restart gateway |

## Recovery Procedures

### Recover Stuck Executions

Continuations stuck in `executing` state (from crash or stalled executor):
```bash
# Dry run — see what's stuck
curl -X POST "http://localhost:8080/v1/continuations/recover-executing?dry_run=true"

# Recover all stuck continuations
curl -X POST "http://localhost:8080/v1/continuations/recover-executing"

# Recover only continuations stuck > 10 minutes
curl -X POST "http://localhost:8080/v1/continuations/recover-executing?older_than_minutes=10"

# Recover a single stuck continuation
curl -X POST "http://localhost:8080/v1/continuations/{id}/recover-executing"
```

### Pause/Resume Orchestrator

When performing maintenance that requires pausing automatic execution:
```bash
# Pause (stop picking up new continuations)
curl -X POST "http://localhost:8080/v1/continuations/queue/pause"

# Resume
curl -X POST "http://localhost:8080/v1/continuations/queue/resume"
```

### Clear Agent Restrictions

```bash
# View all restricted agents
curl "http://localhost:8080/v1/shield/status"

# Unrestrict a specific agent
curl -X POST "http://localhost:8080/v1/shield/unrestrict/{agent_id}"
```

### Policy Reload

If hot reload is enabled, policies reload automatically on file change. To force reload:
```bash
# Policy reload is file-watch driven; ensure file is updated
# Check current policy version
curl "http://localhost:8080/v1/runtime/status" | jq .policy_version
```

## Log Analysis

Decisions are logged to `var/log/decisions.jsonl` (one JSON line per decision):
```bash
tail -f var/log/decisions.jsonl | jq .
```

Events are stored in `var/data/events.jsonl`:
```bash
# Count events by type
cat var/data/events.jsonl | jq -r '.event_type' | sort | uniq -c | sort -rn
```

## Retention and export

The receipt chain is append-only and verified whole: `ovara log`, `ovara
log export`, the incident bundle and every run's attestation read it from
the first line. It grows with every request (a few hundred bytes each),
and a deployment that runs for months should plan for that rather than let
one file carry a year. `ovara doctor` says how big it is and warns past
256 MiB.

What keeps the record whole and checkable:

- **Export on a schedule.** `ovara log export -since <last export time>
  -out receipts-<date>.jsonl` (JSONL: the signed lines, unchanged) or
  `-format ocsf` for a SIEM. Exported lines verify on their own with the
  public key and, for a cut, a `segment.json` naming where it starts (what
  the incident bundle writes). A cron line that keeps the last day:

  ```
  15 0 * * *  ovara log export -dir /srv/ovara -since "$(date -u -d yesterday +%Y-%m-%dT00:00:00Z)" -out /srv/ovara-archive/receipts-$(date -u +%F).jsonl
  ```

- **Bundle before you rotate.** `ovara incident bundle -dir D -out
  case.tar.gz` packs the chain, anchors, key history, policy and the
  attestations; it verifies offline, and it is what you hand to an auditor.
- **Rotate the deployment, not the file.** To start afresh, stop Ovara,
  bundle, and begin a new deployment directory (`ovara init`) for new
  runs; keep the old one read-only. Do not cut the live chain by hand: the
  resume check refuses a chain whose start does not match its anchors, and
  that is the point of it.
- **Attestations** are one small file per run under `var/attestations`;
  they travel with the bundle and can be archived with the exports.

Receipt keys: rotate them on a schedule of your own (`ovara keys
rotate-receipt`); the history keeps older receipts verifiable.

## Performance Baseline

On Apple M4:
- Decision evaluation: ~5-8μs (full HTTP path including identity/capability/trust)
- HMAC-SHA256 signing: ~600ns
- Decision cache: ~40ns per get/put
- Concurrent orchestrator: 2s poll interval, goroutine-per-continuation

## Troubleshooting

### Gateway won't start
1. Check `OVARA_CONFIG` points to valid config file
2. Verify Go version: `go version` (requires 1.25+)
3. Check port availability: `lsof -i :8080`

### Continuations stuck in "escalated"
No one has approved them. Check pending approvals:
```bash
curl "http://localhost:8080/v1/approvals?status=pending"
```

### Executor not running
Check executor registration in logs. The gateway registers `shell`, `exec`, `git.push`, `git.pull`, `git.fetch`, `git.checkout` executors. Unknown action types are skipped with `SKIP no executor` log message.

### High latency in /v1/runtime/check
1. Check decision cache size: `/v1/runtime/status` → `decision_cache_count`
2. Review trust evaluator patterns: risky shell patterns add ~200ns
3. Check policy rule count: many rules mean more iteration
