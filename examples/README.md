# OVARA Runtime Gateway - Demo Scripts

This directory contains scripts for exercising the OVARA Runtime Gateway flows.

## Prerequisites

- Go 1.21+ installed
- Gateway service running at `localhost:8080` (or set `GATEWAY` env var)

## Quick Start

1. **Start the gateway:**
   ```bash
   ./start_gateway.sh
   ```
   Or with custom config:
   ```bash
   OVARA_CONFIG=../../examples/sample_policy_local.json ./start_gateway.sh
   ```

2. **Run demo scripts:**
   ```bash
   ./demo_safe_shell.sh
   ./demo_risky_shell.sh
   ./demo_restricted_agent.sh
   ./demo_approval_flow.sh
   ./demo_inspection.sh
   ```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `GATEWAY` | `http://localhost:8080` | Gateway base URL |
| `OVARA_PORT` | `8080` | Gateway port (used by start_gateway.sh) |
| `OVARA_CONFIG` | `` | Path to config JSON file |
| `OVARA_ENVIRONMENT` | `local` | Gateway environment (local, dev, production) |

Note: Policy configuration is done via the config JSON file (`policy_file` and `policy_refresh_interval` fields), not environment variables.

## Scripts Overview

### `start_gateway.sh`
Starts the gateway with sensible defaults. Must be run from repo root.

### `demo_safe_shell.sh`
Exercises shell commands. By default, shell commands in `local` environment are allowed. Use `demo_approval_flow.sh` to see the escalation workflow.

### `demo_risky_shell.sh`
Exercises risky shell patterns that trigger escalate decisions:
- Dangerous patterns (`curl |sh`, `rm -rf /`)
- Production targeting

### `demo_restricted_agent.sh`
Demonstrates the restriction flow:
- Check shield status
- Restrict an agent
- Verify restricted behavior
- Unrestrict agent

### `demo_approval_flow.sh`
Full approval workflow:
1. Trigger escalate decision
2. Create approval
3. Approve (with admin identity)
4. Resume approved action

### `demo_inspection.sh`
Inspection endpoints demo:
- Gateway status
- Trust context
- Shield status
- Receipts
- Decision lookup

### `sample_config.json`
Sample gateway configuration in JSON format. Configure with:
```bash
OVARA_CONFIG=./examples/sample_config.json ./start_gateway.sh
```

### `sample_policy.json`
Sample policy file with rules for supported action types (`shell`, `exec`, `git.push`, `git.pull`).

### `sample_policy_local.json`
A "local dev" policy profile demonstrating all three outcomes (allow, deny, escalate):
- `shell` + `local` → allow (harmless read-only)
- `shell` + `production` → deny (too risky)
- `shell` + `dev` → escalate (risky but recoverable)
- `git.pull` + `*` → allow (read-only, always safe)
- `exec` + `*` → escalate (direct subprocess, always requires approval)

## Enrollment and Status

The gateway maintains a local enrollment identity stored in `var/data/enrollment.json`. The status endpoint shows:
- `gateway_id`, `gateway_name`, `gateway_version` from enrollment
- `enrollment_state` (always `local` in v1)
- `last_seen_at` (updated by heartbeat every 30s by default)
- `pending_approval_count`, `shield_restricted_agents`, `shield_total_agents`

Check enrollment status:
```bash
curl -s http://localhost:8080/v1/runtime/status | jq '{gateway_id, enrollment_state, last_seen_at}'
```

## Common Patterns

**Override gateway URL:**
```bash
GATEWAY=http://other-host:9090 ./demo_safe_shell.sh
```

**Run with custom agent:**
```bash
./demo_safe_shell.sh my-custom-agent-id
```

**Check JSON output with jq:**
```bash
curl -s http://localhost:8080/v1/runtime/status | jq .
```

## Troubleshooting

- **Connection refused:** Gateway not running. Start with `./start_gateway.sh`
- **Empty responses:** Gateway may be on different port. Check `GATEWAY` env var
- **Permission errors:** Ensure you have write access to the gateway directory
