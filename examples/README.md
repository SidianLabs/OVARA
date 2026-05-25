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
   OVARA_CONFIG=./examples/sample_config.yaml ./start_gateway.sh
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
| `OVARA_PORT` | `8080` | Gateway port |
| `OVARA_CONFIG` | `` | Path to config file |
| `OVARA_POLICY_FILE` | `` | Path to policy JSON |
| `OVARA_POLICY_REFRESH_INTERVAL` | `0` | Policy hot reload interval (seconds) |

## Scripts Overview

### `start_gateway.sh`
Starts the gateway with sensible defaults. Must be run from repo root.

### `demo_safe_shell.sh`
Exercises shell commands. By default, ALL shell commands escalate (require approval) in the default policy. This script is useful for verifying the escalation flow works correctly.

### `demo_risky_shell.sh`
Exercises risky shell patterns that trigger escalate decisions. Demonstrates:
- Dangerous patterns (`curl |sh`, `rm -rf /`)
- Git force push escalation
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

### `sample_policy.json`
Sample policy file for testing hot reload. Configure with:
```bash
OVARA_POLICY_FILE=./examples/sample_policy.json OVARA_POLICY_REFRESH_INTERVAL=10 ./start_gateway.sh
```

### `sample_policy_local.json`
A "local dev" policy profile. Note: The current policy engine does not support Allow rules for shell actions - all shell commands escalate by default policy. This file is provided for future use when Allow rules are implemented.

### `sample_config.yaml`
Sample gateway configuration file.

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