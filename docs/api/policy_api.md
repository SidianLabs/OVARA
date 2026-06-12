# Policy API

The Policy API provides runtime introspection and management of policy
rules in the Ovara Runtime Gateway.

## Data Model

A policy is a JSON document with a version and an ordered list of
rules. The gateway applies rules in order; the first matching rule wins.
If no rule matches, the gateway's default is to **escalate** (require
human approval).

```json
{
  "version": "v1",
  "rules": [
    {
      "action_type": "shell",
      "environment": "local",
      "allow": true,
      "description": "Local shell commands are allowed"
    },
    {
      "action_type": "*",
      "environment": "production",
      "escalate": true,
      "description": "Catch-all: all actions in production require approval"
    }
  ]
}
```

## Rule Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `action_type` | string | yes | The action type, e.g. `shell`, `git.push`, or `*` for wildcard |
| `environment` | string | yes | The environment, e.g. `local`, `dev`, `production`, or `*` |
| `allow` | bool | one of | If true, allow the action |
| `deny` | bool | one of | If true, deny the action |
| `escalate` | bool | one of | If true, escalate for human approval |
| `conditions` | object | no | Additional conditions (e.g., `agent_id`, `resource_pattern`) |
| `description` | string | no | Human-readable description |

A rule must have exactly one of `allow`, `deny`, or `escalate` set to
true. Having none or multiple is a validation error.

## Condition Fields

| Field | Type | Description |
|-------|------|-------------|
| `patterns` | array of strings | Shell patterns to match against the resource |
| `require_explicit_approval` | bool | Force escalation regardless of other rules |
| `agent_id` | string | Restrict rule to a specific agent |
| `resource_pattern` | string | Glob pattern to match against the resource |
| `min_trust_score` | number | Minimum trust score (0.0-1.0) required |
| `min_trust_level` | string | Minimum trust level: `high`, `medium`, `low`, `none` |

## Endpoints

### `POST /v1/policy/simulate`

Simulate a policy against a given action request. Returns the decision
that *would* be made without actually executing the action.

**Request:**

```json
{
  "policy": {
    "version": "v1",
    "rules": [...]
  },
  "request": {
    "action_type": "shell",
    "resource": "shell:rm -rf /tmp",
    "environment": "dev"
  }
}
```

**Response:**

```json
{
  "decision": "escalate",
  "reason_codes": ["policy_escalate", "risky_pattern"],
  "policy_version": "v1",
  "rule_matched": "shell:dev:risky-patterns"
}
```

### `POST /v1/policy/compare`

Compare two policies and report the differences.

**Request:**

```json
{
  "current": { "version": "v1", "rules": [...] },
  "candidate": { "version": "v1", "rules": [...] }
}
```

**Response:**

```json
{
  "added_rules": [...],
  "removed_rules": [...],
  "changed_rules": [
    {
      "action_type": "shell",
      "environment": "dev",
      "from": { "allow": true },
      "to": { "escalate": true }
    }
  ],
  "total_changes": 1
}
```

## Loading Policies

Policies are loaded from `policy_file` in the gateway config
(default: `etc/policy.json`). When the file changes, the gateway
hot-reloads the policy via a file watcher. There is no API endpoint
to upload a policy directly; use the file system.

For multi-gateway deployments, share the policy file via a shared
filesystem (NFS) or config management tool (Ansible, Chef, etc.).
For cloud deployments, the policy is distributed from the control
plane to enrolled gateways via the cloud enrollment sync service.

## Adapters

Policies from other formats (OPA Rego, AWS Cedar, custom JSON) can be
translated to Ovara's native format using the adapters in
[`policy/adapters/`](../../policy/adapters/):

- [OPA (Rego) adapter](../../policy/adapters/opa/)
- [Cedar adapter](../../policy/adapters/cedar/)
- [Custom JSON adapter](../../policy/adapters/custom/)

## Validation

Policies are validated at load time. The following are rejected:

- Missing `version` or `rules`
- Empty `rules` array
- Rules with no outcome (no `allow`, `deny`, or `escalate`)
- Rules with multiple outcomes
- Rules with invalid `action_type` (unknown action)
- Rules with invalid `environment` (not `local`, `dev`, `staging`, `production`, or `*`)
- Circular conditions (a rule that depends on its own outcome)

## Examples

See [`examples/`](../../examples/) for sample policies covering common
patterns:

- [`sample_policy.json`](../../examples/sample_policy.json) — production
  policy with patterns and trust-dependent rules
- [`sample_policy_local.json`](../../examples/sample_policy_local.json) —
  local dev policy demonstrating all three outcomes
