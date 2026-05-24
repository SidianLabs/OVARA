# Runtime API

## `POST /v1/runtime/check`

Evaluates an action before execution.

Request fields:

- `action_type`
- `resource`
- `agent_identity`
- `capability_lease`
- `environment`
- `metadata`

Response fields:

- `decision`
- `decision_id`
- `reason_codes`
- `trust_score`
- `requires_approval`
- `receipt_stub`

