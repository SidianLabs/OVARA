#!/bin/bash
# demo_safe_shell.sh - Shell command flow demonstration
# Under examples/sample_policy_local.json (the demo config): shell commands
# in the `local` environment are ALLOWED. Use environment=dev to see the
# escalate path, production to see deny. See demo_approval_flow.sh for the
# full approval workflow.

set -e

GATEWAY="${GATEWAY:-http://localhost:8080}"
AGENT_ID="${1:-agent-demo-001}"

echo "=== Demo: Shell Command Flow ==="
echo "Gateway: $GATEWAY"
echo "Agent: $AGENT_ID"
echo ""
echo "NOTE: under the demo policy, local shell commands are allowed."
echo "Try environment=dev (escalate) or production (deny) for other outcomes."
echo ""

echo "--- Step 1: Health check ---"
curl -s "$GATEWAY/health" | jq .
echo ""

echo "--- Step 2: Shell check (ls -la, env=local) - allowed by demo policy ---"
curl -s -X POST "$GATEWAY/v1/runtime/check" \
  -H "Content-Type: application/json" \
  -d "{
    \"action_type\": \"shell\",
    \"nonce\": \"$(uuidgen)\",
    \"issued_at\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",
    \"resource\": \"shell:ls -la\",
    \"environment\": \"local\",
    \"agent_identity\": {
      \"issuer\": \"ovara\",
      \"subject_id\": \"\$AGENT_ID\"
    }
  }" | jq .
echo ""

echo "--- Step 3: Another shell command (pwd, env=local) - also allowed ---"
curl -s -X POST "$GATEWAY/v1/runtime/check" \
  -H "Content-Type: application/json" \
  -d "{
    \"action_type\": \"shell\",
    \"nonce\": \"$(uuidgen)\",
    \"issued_at\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",
    \"resource\": \"shell:pwd\",
    \"environment\": \"local\",
    \"agent_identity\": {
      \"issuer\": \"ovara\",
      \"subject_id\": \"\$AGENT_ID\"
    }
  }" | jq .
echo ""

echo "--- Step 4: Gateway status ---"
curl -s "$GATEWAY/v1/runtime/status" | jq .
echo ""

echo "--- Step 5: Trust context for this agent ---"
curl -s "$GATEWAY/v1/trust/context?agent_id=$AGENT_ID" | jq .
echo ""

echo "=== Shell demo complete ==="
echo "Local shell commands were allowed under the demo policy."
echo "Use demo_approval_flow.sh (environment=dev) to see escalate → approve → resume."