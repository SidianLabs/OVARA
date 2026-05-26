#!/bin/bash
# demo_safe_shell.sh - Shell command flow demonstration
# NOTE: By default policy, ALL shell commands escalate to approval (require_approval=true).
# The approval workflow allows a human to review and approve or deny the escalated action.

set -e

GATEWAY="${GATEWAY:-http://localhost:8080}"
AGENT_ID="${1:-agent-demo-001}"

echo "=== Demo: Shell Command Flow ==="
echo "Gateway: $GATEWAY"
echo "Agent: $AGENT_ID"
echo ""
echo "NOTE: By default policy, ALL shell commands escalate to approval."
echo "This demonstrates the trust-based escalation path."
echo ""

echo "--- Step 1: Health check ---"
curl -s "$GATEWAY/health" | jq .
echo ""

echo "--- Step 2: Shell check (ls -la) - Escalates by default ---"
curl -s -X POST "$GATEWAY/v1/runtime/check" \
  -H "Content-Type: application/json" \
  -d "{
    \"action_type\": \"shell\",
    \"resource\": \"shell:ls -la\",
    \"environment\": \"local\",
    \"agent_identity\": {
      \"issuer\": \"ovara\",
      \"subject_id\": \"\$AGENT_ID\"
    }
  }" | jq .
echo ""

echo "--- Step 3: Another shell command (pwd) - Also escalates ---"
curl -s -X POST "$GATEWAY/v1/runtime/check" \
  -H "Content-Type: application/json" \
  -d "{
    \"action_type\": \"shell\",
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
echo "All shell commands escalated (required_approval=true)."
echo "Use demo_approval_flow.sh to create and approve an escalation."