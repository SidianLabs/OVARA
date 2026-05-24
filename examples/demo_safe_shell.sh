#!/bin/bash
# demo_safe_shell.sh - Safe shell action that gets allowed
set -e

GATEWAY="${GATEWAY:-http://localhost:8080}"
AGENT_ID="${1:-agent-demo-001}"

echo "=== Demo: Safe Shell Action ==="
echo "Gateway: $GATEWAY"
echo "Agent: $AGENT_ID"
echo ""

echo "--- Step 1: Health check ---"
curl -s "$GATEWAY/health" | jq .
echo ""

echo "--- Step 2: Safe shell check (ls -la) ---"
curl -s -X POST "$GATEWAY/v1/runtime/check" \
  -H "Content-Type: application/json" \
  -d "{
    \"action_type\": \"shell\",
    \"resource\": \"shell:ls -la\",
    \"environment\": \"local\",
    \"agent_identity\": {
      \"issuer\": \"ovara\",
      \"subject_id\": \"$AGENT_ID\"
    }
  }" | jq .
echo ""

echo "--- Step 3: Another safe command (pwd) ---"
curl -s -X POST "$GATEWAY/v1/runtime/check" \
  -H "Content-Type: application/json" \
  -d "{
    \"action_type\": \"shell\",
    \"resource\": \"shell:pwd\",
    \"environment\": \"local\",
    \"agent_identity\": {
      \"issuer\": \"ovara\",
      \"subject_id\": \"$AGENT_ID\"
    }
  }" | jq .
echo ""

echo "--- Step 4: Gateway status ---"
curl -s "$GATEWAY/v1/runtime/status" | jq .
echo ""

echo "=== Safe shell demo complete ==="