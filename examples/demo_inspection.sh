#!/bin/bash
# demo_inspection.sh - Inspect receipts, trust context, shield status
set -e

GATEWAY="${GATEWAY:-http://localhost:8080}"
AGENT_ID="${1:-agent-demo-005}"

echo "=== Demo: Inspection Endpoints ==="
echo "Gateway: $GATEWAY"
echo "Agent: $AGENT_ID"
echo ""

echo "--- Step 1: Gateway status ---"
curl -s "$GATEWAY/v1/runtime/status" | jq .
echo ""

echo "--- Step 2: Trust context for agent ---"
curl -s "$GATEWAY/v1/trust/context?agent_id=$AGENT_ID" | jq .
echo ""

echo "--- Step 3: Shield status (all restricted agents) ---"
curl -s "$GATEWAY/v1/shield/status" | jq .
echo ""

echo "--- Step 4: Shield status for specific agent ---"
curl -s "$GATEWAY/v1/shield/status/$AGENT_ID" | jq .
echo ""

echo "--- Step 5: Generate a few actions first ---"
for cmd in "ls -la" "pwd" "echo hello"; do
  curl -s -X POST "$GATEWAY/v1/runtime/check" \
    -H "Content-Type: application/json" \
    -d "{
      \"action_type\": \"shell\",
      \"resource\": \"shell:$cmd\",
      \"environment\": \"local\",
      \"agent_identity\": {
        \"issuer\": \"ovara\",
        \"subject_id\": \"$AGENT_ID\"
      }
    }" | jq -r '.decision_id' | xargs -I{} echo "  Decision: {}"
done
echo ""

echo "--- Step 6: List all receipts ---"
curl -s "$GATEWAY/v1/receipts" | jq .
echo ""

echo "--- Step 7: Recent receipts for this agent ---"
curl -s "$GATEWAY/v1/runtime/agent/$AGENT_ID/recent" | jq .
echo ""

echo "--- Step 8: Decision lookup (last decision) ---"
LAST_DECISION_ID=$(curl -s "$GATEWAY/v1/runtime/agent/$AGENT_ID/recent" | jq -r '.receipts[0].decision_id')
if [ "$LAST_DECISION_ID" != "null" ] && [ -n "$LAST_DECISION_ID" ]; then
  curl -s "$GATEWAY/v1/runtime/decision/$LAST_DECISION_ID" | jq .
else
  echo "  No decisions found for agent"
fi
echo ""

echo "=== Inspection demo complete ==="