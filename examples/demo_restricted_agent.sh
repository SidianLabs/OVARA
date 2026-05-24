#!/bin/bash
# demo_restricted_agent.sh - Restricted agent path
set -e

GATEWAY="${GATEWAY:-http://localhost:8080}"
AGENT_ID="${1:-agent-demo-003}"

echo "=== Demo: Restricted Agent Flow ==="
echo "Gateway: $GATEWAY"
echo "Agent: $AGENT_ID"
echo ""

echo "--- Step 1: Check current shield status ---"
curl -s "$GATEWAY/v1/shield/status" | jq .
echo ""

echo "--- Step 2: Get trust context for agent ---"
curl -s "$GATEWAY/v1/trust/context?agent_id=$AGENT_ID" | jq .
echo ""

echo "--- Step 3: Manually restrict this agent ---"
curl -s -X POST "$GATEWAY/v1/shield/restrict/$AGENT_ID" \
  -H "Content-Type: application/json" \
  -d '{"reason": "demo: suspicious shell patterns detected"}' | jq .
echo ""

echo "--- Step 4: Verify agent is now restricted ---"
curl -s "$GATEWAY/v1/shield/status/$AGENT_ID" | jq .
echo ""

echo "--- Step 5: Try a safe action (should still evaluate) ---"
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

echo "--- Step 6: Show all restricted agents ---"
curl -s "$GATEWAY/v1/shield/status" | jq .
echo ""

echo "--- Step 7: Unrestrict the agent ---"
curl -s -X POST "$GATEWAY/v1/shield/unrestrict/$AGENT_ID" | jq .
echo ""

echo "--- Step 8: Verify agent is now unrestricted ---"
curl -s "$GATEWAY/v1/shield/status/$AGENT_ID" | jq .
echo ""

echo "=== Restricted agent demo complete ==="