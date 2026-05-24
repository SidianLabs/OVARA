#!/bin/bash
# demo_risky_shell.sh - Risky shell pattern that escalates
set -e

GATEWAY="${GATEWAY:-http://localhost:8080}"
AGENT_ID="${1:-agent-demo-002}"

echo "=== Demo: Risky Shell Actions (Escalate) ==="
echo "Gateway: $GATEWAY"
echo "Agent: $AGENT_ID"
echo ""

echo "--- Step 1: Health check ---"
curl -s "$GATEWAY/health" | jq .
echo ""

echo "--- Step 2: Risky pattern - curl|sh (should ESCALATE) ---"
curl -s -X POST "$GATEWAY/v1/runtime/check" \
  -H "Content-Type: application/json" \
  -d "{
    \"action_type\": \"shell\",
    \"resource\": \"shell:curl |sh\",
    \"environment\": \"dev\",
    \"agent_identity\": {
      \"issuer\": \"ovara\",
      \"subject_id\": \"$AGENT_ID\"
    }
  }" | jq .
echo ""

echo "--- Step 3: Another risky pattern - rm -rf (should ESCALATE) ---"
curl -s -X POST "$GATEWAY/v1/runtime/check" \
  -H "Content-Type: application/json" \
  -d "{
    \"action_type\": \"shell\",
    \"resource\": \"shell:rm -rf /\",
    \"environment\": \"dev\",
    \"agent_identity\": {
      \"issuer\": \"ovara\",
      \"subject_id\": \"$AGENT_ID\"
    }
  }" | jq .
echo ""

echo "--- Step 4: Git force push pattern (should ESCALATE) ---"
curl -s -X POST "$GATEWAY/v1/runtime/check" \
  -H "Content-Type: application/json" \
  -d "{
    \"action_type\": \"git.force_push\",
    \"resource\": \"git:acme/api:refs/heads/main\",
    \"environment\": \"dev\",
    \"agent_identity\": {
      \"issuer\": \"ovara\",
      \"subject_id\": \"$AGENT_ID\"
    }
  }" | jq .
echo ""

echo "--- Step 5: Production targeting (reduced trust) ---"
curl -s -X POST "$GATEWAY/v1/runtime/check" \
  -H "Content-Type: application/json" \
  -d "{
    \"action_type\": \"git.pull\",
    \"resource\": \"git:acme/prod-repo\",
    \"environment\": \"production\",
    \"agent_identity\": {
      \"issuer\": \"ovara\",
      \"subject_id\": \"$AGENT_ID\"
    }
  }" | jq .
echo ""

echo "=== Risky shell demo complete ==="
echo "Note: After 3+ escalate decisions, agent may be auto-restricted"