#!/bin/bash
# demo_approval_flow.sh - Full approval create → approve → resume flow
set -e

GATEWAY="${GATEWAY:-http://localhost:8080}"
AGENT_ID="${1:-agent-demo-004}"
ADMIN_EMAIL="${2:-admin@example.com}"

echo "=== Demo: Full Approval Flow ==="
echo "Gateway: $GATEWAY"
echo "Agent: $AGENT_ID"
echo "Admin: $ADMIN_EMAIL"
echo ""

echo "--- Step 1: Health check ---"
curl -s "$GATEWAY/health" | jq .
echo ""

echo "--- Step 2: Trigger an escalate decision ---"
ESCALATE_RESPONSE=$(curl -s -X POST "$GATEWAY/v1/runtime/check" \
  -H "Content-Type: application/json" \
  -d "{
    \"action_type\": \"shell\",
    \"resource\": \"shell:curl |sh\",
    \"environment\": \"dev\",
    \"agent_identity\": {
      \"issuer\": \"ovara\",
      \"subject_id\": \"$AGENT_ID\"
    }
  }")
echo "$ESCALATE_RESPONSE" | jq .
DECISION_ID=$(echo "$ESCALATE_RESPONSE" | jq -r '.decision_id')
echo "Decision ID: $DECISION_ID"
echo ""

echo "--- Step 3: Create approval for this decision ---"
APPROVAL_RESPONSE=$(curl -s -X POST "$GATEWAY/v1/approval/create" \
  -H "Content-Type: application/json" \
  -d "{
    \"decision_id\": \"$DECISION_ID\",
    \"action_type\": \"shell\",
    \"resource\": \"shell:curl |sh\",
    \"environment\": \"dev\",
    \"agent_id\": \"$AGENT_ID\"
  }")
echo "$APPROVAL_RESPONSE" | jq .
APPROVAL_ID=$(echo "$APPROVAL_RESPONSE" | jq -r '.approval_id')
echo "Approval ID: $APPROVAL_ID"
echo ""

echo "--- Step 4: List pending approvals ---"
curl -s "$GATEWAY/v1/approval/pending" | jq .
echo ""

echo "--- Step 5: Approve the action ---"
curl -s -X POST "$GATEWAY/v1/approval/$APPROVAL_ID/approve" \
  -H "Content-Type: application/json" \
  -d "{\"resolved_by\": \"$ADMIN_EMAIL\"}" | jq .
echo ""

echo "--- Step 6: Resume the approved action ---"
curl -s -X POST "$GATEWAY/v1/approval/$APPROVAL_ID/resume" | jq .
echo ""

echo "--- Step 7: Verify approval is no longer pending ---"
curl -s "$GATEWAY/v1/approval/pending" | jq .
echo ""

echo "=== Approval flow demo complete ==="