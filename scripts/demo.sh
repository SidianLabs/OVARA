#!/usr/bin/env bash
# OVARA gateway demo: fresh throwaway state → secured action round trip.
#
#   ./scripts/demo.sh        (or: make demo)
#
# Generates a config under a temp dir, boots the gateway, then runs:
#   POST /v1/runtime/check  (agent token, allowed action)
#   POST /v1/runtime/check  (agent token, shell action → escalate)
#   POST /v1/approval/create + POST /v1/approval/{id}/approve (operator token)
#   orchestrated execution of `echo` → signed receipt + lin_v1 lineage bundles
# Prints the artifacts, then exits cleanly (temp dir is kept for inspection).
set -euo pipefail

for dep in curl jq go; do
  command -v "$dep" >/dev/null 2>&1 || { echo "demo: missing dependency: $dep" >&2; exit 1; }
done

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d /tmp/ovara-demo.XXXXXX)"
GW_PID=""
PORT="${OVARA_DEMO_PORT:-$((20000 + RANDOM % 20000))}"
BASE="http://127.0.0.1:$PORT"

cleanup() { [ -n "$GW_PID" ] && kill "$GW_PID" 2>/dev/null || true; }
trap cleanup EXIT

say() { printf '\n=== %s ===\n' "$*"; }

rand() { openssl rand -hex 16 2>/dev/null || head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n'; }
nonce() { uuidgen 2>/dev/null | tr 'A-Z' 'a-z' || rand; }

OP_TOKEN="op-$(rand)"
AG_TOKEN="ag-$(rand)"

say "1/7 generating throwaway config in $TMP"
cat > "$TMP/config.json" <<EOF
{
  "server_port": "$PORT",
  "listen_addr": "127.0.0.1",
  "auth_enabled": true,
  "operator_tokens": ["$OP_TOKEN"],
  "agent_tokens": ["$AG_TOKEN"],
  "gateway_name": "demo-gateway",
  "policy_file": "$TMP/policy.json",
  "receipt_signing_key": "demo-$(rand)",
  "trusted_issuers": {},
  "receipt_log_enabled": true,
  "receipts_file": "$TMP/var/receipts.json",
  "approvals_file": "$TMP/var/approvals.json",
  "continuations_file": "$TMP/var/continuations.jsonl",
  "execution_file": "$TMP/var/executions.jsonl",
  "events_file": "$TMP/var/events.jsonl",
  "gateway_key_file": "$TMP/var/gateway.key",
  "gateway_registry_file": "$TMP/var/gateway_registry.json",
  "enrollment_file": "$TMP/var/enrollment.json",
  "identity_registry_file": "$TMP/var/identity_registry.json",
  "replay_file": "$TMP/var/replay.json",
  "lineage_file": "$TMP/var/lineage.jsonl",
  "lineage_ledger_file": "$TMP/var/lineage_ledger.json",
  "lineage_ledger_key_file": "$TMP/var/lineage_ledger.key",
  "journal_signing_required": true,
  "enable_host_executors": true,
  "decision_log_file": "$TMP/var/decisions.jsonl"
}
EOF
# escalate rules run last; with no allow rule, every check escalates.
# We want one allow + one escalate to show the contrast.
cat > "$TMP/policy.json" <<'EOF'
{
  "version": "v1-demo",
  "rules": [
    {"action_type": "git.pull", "environment": "dev", "allow": true},
    {"action_type": "shell", "environment": "dev", "escalate": true}
  ]
}
EOF

say "2/7 building gateway"
(cd "$ROOT/runtime/gateway" && go build -o "$TMP/gateway" ./cmd/server)

say "3/7 booting on 127.0.0.1:$PORT"
OVARA_CONFIG="$TMP/config.json" "$TMP/gateway" > "$TMP/gateway.log" 2>&1 &
GW_PID=$!
for i in $(seq 1 50); do
  curl -sf "$BASE/health" >/dev/null 2>&1 && break
  kill -0 "$GW_PID" 2>/dev/null || { cat "$TMP/gateway.log"; exit 1; }
  [ "$i" = 50 ] && { echo "gateway never became healthy"; cat "$TMP/gateway.log"; exit 1; }
  sleep 0.2
done
echo "healthy"

agent_check() { # action resource → decision json
  curl -sf -X POST "$BASE/v1/runtime/check" \
    -H "Authorization: Bearer $AG_TOKEN" -H 'Content-Type: application/json' \
    -d "{\"action_type\":\"$1\",\"resource\":\"$2\",\"environment\":\"dev\",\"nonce\":\"$(nonce)\",\"issued_at\":\"$(date -u +%FT%TZ)\"}"
}

say "4/7 check safe action (agent token): git.pull"
agent_check git.pull origin/main | jq '{decision_id, decision, reason_codes}'

say "5/7 check risky action (agent token): shell echo"
CHECK="$(agent_check shell 'shell:echo OVARA_DEMO_OK')"
echo "$CHECK" | jq '{decision_id, decision, requires_approval, reason_codes}'
DECISION_ID="$(echo "$CHECK" | jq -r .decision_id)"

say "6/7 approval round trip (agent creates, operator approves)"
APPR="$(curl -sf -X POST "$BASE/v1/approval/create" \
  -H "Authorization: Bearer $AG_TOKEN" -H 'Content-Type: application/json' \
  -d "{\"decision_id\":\"$DECISION_ID\"}")"
APPR_ID="$(echo "$APPR" | jq -r .approval_id)"
echo "approval_id=$APPR_ID"
curl -sf -X POST "$BASE/v1/approval/$APPR_ID/approve" \
  -H "Authorization: Bearer $OP_TOKEN" -H 'Content-Type: application/json' \
  -d '{}' | jq '{approval_id, status}'
echo "waiting for orchestrated execution..."
for i in $(seq 1 30); do
  STATE="$(curl -sf "$BASE/v1/executions" -H "Authorization: Bearer $OP_TOKEN" | jq -r '.executions[-1].state // empty')"
  [ "$STATE" = "succeeded" ] && break
  [ "$i" = 30 ] && { echo "execution never finished"; exit 1; }
  sleep 1
done
curl -sf "$BASE/v1/executions" -H "Authorization: Bearer $OP_TOKEN" \
  | jq '.executions[-1] | {state, stdout}'

say "7/7 signed receipt + lineage"
curl -sf "$BASE/v1/receipts/decision/$DECISION_ID" -H "Authorization: Bearer $OP_TOKEN" \
  | jq '.receipts[-1] | {decision_id, signature, gateway_sig, gateway_key_id}'
jq -r '.payload | "lineage stage=\(.stage) sig=\(.sig[0:32])... inclusion=\(.inclusion.sig[0:32])..."' "$TMP/var/lineage.jsonl"
echo "ledger inclusions: $(wc -l < "$TMP/var/lineage_ledger.json" | tr -d ' ')"

say "PASS — secured round trip complete"
echo "artifacts kept in $TMP (config.json, gateway.log, var/*.json*) — delete when done"
