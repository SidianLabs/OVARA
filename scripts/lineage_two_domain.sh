#!/usr/bin/env bash
# OVARA cross-domain action-lineage demo (docs/ACTION_LINEAGE.md):
# two trust domains, real processes —
#
#   A (issuing domain) : a real gateway emits lin_v1 bundles at
#                        decision → approval → execution, each
#                        countersigned into its file ledger.
#   B (relying domain) : verifies the final bundle OFFLINE with
#                        `linverify` against a pinned anchor exported
#                        from A's stores by `gwctl export-anchor`.
#                        Verification needs no gateway of its own —
#                        that is the design's point.
#
# Then the trust-shape beats:
#   forge   — a same-length tamper rejects at a named layer,
#   replay  — a nonce-swapped delivered request rejects at request,
#   revoke  — retiring A's key makes a FRESH anchor reject it, while
#             B's pinned snapshot still proves the history it saw.
#
#   ./scripts/lineage_two_domain.sh   (or: make demo-lineage)
set -euo pipefail

for dep in curl jq go; do
  command -v "$dep" >/dev/null 2>&1 || { echo "demo: missing dependency: $dep" >&2; exit 1; }
done

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d /tmp/ovara-lineage-demo.XXXXXX)"
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

mkdir -p "$TMP/bin" "$TMP/var"

say "1/8 building gateway, gwctl, linverify"
(cd "$ROOT/runtime/gateway" && go build -o "$TMP/bin/gateway" ./cmd/server \
  && go build -o "$TMP/bin/gwctl" ./cmd/gwctl \
  && go build -o "$TMP/bin/linverify" ./cmd/linverify)

say "2/8 generating throwaway config in $TMP (approver root pinned)"
# Mint the approver key first — its pubkey is pinned in config so the
# emitted approval envelope verifies under the domain's approver root.
APPROVER_PUB="$("$TMP/bin/gwctl" genkey --out "$TMP/var/approver.key")"
cat > "$TMP/config.json" <<EOF
{
  "server_port": "$PORT",
  "listen_addr": "127.0.0.1",
  "auth_enabled": true,
  "operator_tokens": ["$OP_TOKEN"],
  "agent_tokens": ["$AG_TOKEN"],
  "gateway_name": "lineage-demo-gateway",
  "policy_file": "$TMP/policy.json",
  "receipt_signing_key": "demo-$(rand)",
  "trusted_issuers": {},
  "receipt_log_enabled": true,
  "receipts_file": "$TMP/var/receipts.json",
  "approvals_file": "$TMP/var/approvals.json",
  "approver_key_file": "$TMP/var/approver.key",
  "approver_pubkey": "$APPROVER_PUB",
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
cat > "$TMP/policy.json" <<'EOF'
{
  "version": "v1-lineage-demo",
  "rules": [
    {"action_type": "shell", "environment": "dev", "escalate": true}
  ]
}
EOF

say "3/8 booting domain A on 127.0.0.1:$PORT"
OVARA_CONFIG="$TMP/config.json" "$TMP/bin/gateway" > "$TMP/gateway.log" 2>&1 &
GW_PID=$!
for i in $(seq 1 50); do
  curl -sf "$BASE/health" >/dev/null 2>&1 && break
  kill -0 "$GW_PID" 2>/dev/null || { cat "$TMP/gateway.log"; exit 1; }
  [ "$i" = 50 ] && { echo "gateway never became healthy"; cat "$TMP/gateway.log"; exit 1; }
  sleep 0.2
done
echo "healthy"

say "4/8 secured action: shell → escalate → approval → orchestrated execution"
# The delivered request domain B will later verify — kept verbatim.
cat > "$TMP/request_posted.json" <<EOF
{"action_type":"shell","resource":"shell:echo OVARA_LINEAGE_DEMO","environment":"dev","nonce":"$(nonce)","issued_at":"$(date -u +%FT%TZ)"}
EOF
CHECK="$(curl -sf -X POST "$BASE/v1/runtime/check" \
  -H "Authorization: Bearer $AG_TOKEN" -H 'Content-Type: application/json' \
  -d @"$TMP/request_posted.json")"
echo "$CHECK" | jq '{decision_id, decision, requires_approval}'
DECISION_ID="$(echo "$CHECK" | jq -r .decision_id)"

APPR_ID="$(curl -sf -X POST "$BASE/v1/approval/create" \
  -H "Authorization: Bearer $AG_TOKEN" -H 'Content-Type: application/json' \
  -d "{\"decision_id\":\"$DECISION_ID\"}" | jq -r .approval_id)"
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

say "5/8 extract the execution-stage bundle + export B's pinned anchor"
# Each stage enriches the decision bundle, so the final bundle carries
# every layer: request digest, receipt, approval envelope, execution.
jq -c 'select(.payload.stage == "execution" and .payload.receipt.decision_id == "'"$DECISION_ID"'") | .payload' \
  "$TMP/var/lineage.jsonl" | tail -1 > "$TMP/bundle.json"
jq '{stage, lineage_id, domain_id, gateway_id, layers: {receipt: (.receipt != null), approval: (.approval != null), execution: (.execution != null)}}' \
  "$TMP/bundle.json"
# Domain B's pinned view of A — read-only over A's stores.
"$TMP/bin/gwctl" export-anchor \
  --registry "$TMP/var/gateway_registry.json" \
  --ledger-key "$TMP/var/lineage_ledger.key" \
  --config "$TMP/config.json" > "$TMP/anchor_v1.json"
jq '{domain_id, gateway_keys, approver_keys, ledger_keys, epoch}' "$TMP/anchor_v1.json"
# The delivered request B received = what the agent posted plus the
# credential-bound identity A injected (subject_id is the only
# agent_identity field the request digest covers).
jq --arg s "$(jq -r .action.agent_id "$TMP/bundle.json")" \
  '. + {agent_identity: {subject_id: $s}}' \
  "$TMP/request_posted.json" > "$TMP/request.json"

verdict() { # name expected(exit) bundle anchor [request] → prints verdict, asserts
  local name="$1" want="$2" bundle="$3" anchor="$4" req="${5:-}" rc=0 out
  if [ -n "$req" ]; then
    out="$("$TMP/bin/linverify" -bundle "$bundle" -anchor "$anchor" -request "$req")" || rc=$?
  else
    out="$("$TMP/bin/linverify" -bundle "$bundle" -anchor "$anchor")" || rc=$?
  fi
  echo "$out" | jq '{accept, layer, detail, layers_passed: (.layers | length)}'
  [ "$rc" = "$want" ] || { echo "$name: expected exit $want, got $rc"; exit 1; }
  printf '%s: %s\n' "$name" "$(echo "$out" | jq -r 'if .accept then "ACCEPT" else "REJECT at layer " + .layer end')"
}

say "6/8 domain B verifies offline — delivered-request mode (all layers)"
verdict "honest  " 0 "$TMP/bundle.json" "$TMP/anchor_v1.json" "$TMP/request.json"

say "7/8 adversarial probes"
# Same-length tamper: statement digest covers every signed byte, so the
# ledger inclusion (and the signature over the payload) no longer binds.
jq '.action.resource |= sub("echo"; "xcho")' "$TMP/bundle.json" > "$TMP/bundle_forged.json"
verdict "forged  " 1 "$TMP/bundle_forged.json" "$TMP/anchor_v1.json" "$TMP/request.json"
# A request that is not the one bound into the lineage (nonce swapped).
jq '.nonce = "swapped-nonce"' "$TMP/request.json" > "$TMP/request_forged.json"
verdict "replay  " 1 "$TMP/bundle.json" "$TMP/anchor_v1.json" "$TMP/request_forged.json"

say "8/8 revoke A's gateway key — fresh view vs B's pinned snapshot"
GWID="$(jq -r .gateway_id "$TMP/bundle.json")"
"$TMP/bin/gwctl" retire --registry "$TMP/var/gateway_registry.json" --gateway-id "$GWID"
"$TMP/bin/gwctl" export-anchor \
  --registry "$TMP/var/gateway_registry.json" \
  --ledger-key "$TMP/var/lineage_ledger.key" \
  --config "$TMP/config.json" > "$TMP/anchor_v2.json"
jq '{gateway_keys, epoch}' "$TMP/anchor_v2.json"
verdict "post-revoke fresh anchor  " 1 "$TMP/bundle.json" "$TMP/anchor_v2.json" "$TMP/request.json"
verdict "post-revoke pinned anchor " 0 "$TMP/bundle.json" "$TMP/anchor_v1.json" "$TMP/request.json"

say "PASS — lineage verified across domains; history survives key retirement"
echo "artifacts kept in $TMP (bundle.json, anchor_v1.json, anchor_v2.json, var/*) — delete when done"
