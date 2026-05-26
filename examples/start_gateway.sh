#!/bin/bash
# start_gateway.sh - Start the OVARA Runtime Gateway with sensible defaults
set -e

cd "$(dirname "$0")/.." || { echo "Error: Cannot find repo root"; exit 1; }

GATEWAY_DIR="runtime/gateway"
PORT="${OVARA_PORT:-8080}"
CONFIG="${OVARA_CONFIG:-}"
POLICY_FILE="${OVARA_POLICY_FILE:-}"
POLICY_REFRESH="${OVARA_POLICY_REFRESH_INTERVAL:-0}"

echo "=== Starting OVARA Runtime Gateway ==="
echo "Port: $PORT"
echo "Gateway dir: $GATEWAY_DIR"

export OVARA_PORT
[ -n "$CONFIG" ] && export OVARA_CONFIG="$CONFIG"
[ -n "$POLICY_FILE" ] && export OVARA_POLICY_FILE="$POLICY_FILE"
[ -n "$POLICY_REFRESH" ] && export OVARA_POLICY_REFRESH_INTERVAL="$POLICY_REFRESH"

if [ ! -d "$GATEWAY_DIR" ]; then
    echo "Error: Gateway directory not found at $GATEWAY_DIR"
    exit 1
fi

cd "$GATEWAY_DIR"
echo "Starting gateway on port $PORT..."
go run cmd/server/main.go