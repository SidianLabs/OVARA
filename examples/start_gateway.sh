#!/bin/bash
# start_gateway.sh - Start the OVARA Runtime Gateway.
#
# The gateway binary reads exactly two environment variables:
#   OVARA_CONFIG       - path to a JSON config file (see
#                        runtime/gateway/internal/config/config.go for fields)
#   OVARA_ENVIRONMENT  - environment name (local/dev/production)
# (plus OVARA_SANDBOX_ENABLED to opt into the sandboxed executor).
#
# OVARA_PORT / OVARA_POLICY_FILE / OVARA_POLICY_REFRESH_INTERVAL are NOT
# read by the gateway — set server_port / policy_file /
# policy_refresh_interval inside the config file instead.
set -e

cd "$(dirname "$0")/.." || { echo "Error: Cannot find repo root"; exit 1; }

GATEWAY_DIR="runtime/gateway"
# OVARA_CONFIG is resolved relative to the gateway working directory;
# runtime/gateway/etc/config.json is the bundled default.
export OVARA_CONFIG="${OVARA_CONFIG:-etc/config.json}"
export OVARA_ENVIRONMENT="${OVARA_ENVIRONMENT:-local}"

echo "=== Starting OVARA Runtime Gateway ==="
echo "Config:      $OVARA_CONFIG (relative to $GATEWAY_DIR)"
echo "Environment: $OVARA_ENVIRONMENT"
echo "Gateway dir: $GATEWAY_DIR"

if [ ! -f "$GATEWAY_DIR/$OVARA_CONFIG" ] && [ ! -f "$OVARA_CONFIG" ]; then
    echo "Error: config file not found at $OVARA_CONFIG"
    exit 1
fi

if [ ! -d "$GATEWAY_DIR" ]; then
    echo "Error: Gateway directory not found at $GATEWAY_DIR"
    exit 1
fi

cd "$GATEWAY_DIR"
echo "Starting gateway..."
go run cmd/server/main.go
