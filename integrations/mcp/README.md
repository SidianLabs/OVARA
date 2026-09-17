# Ovara MCP Server

Model Context Protocol server that exposes Ovara runtime trust capabilities to MCP-compatible AI agents.

> **Note:** `check_action` is an advisory check — it informs the agent but
> does not enforce policy. Enforcement happens at the Ovara egress proxy.

## Tools

| Tool | Description |
|------|-------------|
| `check_action` | Check if an action is allowed by Ovara policy |
| `get_gateway_status` | Gateway health and enrollment status |
| `list_receipts` | List execution receipts |
| `verify_identity` | Verify an identity's ed25519 signature against a caller-supplied trusted public key |

## Usage

```json
{
  "mcpServers": {
    "ovara": {
      "command": "node",
      "args": ["dist/server.js"],
      "env": {
        "OVARA_GATEWAY_URL": "http://localhost:8080",
        "OVARA_API_KEY": "sk_your_key"
      }
    }
  }
}
```
