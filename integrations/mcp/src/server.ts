import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { createClient, verifyAgentIdentity } from "@ovara/sdk";

const OVARA_URL = process.env.OVARA_GATEWAY_URL || "http://localhost:8080";
const OVARA_KEY = process.env.OVARA_API_KEY || "";

const client = createClient({ baseUrl: OVARA_URL, apiKey: OVARA_KEY, retries: 2 });

const server = new Server(
  { name: "ovara-mcp", version: "0.1.0" },
  { capabilities: { tools: {} } }
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: "check_action",
      description: "Check if an action is allowed by Ovara runtime policy",
      inputSchema: {
        type: "object",
        properties: {
          action: { type: "string", description: "Action type (e.g. shell.execute, git.push)" },
          resource: { type: "string", description: "Target resource (e.g. sudo, main branch)" },
          environment: { type: "string", enum: ["local", "staging", "production"], default: "local" },
        },
        required: ["action", "resource"],
      },
    },
    {
      name: "get_gateway_status",
      description: "Get Ovara gateway health and status",
      inputSchema: { type: "object", properties: {} },
    },
    {
      name: "list_receipts",
      description: "List execution receipts from the gateway",
      inputSchema: {
        type: "object",
        properties: {
          limit: { type: "number", default: 20 },
          offset: { type: "number", default: 0 },
        },
      },
    },
    {
      name: "verify_identity",
      description: "Verify a machine identity's ed25519 signature against a trusted public key",
      inputSchema: {
        type: "object",
        properties: {
          identity: { type: "object", description: "Agent identity object (with signature)" },
          public_key: { type: "string", description: "Trusted ed25519 public key (hex) for the issuer" },
        },
        required: ["identity", "public_key"],
      },
    },
  ],
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  switch (name) {
    case "check_action": {
      const { action, resource, environment } = args as any;
      const result = await client.check({ actionType: action, resource, environment: environment || "local" });
      return {
        content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
      };
    }
    case "get_gateway_status": {
      const status = await client.status();
      return { content: [{ type: "text", text: JSON.stringify(status, null, 2) }] };
    }
    case "list_receipts": {
      const { limit = 20, offset = 0 } = args as any;
      const receipts = await client.listReceipts({ limit, offset });
      return { content: [{ type: "text", text: JSON.stringify(receipts, null, 2) }] };
    }
    case "verify_identity": {
      const { identity, public_key } = args as any;
      // Local signature verification against a caller-supplied trusted
      // key — the gateway has no verify-identity endpoint.
      const result = { valid: verifyAgentIdentity(identity, public_key) };
      return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
    }
    default:
      throw new Error(`Unknown tool: ${name}`);
  }
});

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("Ovara MCP server running");
}

export { server };

// Only start the stdio transport when run directly, not on import.
if (process.argv[1] && /server\.(ts|js|mts)$/.test(process.argv[1])) {
  main().catch(console.error);
}
