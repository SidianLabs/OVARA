import { createClient } from "@ovara/sdk";

const OVARA_URL = process.env.OVARA_GATEWAY_URL || "http://localhost:8080";
const OVARA_KEY = process.env.OVARA_API_KEY || "";
const client = createClient({ baseUrl: OVARA_URL, apiKey: OVARA_KEY });

export function ovaraGuard(): Record<string, unknown> {
  return {
    type: "function",
    function: {
      name: "ovara_check",
      description: "Check if an action is allowed by Ovara runtime trust policy before executing",
      parameters: {
        type: "object",
        properties: {
          action: { type: "string", description: "Action type (shell.execute, git.push, http.request)" },
          resource: { type: "string", description: "Target resource" },
          environment: { type: "string", enum: ["local", "staging", "production"] },
        },
        required: ["action", "resource"],
      },
    },
  };
}

export async function handleOvaraToolCall(args: Record<string, unknown>): Promise<string> {
  const result = await client.check({
    actionType: args.action as string,
    resource: args.resource as string,
    environment: (args.environment as string) || "local",
  });
  return JSON.stringify(result);
}
