import { OvaraClient } from "./client.js";
import type { GuardInput, GuardDecision, FunctionDefinition, GuardConfig } from "./types.js";

export class OvaraGuard {
  private client: OvaraClient;
  readonly functionName = "ovara_check";

  constructor(config?: GuardConfig) {
    const url = config?.baseUrl || process.env.OVARA_GATEWAY_URL || "http://localhost:8080";
    const key = config?.apiKey || process.env.OVARA_API_KEY || "";
    this.client = new OvaraClient({
      baseUrl: url,
      apiKey: key,
      retries: config?.retries ?? 2,
      timeoutMs: config?.timeoutMs ?? 5000,
    });
  }

  async evaluate(input: GuardInput): Promise<GuardDecision> {
    const result = await this.client.check({
      actionType: input.action,
      resource: input.resource,
      environment: input.environment || "local",
    });
    return {
      decision: result.decision,
      reason: result.reason,
      trustScore: result.trustScore,
      receiptId: result.receiptId,
    };
  }

  async handleFunctionCall(args: Record<string, unknown>): Promise<string> {
    const decision = await this.evaluate({
      action: args.action as string,
      resource: args.resource as string,
      environment: (args.environment as GuardInput["environment"]) || "local",
    });
    return JSON.stringify(decision);
  }

  toFunctionDefinition(): FunctionDefinition {
    return {
      type: "function",
      function: {
        name: this.functionName,
        description:
          "Check if an action is allowed by Ovara runtime trust policy before executing",
        parameters: {
          type: "object",
          properties: {
            action: {
              type: "string",
              description: "Action type (shell.execute, git.push, http.request)",
            },
            resource: {
              type: "string",
              description: "Target resource",
            },
            environment: {
              type: "string",
              enum: ["local", "staging", "production"],
              description: "Target environment",
            },
          },
          required: ["action", "resource"],
        },
      },
    };
  }
}

export { OvaraClient, createClient } from "./client.js";
export type { GuardInput, GuardDecision, FunctionDefinition, GuardConfig } from "./types.js";
