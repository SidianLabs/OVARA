import { OvaraClient } from "./client.js";
import type { OvaraToolInput, OvaraToolConfig, OvaraDecision } from "./types.js";
import type { DecisionResponse } from "./client.js";

export class OvaraTool {
  readonly name = "ovara_check_action";
  readonly description =
    "Check if an action is allowed by Ovara runtime trust policy before executing it.";
  readonly parameters = {
    type: "object" as const,
    properties: {
      action_type: {
        type: "string",
        description: "Action type (shell.execute, git.push, http.request)",
      },
      resource: {
        type: "string",
        description: "Target resource (command, branch, URL)",
      },
      environment: {
        type: "string",
        enum: ["local", "staging", "production"],
        default: "local",
        description: "Target environment",
      },
    },
    required: ["action_type", "resource"],
  };

  private client: OvaraClient;

  constructor(config?: OvaraToolConfig) {
    const url = config?.baseUrl || process.env.OVARA_GATEWAY_URL || "http://localhost:8080";
    const key = config?.apiKey || process.env.OVARA_API_KEY || "";
    this.client = new OvaraClient({
      baseUrl: url,
      apiKey: key,
      retries: config?.retries ?? 2,
      timeoutMs: config?.timeoutMs ?? 5000,
    });
  }

  async run(input: OvaraToolInput): Promise<string> {
    const result = await this.check(input);
    return JSON.stringify(result);
  }

  async check(input: OvaraToolInput): Promise<DecisionResponse> {
    return this.client.check({
      actionType: input.action_type,
      resource: input.resource,
      environment: input.environment || "local",
    });
  }

  toToolDefinition(): Record<string, unknown> {
    return {
      type: "function",
      function: {
        name: this.name,
        description: this.description,
        parameters: this.parameters,
      },
    };
  }
}

export { OvaraClient, createClient } from "./client.js";
export type { OvaraToolInput, OvaraToolConfig, OvaraDecision } from "./types.js";
