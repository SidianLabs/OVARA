export type Environment = "local" | "staging" | "production";

export interface GuardInput {
  action: string;
  resource: string;
  environment?: Environment;
}

export interface GuardDecision {
  decision: "allow" | "deny" | "pending";
  reason?: string;
  trustScore?: number;
  receiptId?: string;
}

export interface FunctionDefinition {
  type: "function";
  function: {
    name: string;
    description: string;
    parameters: {
      type: "object";
      properties: Record<string, unknown>;
      required: string[];
    };
  };
}

export interface GuardConfig {
  baseUrl?: string;
  apiKey?: string;
  retries?: number;
  timeoutMs?: number;
}
