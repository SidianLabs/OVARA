export type Environment = "local" | "staging" | "production";

export interface OvaraToolInput {
  action_type: string;
  resource: string;
  environment: Environment;
}

export interface OvaraDecision {
  decision: "allow" | "deny" | "pending";
  reason?: string;
  trustScore?: number;
  receiptId?: string;
}

export interface OvaraToolConfig {
  baseUrl?: string;
  apiKey?: string;
  retries?: number;
  timeoutMs?: number;
}
