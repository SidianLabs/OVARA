export type ActionType = string;
export type Environment = "local" | "staging" | "production";

export interface AgentIdentity {
  id: string;
  issuer: string;
  subjectId: string;
  owner: string;
  lifecycle: "active" | "suspended" | "revoked";
  publicKey?: string;
}

export interface CapabilityLease {
  leaseId: string;
  issuer: string;
  subject: string;
  allowedActions: string[];
  resourceScope: string;
  expiry: string;
  delegationDepth: number;
  revocationHandle?: string;
  issuedAt: string;
  signature?: string;
}

export interface ActionRequest {
  actionType: ActionType;
  resource: string;
  environment: Environment;
  agentIdentity?: AgentIdentity;
  capabilityLease?: CapabilityLease;
  metadata?: Record<string, unknown>;
  traceId?: string;
}

export type Decision = "allow" | "deny" | "pending";

export interface DecisionResponse {
  requestId: string;
  decision: Decision;
  reason?: string;
  trustScore?: number;
  receiptId?: string;
  approvalId?: string;
  continuationId?: string;
  evaluatedAt: string;
}

export interface ExecutionRequest {
  command: string;
  args?: string[];
  env?: Record<string, string>;
  workingDir?: string;
  timeoutMs?: number;
}

export interface ExecutionResponse {
  executionId: string;
  status: "succeeded" | "failed" | "timed_out";
  exitCode: number;
  stdout: string;
  stderr: string;
  durationMs: number;
  receiptId?: string;
}

export interface VerificationResult {
  valid: boolean;
  identityDigest: string;
  issuer: string;
  errors: string[];
}

export interface VerifiabilityResult {
  valid: boolean;
  identityDigest: string;
  issuer: string;
  subjectId: string;
  errors: string[];
}

export interface GatewayStatus {
  gatewayId: string;
  enrollmentState: "local" | "enrolled" | "pending";
  environment: string;
  isHealthy: boolean;
  policyVersion: string;
  uptimeSeconds: number;
}

export interface OvaraClientOptions {
  baseUrl: string;
  apiKey?: string;
  timeoutMs?: number;
  retries?: number;
}

export interface PaginationParams {
  limit?: number;
  offset?: number;
}

export interface ReceiptRecord {
  receiptId: string;
  decisionId: string;
  actionType: string;
  resource: string;
  decision: string;
  agentId?: string;
  trustScore?: number;
  signature: string;
  issuedAt: string;
}
