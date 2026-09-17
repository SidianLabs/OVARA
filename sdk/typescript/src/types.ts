export type ActionType = string;
export type Environment = "local" | "dev" | "staging" | "production";

export interface AgentIdentity {
  id?: string;
  issuer: string;
  subjectId: string;
  owner?: string;
  lifecycle?: "active" | "suspended" | "revoked";
  publicKey?: string;
}

export interface CapabilityLease {
  leaseId: string;
  issuer: string;
  subject: string;
  allowedActions: string[];
  resourceScope: string;
  /** Unix seconds; serialized to RFC3339 for the gateway. */
  expiry: number;
  delegationDepth: number;
  revocationHandle?: string;
  /** Unix seconds; serialized to RFC3339 for the gateway. */
  issuedAt?: number;
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
  nonce?: string;
  issuedAt?: string;
}

export type Decision = "allow" | "deny" | "escalate";
export type ReasonCode = string;
export type TrustLevel = "high" | "medium" | "low" | "none";

export interface AnomalySignal {
  code: string;
  pattern?: string;
  severity: string;
}

export interface TrustContext {
  score: number;
  level: TrustLevel;
  anomaly_signals?: AnomalySignal[];
  shield_active?: boolean;
  restricted?: boolean;
  risk_count?: number;
  evaluation_time: string;
}

export interface ReceiptStub {
  receipt_id: string;
  action_digest: string;
  action_type: string;
  resource: string;
  policy_version: string;
  trust_context_score?: number;
  issued_at: string;
}

/**
 * Mirrors models.DecisionResponse in the gateway exactly — the gateway
 * returns snake_case JSON and the SDK exposes it verbatim.
 */
export interface DecisionResponse {
  decision_id: string;
  decision: Decision;
  reason_codes: ReasonCode[];
  trust_score?: number;
  trust_level?: TrustLevel;
  requires_approval: boolean;
  approval_id?: string;
  receipt_stub?: ReceiptStub;
  trust_context?: TrustContext;
  evaluation_summary?: string;
}

/** Shape of GET /v1/runtime/status (subset of the gateway response). */
export interface GatewayStatus {
  gateway_id?: string;
  gateway_name?: string;
  gateway_version?: string;
  enrollment_state?: string;
  environment?: string;
  enrollment_healthy?: boolean;
  policy_version?: string;
  policy_source?: string;
  storage_mode?: string;
  receipt_count?: number;
  [key: string]: unknown;
}

/** Shape of GET /v1/runtime/health. */
export interface HealthStatus {
  healthy: boolean;
  sla?: Record<string, unknown>;
  reason?: string;
  [key: string]: unknown;
}

export interface OvaraClientOptions {
  baseUrl: string;
  apiKey?: string;
  timeoutMs?: number;
  retries?: number;
  retryDelayMs?: number;
}

export interface PaginationParams {
  limit?: number;
  offset?: number;
}

/** Mirrors models.Receipt in the gateway (snake_case JSON). */
export interface ReceiptRecord {
  receipt_id: string;
  decision_id?: string;
  action_digest?: string;
  action_type?: string;
  resource?: string;
  agent_id?: string;
  capability_lease_id?: string;
  decision?: string;
  policy_version?: string;
  trust_score?: number;
  trust_level?: TrustLevel;
  anomaly_signals?: AnomalySignal[];
  shield_active?: boolean;
  restricted?: boolean;
  risk_count?: number;
  approval_id?: string;
  approval_decision?: string;
  issued_at?: string;
  signature?: string;
}
