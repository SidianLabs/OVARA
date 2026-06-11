export type ActionType =
  | "shell"
  | "exec"
  | "git.push"
  | "git.pull"
  | "git.fetch"
  | "git.checkout"
  | "git.force_push"
  | "github.push"
  | "github.pr"
  | "github.merge"
  | "github.delete_branch"
  | "ci.deploy"
  | "ci.build_trigger"
  | "ci.approval";

export type Environment = "local" | "dev" | "staging" | "production";

export type Decision = "allow" | "deny" | "escalate";

export type TrustLevel = "none" | "low" | "medium" | "high";

export type ApprovalState = "pending" | "approved" | "denied" | "expired";

export type ReasonCode =
  | "policy_allow"
  | "policy_deny"
  | "policy_escalate"
  | "production_denied"
  | "identity_invalid"
  | "capability_not_allowed"
  | "capability_expiry"
  | "capability_scope"
  | "capability_revoked"
  | "containment_active"
  | "trust_escalate"
  | "trust_low"
  | "anomaly_detected"
  | "allowed";

export interface ActionRequest {
  action_type: ActionType;
  resource: string;
  environment: Environment;
  agent_identity?: AgentIdentity;
  capability_lease?: CapabilityLease;
  delegation_chain?: DelegationChain;
  metadata?: Record<string, unknown>;
}

export interface AgentIdentity {
  issuer: string;
  subject_id: string;
  owner?: string;
  lifecycle?: string;
  verify_key?: string;
}

export interface CapabilityLease {
  lease_id: string;
  issuer: string;
  subject: string;
  allowed_actions: string[];
  resource_scope: string;
  expiry: string;
  delegation_depth: number;
  issued_at?: string;
  revocation_handle?: string;
  signature?: number[];
  verify_key?: string;
}

export interface DelegationChain {
  authorities: Authority[];
  chain_hash?: string;
  depth: number;
}

export interface Authority {
  issuer: string;
  subject_id: string;
  delegated_at?: string;
}

export interface DecisionResponse {
  decision_id: string;
  decision: Decision;
  reason_codes: ReasonCode[];
  trust_score: number;
  trust_level: TrustLevel;
  requires_approval: boolean;
  receipt_stub?: ReceiptStub;
  trust_context?: TrustContext;
  evaluation_summary?: string;
}

export interface ReceiptStub {
  receipt_id: string;
  action_digest: string;
  action_type: string;
  resource: string;
  policy_version: string;
  trust_context_score: number;
  issued_at: string;
}

export interface TrustContext {
  score: number;
  level: TrustLevel;
  anomaly_signals?: AnomalySignal[];
  shield_active: boolean;
  restricted: boolean;
  risk_count: number;
  evaluation_time: string;
}

export interface AnomalySignal {
  code: string;
  severity: string;
  description: string;
}

export interface Approval {
  id: string;
  decision_id: string;
  action_type: ActionType;
  resource: string;
  agent_id: string;
  gateway_id: string;
  state: ApprovalState;
  requested_at: string;
  resolved_at?: string;
  resolved_by?: string;
  reason?: string;
}

export interface Receipt {
  receipt_id: string;
  decision_id: string;
  action_type: string;
  resource: string;
  decision: Decision;
  agent_identity?: string;
  trust_score: number;
  policy_version: string;
  issued_at: string;
  signature?: string;
  organization_id?: string;
  gateway_id?: string;
}

export interface Gateway {
  id: string;
  name: string;
  organization_id: string;
  status: "active" | "inactive" | "enrolling";
  enrolled_at?: string;
  last_heartbeat?: string;
  version?: string;
}

export interface Policy {
  version: string;
  rules: PolicyRule[];
  updated_at: string;
  updated_by?: string;
}

export interface PolicyRule {
  action_type?: string;
  environment?: string;
  allow?: boolean;
  deny?: boolean;
  escalate?: boolean;
  min_trust_score?: number;
  min_trust_level?: TrustLevel;
}

export interface HealthResponse {
  status: string;
  sla?: {
    executing_total: number;
    executing_breaching: number;
    escalations_pending: number;
    breaches: string[];
  };
}

export interface MetricsResponse {
  decisions_total: number;
  allow_count: number;
  deny_count: number;
  escalate_count: number;
  avg_trust_score: number;
  uptime_seconds: number;
}
