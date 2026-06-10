export interface Policy {
  id: string;
  organizationId: string;
  name: string;
  version: number;
  rules: PolicyRule[];
  status: string;
  publishedAt?: Date;
  updatedAt?: Date;
}

export interface PolicyRule {
  id: string;
  action: string;
  target: string;
  condition?: string;
  effect: "allow" | "deny";
  priority: number;
}

export interface DistributionTarget {
  gatewayId: string;
  url: string;
  orgId: string;
  status: "online" | "offline" | "enrolling";
  lastSync?: Date;
}

export interface DistributionRecord {
  id: string;
  policyVersion: number;
  gatewayId: string;
  status: DistributionResultStatus;
  timestamp: Date;
  error?: string;
}

export type DistributionResultStatus = "delivered" | "pending" | "failed";

export interface DistributionResult {
  gatewayId: string;
  status: DistributionResultStatus;
  timestamp: Date;
  error?: string;
}

export interface DistributionStatus {
  total: number;
  delivered: number;
  pending: number;
  failed: number;
}

export interface DistributorConfig {
  maxRetries?: number;
  retryBaseDelayMs?: number;
  requestTimeoutMs?: number;
}
