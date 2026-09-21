export interface DecisionEvent {
  decisionId: string;
  decision: "allow" | "deny" | "pending";
  actionType: string;
  resource: string;
  gatewayId: string;
  agentId?: string;
  trustScore: number;
  latencyMs: number;
  timestamp: string;
}

export interface MetricsSummary {
  totalDecisions: number;
  allowCount: number;
  denyCount: number;
  pendingCount: number;
  allowRate: number;
  denyRate: number;
  avgLatencyMs: number;
  avgTrustScore: number;
  activeGateways: number;
  activeAgents: number;
  decisionsPerMinute: number;
  topActions: Array<{ action: string; count: number }>;
  topResources: Array<{ resource: string; count: number }>;
}

export interface TimeSeriesPoint {
  timestamp: string;
  count: number;
  allowCount: number;
  denyCount: number;
}

export interface TrendReport {
  hourly: TimeSeriesPoint[];
  daily: TimeSeriesPoint[];
}
