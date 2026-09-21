// Ovara Admin Dashboard — API Client
// Provides typed access to the Ovara Gateway API

export interface GatewayInfo {
  id: string;
  region: string;
  status: 'healthy' | 'degraded' | 'unhealthy';
  version: string;
  decisions: number;
  lastHeartbeat: string;
}

export interface PolicyInfo {
  id: string;
  name: string;
  rules: number;
  status: 'active' | 'draft' | 'archived';
  lastModified: string;
}

export interface AuditEntry {
  id: string;
  timestamp: string;
  gateway: string;
  action: string;
  decision: 'allow' | 'deny' | 'escalate';
  agent: string;
  receiptDigest?: string;
}

export interface OrganizationInfo {
  domain: string;
  name: string;
  members: number;
  gateways: number;
  trustScore: number;
  status: 'active' | 'probation' | 'suspended';
}

export interface DashboardMetrics {
  decisionsPerSec: number;
  avgLatencyMs: number;
  errorRate: number;
  activeGateways: number;
  trustScores: number[];
}

const DEFAULT_BASE_URL = 'http://localhost:9090/v1';

export class OvaraClient {
  private baseUrl: string;
  private apiKey?: string;

  constructor(baseUrl?: string, apiKey?: string) {
    this.baseUrl = baseUrl || DEFAULT_BASE_URL;
    this.apiKey = apiKey;
  }

  private async request<T>(path: string, options?: RequestInit): Promise<T> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    };
    if (this.apiKey) {
      headers['Authorization'] = `Bearer ${this.apiKey}`;
    }

    const res = await fetch(`${this.baseUrl}${path}`, {
      ...options,
      headers: { ...headers, ...options?.headers },
    });

    if (!res.ok) {
      throw new Error(`API error: ${res.status} ${res.statusText}`);
    }

    return res.json();
  }

  // Health
  async health(): Promise<{ status: string; version: string }> {
    return this.request('/runtime/health');
  }

  // Gateways
  async listGateways(): Promise<GatewayInfo[]> {
    return this.request('/runtime/gateways');
  }

  async getGateway(id: string): Promise<GatewayInfo> {
    return this.request(`/runtime/gateways/${id}`);
  }

  // Policies
  async listPolicies(): Promise<PolicyInfo[]> {
    return this.request('/policies');
  }

  async getPolicy(id: string): Promise<PolicyInfo> {
    return this.request(`/policies/${id}`);
  }

  // Audit
  async queryAuditLog(params?: { action?: string; decision?: string; limit?: number }): Promise<AuditEntry[]> {
    const searchParams = new URLSearchParams();
    if (params?.action) searchParams.set('action', params.action);
    if (params?.decision) searchParams.set('decision', params.decision);
    if (params?.limit) searchParams.set('limit', String(params.limit));
    const qs = searchParams.toString();
    return this.request(`/audit${qs ? `?${qs}` : ''}`);
  }

  // Organizations
  async listOrganizations(): Promise<OrganizationInfo[]> {
    return this.request('/organizations');
  }

  // Metrics
  async getMetrics(): Promise<DashboardMetrics> {
    return this.request('/runtime/metrics');
  }

  // Decision simulation
  async simulateDecision(action: string, resource: string, agentId: string): Promise<{
    decision: string;
    reasons: string[];
    trustScore: number;
  }> {
    return this.request('/policy/simulate', {
      method: 'POST',
      body: JSON.stringify({ action, resource, agent_identity: agentId }),
    });
  }
}

export const ovaraClient = new OvaraClient();
