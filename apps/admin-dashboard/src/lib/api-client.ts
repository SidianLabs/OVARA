// Ovara Admin Dashboard — API Client
// Typed access to the Ovara control plane (:3000 by default).
// Configure via NEXT_PUBLIC_OVARA_API_URL / NEXT_PUBLIC_OVARA_API_KEY.
// The API key is a control-plane key in `prefix.secret` form.

export interface GatewayInfo {
  id: string;
  name: string;
  region: string;
  status: 'healthy' | 'degraded' | 'unhealthy';
  version: string;
  decisions: number | null;
  lastHeartbeat: string;
}

export interface PolicyInfo {
  id: string;
  name: string;
  rules: number;
  status: string;
  lastModified: string;
}

export interface AuditEntry {
  id: string;
  timestamp: string;
  actor: string;
  action: string;
  resource: string;
  resourceId?: string;
}

export interface OrganizationInfo {
  id: string;
  name: string;
  displayName: string;
  status: string;
}

const DEFAULT_BASE_URL = 'http://localhost:3000/v1';

function timeAgo(iso?: string | null): string {
  if (!iso) return '—';
  const secs = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (secs < 60) return `${Math.floor(secs)}s ago`;
  if (secs < 3600) return `${Math.floor(secs / 60)}m ago`;
  if (secs < 86400) return `${Math.floor(secs / 3600)}h ago`;
  return `${Math.floor(secs / 86400)}d ago`;
}

function gatewayStatus(status: string, lastHeartbeat?: string | null): GatewayInfo['status'] {
  if (status !== 'online') return status === 'enrolling' ? 'degraded' : 'unhealthy';
  const age = lastHeartbeat ? Date.now() - new Date(lastHeartbeat).getTime() : Infinity;
  if (age < 60_000) return 'healthy';
  if (age < 300_000) return 'degraded';
  return 'unhealthy';
}

interface CloudGateway {
  id: string;
  name: string;
  region: string;
  status: string;
  lastHeartbeat?: string | null;
  metadata?: { version?: string; decisions?: number } | null;
}

interface CloudPolicy {
  id: string;
  name: string;
  rules: unknown[];
  status: string;
  updatedAt: string;
}

interface CloudAuditRow {
  id: string;
  actor: string;
  action: string;
  resource: string;
  resourceId?: string | null;
  createdAt: string;
}

export class OvaraClient {
  private baseUrl: string;
  private apiKey?: string;

  constructor(baseUrl?: string, apiKey?: string) {
    this.baseUrl = baseUrl || process.env.NEXT_PUBLIC_OVARA_API_URL || DEFAULT_BASE_URL;
    this.apiKey = apiKey || process.env.NEXT_PUBLIC_OVARA_API_KEY;
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

  async health(): Promise<{ status: string; timestamp: string }> {
    const res = await fetch(this.baseUrl.replace(/\/v1$/, '/health'));
    if (!res.ok) throw new Error(`API error: ${res.status}`);
    return res.json();
  }

  async listGateways(): Promise<GatewayInfo[]> {
    const rows = await this.request<CloudGateway[]>('/gateways');
    return rows.map((g) => ({
      id: g.id,
      name: g.name,
      region: g.region,
      status: gatewayStatus(g.status, g.lastHeartbeat),
      version: g.metadata?.version ?? '—',
      decisions: g.metadata?.decisions ?? null,
      lastHeartbeat: timeAgo(g.lastHeartbeat),
    }));
  }

  async listPolicies(): Promise<PolicyInfo[]> {
    const rows = await this.request<CloudPolicy[]>('/policies');
    return rows.map((p) => ({
      id: p.id,
      name: p.name,
      rules: Array.isArray(p.rules) ? p.rules.length : 0,
      status: p.status,
      lastModified: timeAgo(p.updatedAt),
    }));
  }

  async queryAuditLog(limit = 100): Promise<AuditEntry[]> {
    const rows = await this.request<CloudAuditRow[]>(`/audit?limit=${limit}`);
    return rows.map((r) => ({
      id: r.id,
      timestamp: r.createdAt,
      actor: r.actor,
      action: r.action,
      resource: r.resource,
      resourceId: r.resourceId ?? undefined,
    }));
  }

  async listOrganizations(): Promise<OrganizationInfo[]> {
    const rows = await this.request<Array<{ id: string; name: string; displayName: string; status: string }>>('/organizations');
    return rows.map((o) => ({ id: o.id, name: o.name, displayName: o.displayName, status: o.status }));
  }
}

export const ovaraClient = new OvaraClient();
