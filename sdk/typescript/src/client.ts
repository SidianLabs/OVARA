import { randomUUID } from "crypto";
import {
  OvaraClientOptions,
  ActionRequest,
  AgentIdentity,
  CapabilityLease,
  DelegationChain,
  DecisionResponse,
  GatewayStatus,
  HealthStatus,
  ReceiptRecord,
  PaginationParams,
} from "./types";

// --- Serializers -------------------------------------------------------
// The gateway expects snake_case fields matching the JSON tags in
// runtime/gateway/internal/models/action_request.go. SDK callers use
// camelCase; these functions perform the explicit mapping.

function unixToRFC3339(unix: number): string {
  return new Date(unix * 1000).toISOString();
}

function serializeAgentIdentity(identity: AgentIdentity): Record<string, unknown> {
  const out: Record<string, unknown> = {
    issuer: identity.issuer,
    subject_id: identity.subjectId,
  };
  if (identity.owner !== undefined) out.owner = identity.owner;
  if (identity.lifecycle !== undefined) out.lifecycle = identity.lifecycle;
  if (identity.publicKey !== undefined) out.verify_key = identity.publicKey;
  return out;
}

function serializeCapabilityLease(lease: CapabilityLease): Record<string, unknown> {
  const out: Record<string, unknown> = {
    lease_id: lease.leaseId,
    issuer: lease.issuer,
    subject: lease.subject,
    allowed_actions: lease.allowedActions,
    resource_scope: lease.resourceScope,
    expiry: unixToRFC3339(lease.expiry),
    delegation_depth: lease.delegationDepth,
  };
  if (lease.issuedAt !== undefined) out.issued_at = unixToRFC3339(lease.issuedAt);
  if (lease.revocationHandle !== undefined) out.revocation_handle = lease.revocationHandle;
  if (lease.signature !== undefined) out.signature = lease.signature;
  return out;
}

function serializeDelegationChain(chain: DelegationChain): Record<string, unknown> {
  return {
    authorities: chain.authorities.map((a) => {
      const out: Record<string, unknown> = {
        issuer: a.issuer,
        subject_id: a.subjectId,
      };
      if (a.delegatedAt !== undefined) out.delegated_at = a.delegatedAt;
      return out;
    }),
    chain_hash: chain.chainHash,
    depth: chain.depth,
  };
}

function serializeActionRequest(request: ActionRequest): Record<string, unknown> {
  return {
    action_type: request.actionType,
    resource: request.resource,
    environment: request.environment,
    agent_identity: request.agentIdentity
      ? serializeAgentIdentity(request.agentIdentity)
      : undefined,
    capability_lease: request.capabilityLease
      ? serializeCapabilityLease(request.capabilityLease)
      : undefined,
    delegation_chain: request.delegationChain
      ? serializeDelegationChain(request.delegationChain)
      : undefined,
    metadata: request.metadata,
    nonce: request.nonce || randomUUID(),
    issued_at: request.issuedAt || new Date().toISOString(),
  };
}

// Retryable HTTP statuses: 5xx and 429. Other 4xx are policy/validation
// failures — retrying them is pointless.
function isRetryableStatus(status: number): boolean {
  return status === 429 || status >= 500;
}

export class OvaraClient {
  private baseUrl: string;
  private apiKey: string | undefined;
  private timeoutMs: number;
  private retries: number;
  private retryDelayMs: number;

  constructor(options: OvaraClientOptions) {
    this.baseUrl = options.baseUrl.replace(/\/+$/, "");
    this.apiKey = options.apiKey;
    this.timeoutMs = options.timeoutMs || 5000;
    this.retries = options.retries || 2;
    this.retryDelayMs = options.retryDelayMs ?? 100;
  }

  async check(request: ActionRequest): Promise<DecisionResponse> {
    return this.fetch("/v1/runtime/check", {
      method: "POST",
      body: JSON.stringify(serializeActionRequest(request)),
    });
  }

  async allow(actionType: string, resource: string, env: string = "local"): Promise<boolean> {
    const resp = await this.check({
      actionType,
      resource,
      environment: env as any,
      nonce: randomUUID(),
    });
    return resp.decision === "allow";
  }

  async batchCheck(requests: ActionRequest[]): Promise<DecisionResponse[]> {
    const resp = await this.fetch("/v1/runtime/batch-check", {
      method: "POST",
      body: JSON.stringify({
        requests: requests.map(serializeActionRequest),
      }),
    });
    return (resp as any).decisions || [];
  }

  async status(): Promise<GatewayStatus> {
    return this.fetch("/v1/runtime/status");
  }

  async health(): Promise<HealthStatus> {
    return this.fetch("/v1/runtime/health");
  }

  async listReceipts(params?: PaginationParams): Promise<ReceiptRecord[]> {
    const query = new URLSearchParams();
    if (params?.limit) query.set("limit", String(params.limit));
    if (params?.offset) query.set("offset", String(params.offset));
    const resp = await this.fetch(`/v1/receipts?${query}`);
    return (resp as any)?.receipts ?? [];
  }

  async getReceipt(receiptId: string): Promise<ReceiptRecord> {
    return this.fetch(`/v1/receipts/${receiptId}`);
  }

  async listApprovals(params?: PaginationParams): Promise<any[]> {
    const query = new URLSearchParams();
    if (params?.limit) query.set("limit", String(params.limit));
    if (params?.offset) query.set("offset", String(params.offset));
    return this.fetch(`/v1/approvals?${query}`);
  }

  async listExecutions(params?: PaginationParams): Promise<any[]> {
    const query = new URLSearchParams();
    if (params?.limit) query.set("limit", String(params.limit));
    if (params?.offset) query.set("offset", String(params.offset));
    return this.fetch(`/v1/executions?${query}`);
  }

  async listContinuations(params?: PaginationParams): Promise<any[]> {
    const query = new URLSearchParams();
    if (params?.limit) query.set("limit", String(params.limit));
    if (params?.offset) query.set("offset", String(params.offset));
    return this.fetch(`/v1/continuations?${query}`);
  }

  async getCapabilities(): Promise<any> {
    return this.fetch("/v1/capabilities");
  }

  async getMetrics(): Promise<any> {
    return this.fetch("/v1/runtime/metrics");
  }

  private async fetch(path: string, options: RequestInit = {}): Promise<any> {
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
    };
    if (this.apiKey) {
      headers["Authorization"] = `Bearer ${this.apiKey}`;
    }

    let lastError: Error | null = null;

    for (let attempt = 0; attempt <= this.retries; attempt++) {
      try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), this.timeoutMs);

        const res = await fetch(`${this.baseUrl}${path}`, {
          ...options,
          headers: { ...headers, ...(options.headers as any) },
          signal: controller.signal,
        });

        clearTimeout(timeout);

        if (!res.ok) {
          const body = await res.text();
          const err = new Error(`Gateway returned ${res.status}: ${body}`);
          (err as any).status = res.status;
          throw err;
        }

        const text = await res.text();
        if (!text) return null;
        return JSON.parse(text);
      } catch (err: any) {
        lastError = err;
        const status = (err as any)?.status;
        // Do not retry non-retryable HTTP errors; only network failures,
        // 5xx and 429 are retried.
        if (status !== undefined && !isRetryableStatus(status)) {
          throw err;
        }
        if (attempt < this.retries) {
          await new Promise((r) => setTimeout(r, this.retryDelayMs * Math.pow(2, attempt)));
        }
      }
    }

    throw lastError || new Error("Request failed");
  }
}

export function createClient(options: OvaraClientOptions): OvaraClient {
  return new OvaraClient(options);
}
