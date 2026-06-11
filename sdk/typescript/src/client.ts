import { randomUUID } from "crypto";
import {
  OvaraClientOptions,
  ActionRequest,
  DecisionResponse,
  GatewayStatus,
  ReceiptRecord,
  PaginationParams,
} from "./types";

export class OvaraClient {
  private baseUrl: string;
  private apiKey: string | undefined;
  private timeoutMs: number;
  private retries: number;

  constructor(options: OvaraClientOptions) {
    this.baseUrl = options.baseUrl.replace(/\/+$/, "");
    this.apiKey = options.apiKey;
    this.timeoutMs = options.timeoutMs || 5000;
    this.retries = options.retries || 2;
  }

  async check(request: ActionRequest): Promise<DecisionResponse> {
    return this.fetch("/v1/runtime/check", {
      method: "POST",
      body: JSON.stringify({
        action_type: request.actionType,
        resource: request.resource,
        environment: request.environment,
        agent_identity: request.agentIdentity,
        capability_lease: request.capabilityLease,
        metadata: request.metadata,
        trace_id: request.traceId || randomUUID(),
      }),
    });
  }

  async allow(actionType: string, resource: string, env: string = "local"): Promise<boolean> {
    const resp = await this.check({
      actionType,
      resource,
      environment: env as any,
      traceId: randomUUID(),
    });
    return resp.decision === "allow";
  }

  async batchCheck(requests: ActionRequest[]): Promise<DecisionResponse[]> {
    const resp = await this.fetch("/v1/runtime/batch-check", {
      method: "POST",
      body: JSON.stringify({
        requests: requests.map((r) => ({
          action_type: r.actionType,
          resource: r.resource,
          environment: r.environment,
          agent_identity: r.agentIdentity,
          capability_lease: r.capabilityLease,
          metadata: r.metadata,
          trace_id: r.traceId || randomUUID(),
        })),
      }),
    });
    return (resp as any).decisions || [];
  }

  async status(): Promise<GatewayStatus> {
    return this.fetch("/v1/runtime/status");
  }

  async health(): Promise<{ status: string }> {
    return this.fetch("/v1/runtime/health");
  }

  async listReceipts(params?: PaginationParams): Promise<ReceiptRecord[]> {
    const query = new URLSearchParams();
    if (params?.limit) query.set("limit", String(params.limit));
    if (params?.offset) query.set("offset", String(params.offset));
    return this.fetch(`/v1/receipts?${query}`);
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
          throw new Error(`Gateway returned ${res.status}: ${body}`);
        }

        const text = await res.text();
        if (!text) return null;
        return JSON.parse(text);
      } catch (err: any) {
        lastError = err;
        if (attempt < this.retries) {
          await new Promise((r) => setTimeout(r, 100 * Math.pow(2, attempt)));
        }
      }
    }

    throw lastError || new Error("Request failed");
  }
}

export function createClient(options: OvaraClientOptions): OvaraClient {
  return new OvaraClient(options);
}
