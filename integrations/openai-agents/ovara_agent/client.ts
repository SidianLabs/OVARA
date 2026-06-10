import type { Environment } from "./types.js";

export interface OvaraClientOptions {
  baseUrl: string;
  apiKey?: string;
  timeoutMs?: number;
  retries?: number;
}

export interface DecisionResponse {
  requestId: string;
  decision: "allow" | "deny" | "pending";
  reason?: string;
  trustScore?: number;
  receiptId?: string;
  evaluatedAt: string;
}

export interface ActionRequest {
  actionType: string;
  resource: string;
  environment: Environment;
}

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
      }),
    });
  }

  private async fetch(path: string, options: RequestInit = {}): Promise<any> {
    const headers: Record<string, string> = { "Content-Type": "application/json" };
    if (this.apiKey) headers["Authorization"] = `Bearer ${this.apiKey}`;

    let lastError: Error | null = null;
    for (let attempt = 0; attempt <= this.retries; attempt++) {
      try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), this.timeoutMs);
        const res = await fetch(`${this.baseUrl}${path}`, {
          ...options,
          headers: { ...headers, ...(options.headers as Record<string, string>) },
          signal: controller.signal,
        });
        clearTimeout(timeout);
        if (!res.ok) {
          const body = await res.text();
          throw new Error(`Gateway ${res.status}: ${body}`);
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
