import { randomUUID } from "crypto";
import type { Environment } from "./types.js";

export interface OvaraClientOptions {
  baseUrl: string;
  apiKey?: string;
  timeoutMs?: number;
  retries?: number;
}

/** Mirrors the gateway's models.DecisionResponse (snake_case JSON). */
export interface DecisionResponse {
  decision_id: string;
  decision: "allow" | "deny" | "escalate";
  reason_codes: string[];
  trust_score?: number;
  requires_approval: boolean;
  approval_id?: string;
  receipt_stub?: { receipt_id: string; [key: string]: unknown };
  [key: string]: unknown;
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
        // Gateway ActionRequest.Validate() requires nonce and issued_at.
        nonce: randomUUID(),
        issued_at: new Date().toISOString(),
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
          const err = new Error(`Gateway ${res.status}: ${body}`);
          (err as any).status = res.status;
          throw err;
        }
        const text = await res.text();
        if (!text) return null;
        return JSON.parse(text);
      } catch (err: any) {
        lastError = err;
        const status = (err as any)?.status;
        // Only retry network errors, 5xx and 429 — other 4xx are final.
        if (status !== undefined && status !== 429 && status < 500) {
          throw err;
        }
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
