import { db } from "../db/connection";
import { policies, gateways, policyDistributions } from "../db/schema";
import { eq, and, inArray } from "drizzle-orm";
import type {
  Policy,
  DistributionTarget,
  DistributionRecord,
  DistributionResult,
  DistributionStatus,
  DistributorConfig,
} from "./types";

// Minimum budget that must remain after a backoff sleep for the next
// attempt to be worth making; below this we fail immediately.
const MIN_ATTEMPT_BUDGET_MS = 1000;

const DEFAULT_CONFIG: Required<DistributorConfig> = {
  maxRetries: 3,
  retryBaseDelayMs: 1000,
  requestTimeoutMs: 10000,
  // Bounds the total time a single gateway's inline retry loop may take so
  // a request handler is never serialized behind N x (timeout + backoff).
  maxRetryWindowMs: 30000,
  // Bearer credential sent to gateways on policy push. Configure via
  // OVARA_GATEWAY_API_KEY; when empty no Authorization header is sent.
  apiKey: process.env.OVARA_GATEWAY_API_KEY ?? "",
};

export class PolicyDistributor {
  private config: Required<DistributorConfig>;
  private history: DistributionRecord[] = [];

  constructor(config?: DistributorConfig) {
    this.config = { ...DEFAULT_CONFIG, ...config };
  }

  async distributePolicy(orgId: string, policy: Policy): Promise<DistributionResult[]> {
    const targets = await this.getTargetsForOrg(orgId);
    const results: DistributionResult[] = [];

    for (const target of targets) {
      const result = await this.distributeToGateway(target.gatewayId, policy);
      results.push(result);
    }

    return results;
  }

  async distributeToGateway(gatewayId: string, policy: Policy): Promise<DistributionResult> {
    const gateway = await db.query.gateways.findFirst({
      where: eq(gateways.id, gatewayId),
    });

    if (!gateway) {
      const result: DistributionResult = {
        gatewayId,
        status: "failed",
        timestamp: new Date(),
        error: "Gateway not found",
      };
      this.recordHistory(policy.organizationId, policy.version, result);
      return result;
    }

    if (gateway.status !== "online") {
      const result: DistributionResult = {
        gatewayId,
        status: "failed",
        timestamp: new Date(),
        error: `Gateway status is ${gateway.status}`,
      };
      await this.updateDistributionStatus(gatewayId, policy, "failed");
      this.recordHistory(policy.organizationId, policy.version, result);
      return result;
    }

    // The push endpoint must be configured on the gateway record. We never
    // fabricate a hostname (e.g. {id}.gateway.ovara.internal) — an unrouteable
    // or attacker-predictable URL is worse than an explicit failure.
    const endpoint = gateway.endpointUrl;
    if (!endpoint) {
      const result: DistributionResult = {
        gatewayId,
        status: "failed",
        timestamp: new Date(),
        error: "Gateway has no endpoint_url configured",
      };
      await this.updateDistributionStatus(gatewayId, policy, "failed");
      this.recordHistory(policy.organizationId, policy.version, result);
      return result;
    }

    try {
      this.validateEndpoint(endpoint, gateway.allowInsecure);
    } catch (error) {
      const result: DistributionResult = {
        gatewayId,
        status: "failed",
        timestamp: new Date(),
        error: error instanceof Error ? error.message : String(error),
      };
      await this.updateDistributionStatus(gatewayId, policy, "failed");
      this.recordHistory(policy.organizationId, policy.version, result);
      return result;
    }

    try {
      await this.pushPolicyToGateway(endpoint, policy);
      const result: DistributionResult = {
        gatewayId,
        status: "delivered",
        timestamp: new Date(),
      };
      await this.updateDistributionStatus(gatewayId, policy, "delivered");
      this.recordHistory(policy.organizationId, policy.version, result);
      return result;
    } catch (error) {
      const result = await this.retryDistribution(gatewayId, endpoint, policy, error);
      return result;
    }
  }

  async getDistributionStatus(orgId: string): Promise<DistributionStatus> {
    const orgPolicies = await db.query.policies.findMany({
      where: eq(policies.organizationId, orgId),
    });

    const orgPolicyIds = orgPolicies.map((p) => p.id);

    if (orgPolicyIds.length === 0) {
      return { total: 0, delivered: 0, pending: 0, failed: 0 };
    }

    const distributions = await db.select().from(policyDistributions).where(
      and(
        inArray(policyDistributions.policyId, orgPolicyIds),
        eq(policyDistributions.status, "delivered"),
      ),
    );

    const allDistributions = await db.select().from(policyDistributions).where(
      inArray(policyDistributions.policyId, orgPolicyIds),
    );

    return {
      total: allDistributions.length,
      delivered: distributions.length,
      pending: allDistributions.filter((d) => d.status === "pending").length,
      failed: allDistributions.filter((d) => d.status === "failed").length,
    };
  }

  async retryFailedDistributions(orgId: string): Promise<DistributionResult[]> {
    const orgPolicies = await db.query.policies.findMany({
      where: eq(policies.organizationId, orgId),
    });

    const results: DistributionResult[] = [];

    for (const policy of orgPolicies) {
      const failedDists = await db.select().from(policyDistributions).where(
        and(
          eq(policyDistributions.policyId, policy.id),
          eq(policyDistributions.status, "failed"),
        ),
      );

      for (const dist of failedDists) {
        const policyData: Policy = {
          id: policy.id,
          organizationId: policy.organizationId,
          name: policy.name,
          version: policy.version,
          rules: (policy.rules as Policy["rules"]) || [],
          status: policy.status,
          updatedAt: policy.updatedAt,
        };
        const result = await this.distributeToGateway(dist.gatewayId, policyData);
        results.push(result);
      }
    }

    return results;
  }

  getHistory(orgId?: string): DistributionRecord[] {
    const records = orgId
      ? this.history.filter((h) => h.organizationId === orgId)
      : this.history;
    return [...records];
  }

  private async getTargetsForOrg(orgId: string): Promise<DistributionTarget[]> {
    const orgGateways = await db.query.gateways.findMany({
      where: eq(gateways.organizationId, orgId),
    });

    return orgGateways.map((gw) => ({
      gatewayId: gw.id,
      url: gw.endpointUrl ?? "",
      orgId,
      status: gw.status as DistributionTarget["status"],
      lastSync: gw.lastHeartbeat ?? undefined,
    }));
  }

  // HTTPS is required for policy push unless the gateway record explicitly
  // sets allow_insecure (intended for local/dev deployments only).
  private validateEndpoint(endpoint: string, allowInsecure: boolean): void {
    let url: URL;
    try {
      url = new URL(endpoint);
    } catch {
      throw new Error(`Invalid gateway endpoint_url: ${endpoint}`);
    }
    if (url.protocol !== "https:" && !allowInsecure) {
      throw new Error(
        `Gateway endpoint_url must use https (got ${url.protocol}); set allow_insecure to override`
      );
    }
  }

  private async pushPolicyToGateway(
    endpoint: string,
    policy: Policy,
    timeoutMs: number = this.config.requestTimeoutMs,
  ): Promise<void> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), timeoutMs);

    const headers: Record<string, string> = { "Content-Type": "application/json" };
    if (this.config.apiKey) {
      headers["Authorization"] = `Bearer ${this.config.apiKey}`;
    }

    try {
      const response = await fetch(`${endpoint.replace(/\/$/, "")}/v1/policy`, {
        method: "PUT",
        headers,
        body: JSON.stringify({
          policyId: policy.id,
          version: policy.version,
          rules: policy.rules,
          name: policy.name,
        }),
        signal: controller.signal,
      });

      if (!response.ok) {
        throw new Error(`Gateway returned ${response.status}`);
      }
    } finally {
      clearTimeout(timeout);
    }
  }

  // Retries run inline in the request handler (no job queue yet), so the
  // total wait is bounded by config.maxRetryWindowMs. Each push attempt is
  // additionally capped by config.requestTimeoutMs inside
  // pushPolicyToGateway. A durable retry queue is the proper long-term fix.
  private async retryDistribution(
    gatewayId: string,
    endpoint: string,
    policy: Policy,
    lastError: unknown,
  ): Promise<DistributionResult> {
    let lastErr = lastError;
    const deadline = Date.now() + this.config.maxRetryWindowMs;

    for (let attempt = 1; attempt <= this.config.maxRetries; attempt++) {
      if (Date.now() >= deadline) break;
      const delay = Math.min(
        this.config.retryBaseDelayMs * Math.pow(2, attempt - 1),
        deadline - Date.now(),
      );
      // If sleeping would leave too little budget for the next attempt to
      // be meaningful, fail now instead of burning the rest of the window.
      if (deadline - Date.now() - delay < MIN_ATTEMPT_BUDGET_MS) break;
      await new Promise((resolve) => setTimeout(resolve, delay));

      const attemptBudget = deadline - Date.now();
      if (attemptBudget <= 0) break;

      try {
        await this.pushPolicyToGateway(endpoint, policy, attemptBudget);
        const result: DistributionResult = {
          gatewayId,
          status: "delivered",
          timestamp: new Date(),
        };
        await this.updateDistributionStatus(gatewayId, policy, "delivered");
        this.recordHistory(policy.organizationId, policy.version, result);
        return result;
      } catch (error) {
        lastErr = error;
      }
    }

    const result: DistributionResult = {
      gatewayId,
      status: "failed",
      timestamp: new Date(),
      error: lastErr instanceof Error ? lastErr.message : String(lastErr),
    };
    await this.updateDistributionStatus(gatewayId, policy, "failed");
    this.recordHistory(policy.organizationId, policy.version, result);
    return result;
  }

  private async updateDistributionStatus(
    gatewayId: string,
    policy: Policy,
    status: string,
  ): Promise<void> {
    const existing = await db.query.policyDistributions.findFirst({
      where: and(
        eq(policyDistributions.policyId, policy.id),
        eq(policyDistributions.gatewayId, gatewayId),
      ),
    });

    if (existing) {
      await db
        .update(policyDistributions)
        .set({
          status,
          deliveredAt: status === "delivered" ? new Date() : undefined,
        })
        .where(eq(policyDistributions.id, existing.id));
    } else {
      await db.insert(policyDistributions).values({
        policyId: policy.id,
        gatewayId,
        status,
        deliveredAt: status === "delivered" ? new Date() : undefined,
      });
    }
  }

  private recordHistory(orgId: string, policyVersion: number, result: DistributionResult): void {
    this.history.push({
      id: crypto.randomUUID(),
      organizationId: orgId,
      policyVersion,
      gatewayId: result.gatewayId,
      status: result.status,
      timestamp: result.timestamp,
      error: result.error,
    });
  }
}
