import { db } from "../db/connection";
import { policies, gateways, policyDistributions } from "../db/schema";
import { eq, and } from "drizzle-orm";
import type {
  Policy,
  DistributionTarget,
  DistributionRecord,
  DistributionResult,
  DistributionStatus,
  DistributorConfig,
} from "./types";

const DEFAULT_CONFIG: Required<DistributorConfig> = {
  maxRetries: 3,
  retryBaseDelayMs: 1000,
  requestTimeoutMs: 10000,
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
      this.recordHistory(policy.version, result);
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
      this.recordHistory(policy.version, result);
      return result;
    }

    try {
      await this.pushPolicyToGateway(gatewayId, policy);
      const result: DistributionResult = {
        gatewayId,
        status: "delivered",
        timestamp: new Date(),
      };
      await this.updateDistributionStatus(gatewayId, policy, "delivered");
      this.recordHistory(policy.version, result);
      return result;
    } catch (error) {
      const result = await this.retryDistribution(gatewayId, policy, error);
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
        eq(policyDistributions.policyId, orgPolicyIds[0]),
        eq(policyDistributions.status, "delivered"),
      ),
    );

    const allDistributions = await db.select().from(policyDistributions).where(
      eq(policyDistributions.policyId, orgPolicyIds[0]),
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

  getHistory(): DistributionRecord[] {
    return [...this.history];
  }

  private async getTargetsForOrg(orgId: string): Promise<DistributionTarget[]> {
    const orgGateways = await db.query.gateways.findMany({
      where: eq(gateways.organizationId, orgId),
    });

    return orgGateways.map((gw) => ({
      gatewayId: gw.id,
      url: `http://${gw.id}.gateway.ovara.internal:9443`,
      orgId,
      status: gw.status as DistributionTarget["status"],
      lastSync: gw.lastHeartbeat ?? undefined,
    }));
  }

  private async pushPolicyToGateway(gatewayId: string, policy: Policy): Promise<void> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.config.requestTimeoutMs);

    try {
      const response = await fetch(`http://${gatewayId}.gateway.ovara.internal:9443/v1/policy`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
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

  private async retryDistribution(
    gatewayId: string,
    policy: Policy,
    lastError: unknown,
  ): Promise<DistributionResult> {
    let lastErr = lastError;

    for (let attempt = 1; attempt <= this.config.maxRetries; attempt++) {
      const delay = this.config.retryBaseDelayMs * Math.pow(2, attempt - 1);
      await new Promise((resolve) => setTimeout(resolve, delay));

      try {
        await this.pushPolicyToGateway(gatewayId, policy);
        const result: DistributionResult = {
          gatewayId,
          status: "delivered",
          timestamp: new Date(),
        };
        await this.updateDistributionStatus(gatewayId, policy, "delivered");
        this.recordHistory(policy.version, result);
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
    this.recordHistory(policy.version, result);
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

  private recordHistory(policyVersion: number, result: DistributionResult): void {
    this.history.push({
      id: crypto.randomUUID(),
      policyVersion,
      gatewayId: result.gatewayId,
      status: result.status,
      timestamp: result.timestamp,
      error: result.error,
    });
  }
}
