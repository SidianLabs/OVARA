import { FastifyInstance, FastifyRequest, FastifyReply } from "fastify";
import { db } from "../db/connection";
import { policies, gateways, policyDistributions } from "../db/schema";
import { authenticate, requireScope } from "../middleware/auth";
import { eq, and } from "drizzle-orm";
import { PolicyDistributor } from "../distribution/distributor";
import type { Policy } from "../distribution/types";

const distributor = new PolicyDistributor();

export function distributionRoutes(app: FastifyInstance) {

  app.post("/publish", {
    preHandler: [authenticate, requireScope("admin")],
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    const { policyId, organizationId } = request.body as {
      policyId: string;
      organizationId: string;
    };

    if (!policyId || !organizationId) {
      return reply.status(400).send({ error: "policyId and organizationId required" });
    }

    const policy = await db.query.policies.findFirst({
      where: eq(policies.id, policyId),
    });
    if (!policy) {
      return reply.status(404).send({ error: "Policy not found" });
    }

    const policyData: Policy = {
      id: policy.id,
      organizationId: policy.organizationId,
      name: policy.name,
      version: policy.version,
      rules: (policy.rules as Policy["rules"]) || [],
      status: policy.status,
      updatedAt: policy.updatedAt,
    };

    const results = await distributor.distributePolicy(organizationId, policyData);
    return reply.send({
      policyId,
      organizationId,
      results,
      summary: {
        total: results.length,
        delivered: results.filter((r) => r.status === "delivered").length,
        failed: results.filter((r) => r.status === "failed").length,
      },
    });
  });

  app.post("/publish/:gatewayId", {
    preHandler: [authenticate, requireScope("admin")],
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    const { gatewayId } = request.params as { gatewayId: string };
    const { policyId } = request.body as { policyId: string };

    if (!policyId) {
      return reply.status(400).send({ error: "policyId required" });
    }

    const policy = await db.query.policies.findFirst({
      where: eq(policies.id, policyId),
    });
    if (!policy) {
      return reply.status(404).send({ error: "Policy not found" });
    }

    const gateway = await db.query.gateways.findFirst({
      where: eq(gateways.id, gatewayId),
    });
    if (!gateway) {
      return reply.status(404).send({ error: "Gateway not found" });
    }

    const policyData: Policy = {
      id: policy.id,
      organizationId: policy.organizationId,
      name: policy.name,
      version: policy.version,
      rules: (policy.rules as Policy["rules"]) || [],
      status: policy.status,
      updatedAt: policy.updatedAt,
    };

    const result = await distributor.distributeToGateway(gatewayId, policyData);
    return reply.send({ policyId, gatewayId, result });
  });

  app.get("/status/:orgId", {
    preHandler: [authenticate, requireScope("read")],
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    const { orgId } = request.params as { orgId: string };

    const orgGateways = await db.query.gateways.findMany({
      where: eq(gateways.organizationId, orgId),
    });

    const orgPolicies = await db.query.policies.findMany({
      where: eq(policies.organizationId, orgId),
    });

    const status = await distributor.getDistributionStatus(orgId);
    return reply.send({
      organizationId: orgId,
      gateways: orgGateways.length,
      policies: orgPolicies.length,
      distribution: status,
    });
  });

  app.post("/retry/:orgId", {
    preHandler: [authenticate, requireScope("admin")],
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    const { orgId } = request.params as { orgId: string };
    const results = await distributor.retryFailedDistributions(orgId);
    return reply.send({
      organizationId: orgId,
      retried: results.length,
      results,
    });
  });

  app.get("/history", {
    preHandler: [authenticate, requireScope("read")],
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    const { limit, offset } = (request.query as Record<string, string>) || {};
    const allHistory = distributor.getHistory();
    const lim = parseInt(limit || "50", 10);
    const off = parseInt(offset || "0", 10);
    return reply.send(allHistory.slice(off, off + lim));
  });
}
