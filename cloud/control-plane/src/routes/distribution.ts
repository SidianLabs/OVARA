import { FastifyInstance, FastifyRequest, FastifyReply } from "fastify";
import { db } from "../db/connection";
import { policies, gateways, policyDistributions } from "../db/schema";
import { authenticate, requireOrg, requireScope } from "../middleware/auth";
import { publishToGatewaysSchema, publishToGatewaySchema, paginationSchema } from "../schemas";
import { eq, and } from "drizzle-orm";
import { PolicyDistributor } from "../distribution/distributor";
import type { Policy } from "../distribution/types";

const distributor = new PolicyDistributor();

export function distributionRoutes(app: FastifyInstance) {

  app.post("/publish", {
    preHandler: [authenticate, requireScope("admin")],
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    const auth = await authenticate(request);
    const body = publishToGatewaysSchema.parse(request.body || {});
    const { policyId, organizationId } = body;

    // organizationId is accepted for backwards compatibility but must match
    // the authenticated org; the effective org always comes from auth.
    if (organizationId && organizationId !== auth.organizationId) {
      return reply.status(403).send({ error: "Forbidden: organization does not match authenticated credentials" });
    }

    const policy = await db.query.policies.findFirst({
      where: eq(policies.id, policyId),
    });
    // Uniform 404 for missing or cross-org policies to avoid existence oracles.
    if (!policy || policy.organizationId !== auth.organizationId) {
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

    const results = await distributor.distributePolicy(auth.organizationId, policyData);
    return reply.send({
      policyId,
      organizationId: auth.organizationId,
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
    const auth = await authenticate(request);
    const { gatewayId } = request.params as { gatewayId: string };
    const { policyId } = publishToGatewaySchema.parse(request.body || {});

    const policy = await db.query.policies.findFirst({
      where: eq(policies.id, policyId),
    });
    if (!policy || policy.organizationId !== auth.organizationId) {
      return reply.status(404).send({ error: "Policy not found" });
    }

    const gateway = await db.query.gateways.findFirst({
      where: eq(gateways.id, gatewayId),
    });
    if (!gateway || gateway.organizationId !== auth.organizationId) {
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
    await requireOrg(request, orgId);

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
    await requireOrg(request, orgId);
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
    const auth = await authenticate(request);
    const { limit, offset } = paginationSchema.parse(request.query || {});
    const orgHistory = distributor.getHistory(auth.organizationId);
    return reply.send(orgHistory.slice(offset, offset + limit));
  });
}
