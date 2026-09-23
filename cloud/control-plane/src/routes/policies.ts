import { FastifyInstance, FastifyRequest, FastifyReply } from "fastify";
import { db } from "../db/connection";
import { policies, policyDistributions, gateways } from "../db/schema";
import { createPolicySchema, publishPolicySchema, paginationSchema } from "../schemas";
import { authenticate, requireScope } from "../middleware/auth";
import { writeAudit } from "../audit";
import { eq, inArray } from "drizzle-orm";

export function policyRoutes(app: FastifyInstance) {

  app.post("/", {
    preHandler: [authenticate, requireScope("admin")],
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    const auth = await authenticate(request);
    const body = createPolicySchema.parse(request.body);
    const [policy] = await db.insert(policies)
      .values({
        organizationId: auth.organizationId,
        name: body.name,
        rules: body.rules,
        status: "draft",
      })
      .returning();
    await writeAudit(auth, request, "policy.create", "policy", policy.id, { name: policy.name });
    return reply.status(201).send(policy);
  });

  app.post("/:id/publish", {
    preHandler: [authenticate, requireScope("admin")],
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    const { id } = request.params as { id: string };
    const body = publishPolicySchema.parse(request.body || {});

    const auth = await authenticate(request);
    const existing = await db.query.policies.findFirst({ where: eq(policies.id, id) });
    // Uniform 404 for missing or cross-org policies to avoid existence oracles.
    if (!existing || existing.organizationId !== auth.organizationId) {
      return reply.status(404).send({ error: "Policy not found" });
    }

    const [policy] = await db.update(policies)
      .set({ status: "published", publishedAt: new Date(), updatedAt: new Date() })
      .where(eq(policies.id, id))
      .returning();
    if (!policy) return reply.status(404).send({ error: "Policy not found" });

    let targetGatewayIds: string[];
    if (body.gatewayIds?.length) {
      // Explicit targets must all exist and belong to the authenticated
      // org. Uniform 404 for missing or cross-org gateways to avoid
      // existence oracles.
      const targets = await db.select({ id: gateways.id, organizationId: gateways.organizationId })
        .from(gateways)
        .where(inArray(gateways.id, body.gatewayIds));
      if (targets.length !== body.gatewayIds.length ||
          targets.some((g) => g.organizationId !== auth.organizationId)) {
        return reply.status(404).send({ error: "Gateway not found" });
      }
      targetGatewayIds = targets.map((g) => g.id);
    } else {
      targetGatewayIds = (await db.select({ id: gateways.id })
        .from(gateways)
        .where(eq(gateways.organizationId, auth.organizationId)))
        .map(g => g.id);
    }

    if (targetGatewayIds.length > 0) {
      await db.insert(policyDistributions).values(
        targetGatewayIds.map(gwId => ({
          policyId: policy.id,
          gatewayId: gwId,
          status: "pending",
        }))
      );
    }

    await writeAudit(auth, request, "policy.publish", "policy", policy.id, { name: policy.name, distributedTo: targetGatewayIds.length });
    return reply.send({ ...policy, distributedTo: targetGatewayIds.length });
  });

  app.get("/", {
    preHandler: [authenticate, requireScope("read")],
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    const auth = await authenticate(request);
    const query = paginationSchema.parse(request.query);
    const orgId = (request.query as Record<string, string>).organizationId;
    if (orgId && orgId !== auth.organizationId) {
      return reply.status(403).send({ error: "Forbidden: organization does not match authenticated credentials" });
    }

    const rows = await db.select().from(policies)
      .where(eq(policies.organizationId, auth.organizationId))
      .limit(query.limit).offset(query.offset);
    return reply.send(rows);
  });

  app.get("/:id", {
    preHandler: [authenticate, requireScope("read")],
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    const auth = await authenticate(request);
    const { id } = request.params as { id: string };
    const policy = await db.query.policies.findFirst({ where: eq(policies.id, id) });
    if (!policy || policy.organizationId !== auth.organizationId) {
      return reply.status(404).send({ error: "Policy not found" });
    }
    return reply.send(policy);
  });

  app.delete("/:id", {
    preHandler: [authenticate, requireScope("admin")],
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    const auth = await authenticate(request);
    const { id } = request.params as { id: string };
    const policy = await db.query.policies.findFirst({ where: eq(policies.id, id) });
    if (!policy || policy.organizationId !== auth.organizationId) {
      return reply.status(404).send({ error: "Policy not found" });
    }
    await db.delete(policies).where(eq(policies.id, id));
    return reply.status(204).send();
  });

  app.get("/distributions/:gatewayId", {
    preHandler: [authenticate, requireScope("read")],
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    const auth = await authenticate(request);
    const { gatewayId } = request.params as { gatewayId: string };
    const gateway = await db.query.gateways.findFirst({ where: eq(gateways.id, gatewayId) });
    if (!gateway || gateway.organizationId !== auth.organizationId) {
      return reply.status(404).send({ error: "Gateway not found" });
    }
    const dists = await db.select().from(policyDistributions)
      .where(eq(policyDistributions.gatewayId, gatewayId));
    return reply.send(dists);
  });
}
