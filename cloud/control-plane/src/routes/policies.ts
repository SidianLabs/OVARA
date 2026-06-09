import { FastifyInstance, FastifyRequest, FastifyReply } from "fastify";
import { db } from "../db/connection";
import { policies, policyDistributions, gateways } from "../db/schema";
import { createPolicySchema, publishPolicySchema, paginationSchema } from "../schemas";
import { authenticate, requireScope } from "../middleware/auth";
import { eq, and } from "drizzle-orm";

export function policyRoutes(app: FastifyInstance) {

  app.post("/", {
    preHandler: [authenticate, requireScope("admin")],
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    const body = createPolicySchema.parse(request.body);
    const [policy] = await db.insert(policies)
      .values({
        organizationId: body.organizationId,
        name: body.name,
        rules: body.rules,
        status: "draft",
      })
      .returning();
    return reply.status(201).send(policy);
  });

  app.post("/:id/publish", {
    preHandler: [authenticate, requireScope("admin")],
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    const { id } = request.params as { id: string };
    const body = publishPolicySchema.parse(request.body || {});

    const [policy] = await db.update(policies)
      .set({ status: "published", publishedAt: new Date(), updatedAt: new Date() })
      .where(eq(policies.id, id))
      .returning();
    if (!policy) return reply.status(404).send({ error: "Policy not found" });

    const targetGatewayIds = body.gatewayIds?.length
      ? body.gatewayIds
      : (await db.select({ id: gateways.id })
          .from(gateways)
          .where(eq(gateways.organizationId, policy.organizationId)))
          .map(g => g.id);

    if (targetGatewayIds.length > 0) {
      await db.insert(policyDistributions).values(
        targetGatewayIds.map(gwId => ({
          policyId: policy.id,
          gatewayId: gwId,
          status: "pending",
        }))
      );
    }

    return reply.send({ ...policy, distributedTo: targetGatewayIds.length });
  });

  app.get("/", {
    preHandler: [authenticate, requireScope("read")],
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    const query = paginationSchema.parse(request.query);
    const orgId = (request.query as Record<string, string>).organizationId;

    let rows;
    if (orgId) {
      rows = await db.select().from(policies)
        .where(eq(policies.organizationId, orgId))
        .limit(query.limit).offset(query.offset);
    } else {
      rows = await db.select().from(policies)
        .limit(query.limit).offset(query.offset);
    }
    return reply.send(rows);
  });

  app.get("/:id", {
    preHandler: [authenticate, requireScope("read")],
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    const { id } = request.params as { id: string };
    const policy = await db.query.policies.findFirst({ where: eq(policies.id, id) });
    if (!policy) return reply.status(404).send({ error: "Policy not found" });
    return reply.send(policy);
  });

  app.delete("/:id", {
    preHandler: [authenticate, requireScope("admin")],
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    const { id } = request.params as { id: string };
    await db.delete(policies).where(eq(policies.id, id));
    return reply.status(204).send();
  });

  app.get("/distributions/:gatewayId", {
    preHandler: [authenticate, requireScope("read")],
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    const { gatewayId } = request.params as { gatewayId: string };
    const dists = await db.select().from(policyDistributions)
      .where(eq(policyDistributions.gatewayId, gatewayId));
    return reply.send(dists);
  });
}
