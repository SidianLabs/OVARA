import { FastifyInstance, FastifyRequest, FastifyReply } from "fastify";
import { db } from "../db/connection";
import { gateways } from "../db/schema";
import { enrollGatewaySchema } from "../schemas";
import { authenticate, requireScope } from "../middleware/auth";
import { eq } from "drizzle-orm";
import { randomUUID } from "crypto";

export function gatewayRoutes(app: FastifyInstance) {

  app.post("/enroll", {
    preHandler: [authenticate, requireScope("admin")],
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    const body = enrollGatewaySchema.parse(request.body);
    const enrollmentToken = `ovara_enr_${randomUUID().replace(/-/g, "")}`;
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);

    const [gw] = await db.insert(gateways)
      .values({
        organizationId: body.organizationId,
        name: body.name,
        environment: body.environment,
        region: body.region,
        publicKey: body.publicKey,
        enrollmentToken,
        enrollmentExpiresAt: expiresAt,
        status: "enrolling",
      })
      .returning();

    return reply.status(201).send(gw);
  });

  app.post("/confirm/:id", {
    preHandler: [authenticate, requireScope("admin")],
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    const { id } = request.params as { id: string };
    const [gw] = await db.update(gateways)
      .set({ status: "active", enrollmentToken: null, enrollmentExpiresAt: null, updatedAt: new Date() })
      .where(eq(gateways.id, id))
      .returning();
    if (!gw) return reply.status(404).send({ error: "Gateway not found" });
    return reply.send(gw);
  });

  app.get("/", {
    preHandler: [authenticate, requireScope("read")],
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    const query = request.query as Record<string, string>;
    const all = query.organizationId
      ? await db.select().from(gateways).where(eq(gateways.organizationId, query.organizationId))
      : await db.select().from(gateways);
    return reply.send(all);
  });

  app.get("/:id", {
    preHandler: [authenticate, requireScope("read")],
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    const { id } = request.params as { id: string };
    const gw = await db.query.gateways.findFirst({ where: eq(gateways.id, id) });
    if (!gw) return reply.status(404).send({ error: "Gateway not found" });
    return reply.send(gw);
  });

  app.post("/:id/heartbeat", {
    preHandler: [authenticate, requireScope("write")],
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    const { id } = request.params as { id: string };
    const [gw] = await db.update(gateways)
      .set({ lastHeartbeat: new Date(), updatedAt: new Date() })
      .where(eq(gateways.id, id))
      .returning();
    if (!gw) return reply.status(404).send({ error: "Gateway not found" });
    return reply.send(gw);
  });

  app.delete("/:id", {
    preHandler: [authenticate, requireScope("admin")],
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    const { id } = request.params as { id: string };
    await db.delete(gateways).where(eq(gateways.id, id));
    return reply.status(204).send();
  });
}
