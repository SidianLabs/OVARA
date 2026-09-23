import { FastifyInstance, FastifyRequest, FastifyReply } from "fastify";
import { db } from "../db/connection";
import { gateways } from "../db/schema";
import { enrollGatewaySchema } from "../schemas";
import { authenticate, requireScope } from "../middleware/auth";
import { writeAudit } from "../audit";
import { eq } from "drizzle-orm";
import { randomUUID } from "crypto";

export function gatewayRoutes(app: FastifyInstance) {

  app.post("/enroll", {
    preHandler: [authenticate, requireScope("admin")],
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    const auth = await authenticate(request);
    const body = enrollGatewaySchema.parse(request.body);
    const enrollmentToken = `ovara_enr_${randomUUID().replace(/-/g, "")}`;
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);

    const [gw] = await db.insert(gateways)
      .values({
        organizationId: auth.organizationId,
        name: body.name,
        environment: body.environment,
        region: body.region,
        publicKey: body.publicKey,
        endpointUrl: body.endpointUrl,
        allowInsecure: body.allowInsecure,
        enrollmentToken,
        enrollmentExpiresAt: expiresAt,
        status: "enrolling",
      })
      .returning();

    await writeAudit(auth, request, "gateway.enroll", "gateway", gw.id, { name: gw.name });
    return reply.status(201).send(gw);
  });

  app.post("/confirm/:id", {
    preHandler: [authenticate, requireScope("admin")],
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    const auth = await authenticate(request);
    const { id } = request.params as { id: string };
    const existing = await db.query.gateways.findFirst({ where: eq(gateways.id, id) });
    // Uniform 404 for missing or cross-org gateways to avoid existence oracles.
    if (!existing || existing.organizationId !== auth.organizationId) {
      return reply.status(404).send({ error: "Gateway not found" });
    }
    const [gw] = await db.update(gateways)
      .set({ status: "online", enrollmentToken: null, enrollmentExpiresAt: null, updatedAt: new Date() })
      .where(eq(gateways.id, id))
      .returning();
    if (!gw) return reply.status(404).send({ error: "Gateway not found" });
    await writeAudit(auth, request, "gateway.confirm", "gateway", gw.id, { name: gw.name });
    return reply.send(gw);
  });

  app.get("/", {
    preHandler: [authenticate, requireScope("read")],
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    const auth = await authenticate(request);
    const query = request.query as Record<string, string>;
    if (query.organizationId && query.organizationId !== auth.organizationId) {
      return reply.status(403).send({ error: "Forbidden: organization does not match authenticated credentials" });
    }
    const all = await db.select().from(gateways)
      .where(eq(gateways.organizationId, auth.organizationId));
    return reply.send(all);
  });

  app.get("/:id", {
    preHandler: [authenticate, requireScope("read")],
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    const auth = await authenticate(request);
    const { id } = request.params as { id: string };
    const gw = await db.query.gateways.findFirst({ where: eq(gateways.id, id) });
    if (!gw || gw.organizationId !== auth.organizationId) {
      return reply.status(404).send({ error: "Gateway not found" });
    }
    return reply.send(gw);
  });

  app.post("/:id/heartbeat", {
    preHandler: [authenticate, requireScope("write")],
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    const auth = await authenticate(request);
    const { id } = request.params as { id: string };
    const existing = await db.query.gateways.findFirst({ where: eq(gateways.id, id) });
    if (!existing || existing.organizationId !== auth.organizationId) {
      return reply.status(404).send({ error: "Gateway not found" });
    }
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
    const auth = await authenticate(request);
    const { id } = request.params as { id: string };
    const existing = await db.query.gateways.findFirst({ where: eq(gateways.id, id) });
    if (!existing || existing.organizationId !== auth.organizationId) {
      return reply.status(404).send({ error: "Gateway not found" });
    }
    await db.delete(gateways).where(eq(gateways.id, id));
    await writeAudit(auth, request, "gateway.delete", "gateway", id, { name: existing.name });
    return reply.status(204).send();
  });
}
