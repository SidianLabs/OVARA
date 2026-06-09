import { FastifyInstance, FastifyRequest, FastifyReply } from "fastify";
import { db } from "../db/connection";
import { revocations } from "../db/schema";
import { createRevocationSchema } from "../schemas";
import { authenticate, requireScope } from "../middleware/auth";
import { eq } from "drizzle-orm";

export function revocationRoutes(app: FastifyInstance) {

  app.post("/", {
    preHandler: [authenticate, requireScope("admin")],
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    const body = createRevocationSchema.parse(request.body);
    const [rev] = await db.insert(revocations)
      .values({
        organizationId: body.organizationId,
        leaseId: body.leaseId,
        reason: body.reason,
      })
      .returning();
    return reply.status(201).send(rev);
  });

  app.post("/:id/execute", {
    preHandler: [authenticate, requireScope("admin")],
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    const { id } = request.params as { id: string };
    const [rev] = await db.update(revocations)
      .set({ status: "executed", executedAt: new Date() })
      .where(eq(revocations.id, id))
      .returning();
    if (!rev) return reply.status(404).send({ error: "Revocation not found" });
    return reply.send(rev);
  });

  app.get("/", {
    preHandler: [authenticate, requireScope("read")],
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    const query = request.query as Record<string, string>;
    const all = query.organizationId
      ? await db.select().from(revocations).where(eq(revocations.organizationId, query.organizationId))
      : await db.select().from(revocations);
    return reply.send(all);
  });

  app.get("/:id", {
    preHandler: [authenticate, requireScope("read")],
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    const { id } = request.params as { id: string };
    const rev = await db.query.revocations.findFirst({ where: eq(revocations.id, id) });
    if (!rev) return reply.status(404).send({ error: "Revocation not found" });
    return reply.send(rev);
  });
}
