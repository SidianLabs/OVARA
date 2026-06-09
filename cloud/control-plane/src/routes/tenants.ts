import { FastifyInstance, FastifyRequest, FastifyReply } from "fastify";
import { db } from "../db/connection";
import { tenants } from "../db/schema";
import { createTenantSchema } from "../schemas";
import { authenticate, requireScope } from "../middleware/auth";
import { eq } from "drizzle-orm";

export function tenantRoutes(app: FastifyInstance) {

  app.post("/", {
    preHandler: [authenticate, requireScope("admin")],
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    const body = createTenantSchema.parse(request.body);
    const [tenant] = await db.insert(tenants)
      .values({ name: body.name, displayName: body.displayName, plan: body.plan })
      .returning();
    return reply.status(201).send(tenant);
  });

  app.get("/", {
    preHandler: [authenticate, requireScope("admin")],
  }, async (_request: FastifyRequest, reply: FastifyReply) => {
    const all = await db.select().from(tenants);
    return reply.send(all);
  });

  app.get("/:id", {
    preHandler: [authenticate, requireScope("admin")],
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    const { id } = request.params as { id: string };
    const tenant = await db.query.tenants.findFirst({ where: eq(tenants.id, id) });
    if (!tenant) return reply.status(404).send({ error: "Tenant not found" });
    return reply.send(tenant);
  });

  app.patch("/:id", {
    preHandler: [authenticate, requireScope("admin")],
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    const { id } = request.params as { id: string };
    const body = request.body as Record<string, unknown>;
    const [updated] = await db.update(tenants)
      .set({ ...body, updatedAt: new Date() } as any)
      .where(eq(tenants.id, id))
      .returning();
    if (!updated) return reply.status(404).send({ error: "Tenant not found" });
    return reply.send(updated);
  });
}
