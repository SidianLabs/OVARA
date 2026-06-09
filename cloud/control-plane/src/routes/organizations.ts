import { FastifyInstance, FastifyRequest, FastifyReply } from "fastify";
import { db } from "../db/connection";
import { organizations } from "../db/schema";
import { createOrganizationSchema } from "../schemas";
import { authenticate, requireScope } from "../middleware/auth";
import { eq } from "drizzle-orm";

export function organizationRoutes(app: FastifyInstance) {

  app.post("/", {
    preHandler: [authenticate, requireScope("admin")],
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    const body = createOrganizationSchema.parse(request.body);
    const [org] = await db.insert(organizations)
      .values({ tenantId: body.tenantId, name: body.name, displayName: body.displayName })
      .returning();
    return reply.status(201).send(org);
  });

  app.get("/", {
    preHandler: [authenticate, requireScope("read")],
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    const all = await db.select().from(organizations);
    return reply.send(all);
  });

  app.get("/:id", {
    preHandler: [authenticate, requireScope("read")],
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    const { id } = request.params as { id: string };
    const org = await db.query.organizations.findFirst({ where: eq(organizations.id, id) });
    if (!org) return reply.status(404).send({ error: "Organization not found" });
    return reply.send(org);
  });

  app.patch("/:id", {
    preHandler: [authenticate, requireScope("admin")],
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    const { id } = request.params as { id: string };
    const body = request.body as Record<string, unknown>;
    const [org] = await db.update(organizations)
      .set({ ...body, updatedAt: new Date() } as any)
      .where(eq(organizations.id, id))
      .returning();
    if (!org) return reply.status(404).send({ error: "Organization not found" });
    return reply.send(org);
  });
}
