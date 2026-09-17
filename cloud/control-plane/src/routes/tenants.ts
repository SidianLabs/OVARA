import { FastifyInstance, FastifyRequest, FastifyReply } from "fastify";
import { db } from "../db/connection";
import { tenants, organizations } from "../db/schema";
import { createTenantSchema, updateTenantSchema } from "../schemas";
import { authenticate, requireScope } from "../middleware/auth";
import { eq } from "drizzle-orm";

// Resolves the tenant that owns the caller's organization. Tenant records
// are not org-scoped, so tenant isolation is enforced through the caller's
// organization -> tenant link.
async function callerTenantId(organizationId: string): Promise<string | null> {
  const org = await db.query.organizations.findFirst({
    where: eq(organizations.id, organizationId),
  });
  return org?.tenantId ?? null;
}

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
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    const auth = await authenticate(request);
    const tenantId = await callerTenantId(auth.organizationId);
    if (!tenantId) return reply.send([]);
    const rows = await db.select().from(tenants).where(eq(tenants.id, tenantId));
    return reply.send(rows);
  });

  app.get("/:id", {
    preHandler: [authenticate, requireScope("admin")],
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    const auth = await authenticate(request);
    const { id } = request.params as { id: string };
    const tenant = await db.query.tenants.findFirst({ where: eq(tenants.id, id) });
    const tenantId = await callerTenantId(auth.organizationId);
    // Uniform 404 for missing or cross-tenant resources.
    if (!tenant || tenant.id !== tenantId) {
      return reply.status(404).send({ error: "Tenant not found" });
    }
    return reply.send(tenant);
  });

  app.patch("/:id", {
    preHandler: [authenticate, requireScope("admin")],
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    const auth = await authenticate(request);
    const { id } = request.params as { id: string };
    const existing = await db.query.tenants.findFirst({ where: eq(tenants.id, id) });
    const tenantId = await callerTenantId(auth.organizationId);
    if (!existing || existing.id !== tenantId) {
      return reply.status(404).send({ error: "Tenant not found" });
    }

    const body = updateTenantSchema.parse(request.body);
    const [updated] = await db.update(tenants)
      .set({ ...body, updatedAt: new Date() })
      .where(eq(tenants.id, id))
      .returning();
    if (!updated) return reply.status(404).send({ error: "Tenant not found" });
    return reply.send(updated);
  });
}
