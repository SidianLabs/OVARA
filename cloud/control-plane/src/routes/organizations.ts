import { FastifyInstance, FastifyRequest, FastifyReply } from "fastify";
import { db } from "../db/connection";
import { organizations } from "../db/schema";
import { createOrganizationSchema, updateOrganizationSchema } from "../schemas";
import { authenticate, requireScope } from "../middleware/auth";
import { eq } from "drizzle-orm";

export function organizationRoutes(app: FastifyInstance) {

  app.post("/", {
    preHandler: [authenticate, requireScope("admin")],
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    const auth = await authenticate(request);
    const body = createOrganizationSchema.parse(request.body);

    // There is no platform-admin identity, so a key may only create
    // organizations under the tenant that owns the caller's organization.
    // tenantId is derived from auth context, never from the request body.
    const callerOrg = await db.query.organizations.findFirst({
      where: eq(organizations.id, auth.organizationId),
    });
    if (!callerOrg) {
      return reply.status(404).send({ error: "Organization not found" });
    }

    const [org] = await db.insert(organizations)
      .values({ tenantId: callerOrg.tenantId, name: body.name, displayName: body.displayName })
      .returning();
    return reply.status(201).send(org);
  });

  app.get("/", {
    preHandler: [authenticate, requireScope("read")],
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    const auth = await authenticate(request);
    // Keys are scoped to a single organization; listing returns only the
    // caller's own org.
    const own = await db.select().from(organizations)
      .where(eq(organizations.id, auth.organizationId));
    return reply.send(own);
  });

  app.get("/:id", {
    preHandler: [authenticate, requireScope("read")],
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    const auth = await authenticate(request);
    const { id } = request.params as { id: string };
    const org = await db.query.organizations.findFirst({ where: eq(organizations.id, id) });
    // Uniform 404 for missing or cross-org resources to avoid existence oracles.
    if (!org || org.id !== auth.organizationId) {
      return reply.status(404).send({ error: "Organization not found" });
    }
    return reply.send(org);
  });

  app.patch("/:id", {
    preHandler: [authenticate, requireScope("admin")],
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    const auth = await authenticate(request);
    const { id } = request.params as { id: string };
    const existing = await db.query.organizations.findFirst({ where: eq(organizations.id, id) });
    if (!existing || existing.id !== auth.organizationId) {
      return reply.status(404).send({ error: "Organization not found" });
    }

    const body = updateOrganizationSchema.parse(request.body);
    const [org] = await db.update(organizations)
      .set({ ...body, updatedAt: new Date() })
      .where(eq(organizations.id, id))
      .returning();
    if (!org) return reply.status(404).send({ error: "Organization not found" });
    return reply.send(org);
  });
}
