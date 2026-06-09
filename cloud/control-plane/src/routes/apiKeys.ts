import { FastifyInstance, FastifyRequest, FastifyReply } from "fastify";
import { db } from "../db/connection";
import { apiKeys } from "../db/schema";
import { createApiKeySchema } from "../schemas";
import { authenticate, requireScope } from "../middleware/auth";
import { eq } from "drizzle-orm";
import { createHash, randomUUID } from "crypto";

export function apiKeyRoutes(app: FastifyInstance) {

  app.post("/", {
    preHandler: [authenticate, requireScope("admin")],
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    const body = createApiKeySchema.parse(request.body);
    const secret = randomUUID().replace(/-/g, "");
    const prefix = `ovara_${randomUUID().replace(/-/g, "").slice(0, 8)}`;
    const fullKey = `${prefix}.${secret}`;
    const keyHash = createHash("sha256").update(fullKey).digest("hex");

    const [key] = await db.insert(apiKeys)
      .values({
        organizationId: body.organizationId,
        name: body.name,
        keyHash,
        prefix,
        scopes: body.scopes,
        expiresAt: body.expiresAt ? new Date(body.expiresAt) : undefined,
      })
      .returning();

    return reply.status(201).send({ ...key, key: fullKey });
  });

  app.get("/", {
    preHandler: [authenticate, requireScope("read")],
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    const query = request.query as Record<string, string>;
    const all = query.organizationId
      ? await db.select({ id: apiKeys.id, name: apiKeys.name, prefix: apiKeys.prefix, scopes: apiKeys.scopes, expiresAt: apiKeys.expiresAt, lastUsedAt: apiKeys.lastUsedAt, createdAt: apiKeys.createdAt, revokedAt: apiKeys.revokedAt })
        .from(apiKeys).where(eq(apiKeys.organizationId, query.organizationId))
      : await db.select({ id: apiKeys.id, name: apiKeys.name, prefix: apiKeys.prefix, scopes: apiKeys.scopes, expiresAt: apiKeys.expiresAt, lastUsedAt: apiKeys.lastUsedAt, createdAt: apiKeys.createdAt, revokedAt: apiKeys.revokedAt })
        .from(apiKeys);
    return reply.send(all);
  });

  app.post("/:id/revoke", {
    preHandler: [authenticate, requireScope("admin")],
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    const { id } = request.params as { id: string };
    const [key] = await db.update(apiKeys)
      .set({ revokedAt: new Date() })
      .where(eq(apiKeys.id, id))
      .returning();
    if (!key) return reply.status(404).send({ error: "API key not found" });
    return reply.send({ id: key.id, name: key.name, revokedAt: key.revokedAt });
  });
}
