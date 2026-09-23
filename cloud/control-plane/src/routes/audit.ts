import { FastifyInstance, FastifyRequest, FastifyReply } from "fastify";
import { db } from "../db/connection";
import { auditLog } from "../db/schema";
import { authenticate, requireScope } from "../middleware/auth";
import { eq, desc } from "drizzle-orm";

export function auditRoutes(app: FastifyInstance) {
  app.get("/", {
    preHandler: [authenticate, requireScope("read")],
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    const auth = await authenticate(request);
    const query = request.query as Record<string, string>;
    const limit = Math.min(parseInt(query.limit ?? "100", 10) || 100, 500);
    const rows = await db.select().from(auditLog)
      .where(eq(auditLog.organizationId, auth.organizationId))
      .orderBy(desc(auditLog.createdAt))
      .limit(limit);
    return reply.send(rows);
  });
}
