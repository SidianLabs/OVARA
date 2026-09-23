import { FastifyRequest } from "fastify";
import { db } from "./db/connection";
import { auditLog } from "./db/schema";
import { AuthContext } from "./middleware/auth";

export async function writeAudit(
  auth: AuthContext,
  request: FastifyRequest,
  action: string,
  resource: string,
  resourceId?: string,
  details: Record<string, unknown> = {},
): Promise<void> {
  await db.insert(auditLog).values({
    organizationId: auth.organizationId,
    actor: `apikey:${auth.keyId}`,
    action,
    resource,
    resourceId,
    details,
    ip: request.ip,
    userAgent: request.headers["user-agent"],
  });
}
