import { FastifyRequest } from "fastify";
import { db } from "../db/connection";
import { apiKeys } from "../db/schema";
import { eq, and, gt, isNull } from "drizzle-orm";
import { createHash } from "crypto";

export interface AuthContext {
  organizationId: string;
  scopes: string[];
  keyId: string;
}

export async function authenticate(request: FastifyRequest): Promise<AuthContext> {
  if ((request as any).auth) {
    return (request as any).auth as AuthContext;
  }

  const header = request.headers["authorization"];
  if (!header || !header.startsWith("Bearer ")) {
    throw { statusCode: 401, message: "Missing authorization header" };
  }

  const token = header.slice(7);
  const [prefix, secret] = token.split(".");

  if (!prefix || !secret) {
    throw { statusCode: 401, message: "Invalid API key format" };
  }

  const keyHash = createHash("sha256").update(token).digest("hex");

  const key = await db.query.apiKeys.findFirst({
    where: and(
      eq(apiKeys.keyHash, keyHash),
      isNull(apiKeys.revokedAt),
      gt(apiKeys.expiresAt || new Date(0), new Date())
    ),
  });

  if (!key) {
    throw { statusCode: 401, message: "Invalid or expired API key" };
  }

  await db.update(apiKeys)
    .set({ lastUsedAt: new Date() })
    .where(eq(apiKeys.id, key.id));

  const auth: AuthContext = {
    organizationId: key.organizationId,
    scopes: key.scopes as string[],
    keyId: key.id,
  };
  (request as any).auth = auth;
  return auth;
}

/**
 * Tenant isolation guard: returns the authenticated context only when the
 * requested organization matches the API key's organization. Throws 403 on
 * mismatch so callers can never act across org boundaries.
 */
export async function requireOrg(
  request: FastifyRequest,
  organizationId: string,
): Promise<AuthContext> {
  const auth = await authenticate(request);
  if (!organizationId || auth.organizationId !== organizationId) {
    throw { statusCode: 403, message: "Forbidden: organization does not match authenticated credentials" };
  }
  return auth;
}

export function requireScope(required: string) {
  return async (request: FastifyRequest) => {
    const auth = await authenticate(request);
    if (!auth.scopes.includes(required) && !auth.scopes.includes("*")) {
      throw { statusCode: 403, message: `Missing required scope: ${required}` };
    }
    return auth;
  };
}
