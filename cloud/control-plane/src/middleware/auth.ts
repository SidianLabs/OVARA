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

  return {
    organizationId: key.organizationId,
    scopes: key.scopes as string[],
    keyId: key.id,
  };
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
