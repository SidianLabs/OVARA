import Fastify, { FastifyRequest, FastifyReply } from "fastify";
import cors from "@fastify/cors";
import cookie from "@fastify/cookie";
import { randomBytes, randomUUID, timingSafeEqual } from "crypto";
import { OIDCProvider, SAMLProvider } from "./providers";
import { ssoConfigSchema, samlConfigSchema } from "./types";

const app = Fastify({ logger: true });

const oidcConfigs: Map<string, any> = new Map();

const rateLimitStore = new Map<string, { count: number; resetAt: number }>();
const RATE_LIMIT_WINDOW_MS = 60_000;
const RATE_LIMIT_MAX = 30;

function checkRateLimit(key: string): boolean {
  const now = Date.now();
  const entry = rateLimitStore.get(key);
  if (!entry || now > entry.resetAt) {
    rateLimitStore.set(key, { count: 1, resetAt: now + RATE_LIMIT_WINDOW_MS });
    return true;
  }
  if (entry.count >= RATE_LIMIT_MAX) return false;
  entry.count++;
  return true;
}

// Periodically evict expired entries so the store cannot grow unboundedly.
setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of rateLimitStore) {
    if (now > entry.resetAt) rateLimitStore.delete(key);
  }
}, RATE_LIMIT_WINDOW_MS).unref();

function getOIDCProvider(orgId: string): OIDCProvider | null {
  const config = oidcConfigs.get(orgId);
  if (!config) return null;
  return new OIDCProvider(config);
}

function validateOrgId(orgId: string): boolean {
  return /^[a-zA-Z0-9_-]{1,64}$/.test(orgId);
}

function safeEqual(a: string, b: string): boolean {
  const ba = Buffer.from(a);
  const bb = Buffer.from(b);
  return ba.length === bb.length && timingSafeEqual(ba, bb);
}

/**
 * Admin bearer auth for configuration endpoints. Fails closed: when
 * OVARA_SSO_ADMIN_TOKEN is unset every admin request is rejected.
 */
function requireAdmin(request: FastifyRequest, reply: FastifyReply): boolean {
  const adminToken = process.env.OVARA_SSO_ADMIN_TOKEN;
  if (!adminToken) {
    reply.status(503).send({ error: "SSO admin token not configured" });
    return false;
  }
  const header = request.headers["authorization"];
  if (!header || !header.startsWith("Bearer ") || !safeEqual(header.slice(7), adminToken)) {
    reply.status(401).send({ error: "Unauthorized" });
    return false;
  }
  return true;
}

export async function buildApp() {
  // Fail fast: never sign tokens with a default/guessable secret.
  const jwtSecret = process.env.JWT_SECRET;
  if (!jwtSecret) {
    throw new Error("JWT_SECRET environment variable is required — refusing to start");
  }

  const cookieSecret = process.env.COOKIE_SECRET || randomBytes(32).toString("hex");
  if (!process.env.COOKIE_SECRET) {
    app.log.warn("COOKIE_SECRET not set — using an ephemeral random secret (dev only)");
  }

  await app.register(cors, { origin: true, credentials: true });
  await app.register(cookie, { secret: cookieSecret });

  app.addHook("onRequest", async (request: FastifyRequest, reply: FastifyReply) => {
    const clientIp = request.ip || request.socket.remoteAddress || "unknown";
    if (!checkRateLimit(clientIp)) {
      return reply.status(429).send({ error: "Rate limit exceeded" });
    }
  });

  app.post("/sso/:orgId/configure", async (request, reply) => {
    const { orgId } = request.params as { orgId: string };
    if (!validateOrgId(orgId)) {
      return reply.status(400).send({ error: "Invalid organization ID" });
    }

    if (!requireAdmin(request, reply)) return;

    const parsed = ssoConfigSchema.safeParse(request.body);
    if (!parsed.success) {
      return reply.status(400).send({ error: "Invalid configuration", details: parsed.error.issues });
    }

    oidcConfigs.set(orgId, parsed.data);
    return reply.send({ status: "configured", orgId });
  });

  app.get("/sso/:orgId/login", async (request, reply) => {
    const { orgId } = request.params as { orgId: string };
    if (!validateOrgId(orgId)) {
      return reply.status(400).send({ error: "Invalid organization ID" });
    }

    const state = `${orgId}:${randomUUID()}`;
    const nonce = randomUUID();

    const provider = getOIDCProvider(orgId);
    if (!provider) {
      return reply.status(400).send({ error: "SSO not configured for this organization" });
    }

    const url = provider.getAuthUrl(state, nonce);
    reply.header("Set-Cookie", [
      `ovara_sso_state=${state}; HttpOnly; Secure; SameSite=Lax; Path=/`,
      `ovara_sso_nonce=${nonce}; HttpOnly; Secure; SameSite=Lax; Path=/`,
    ]);
    return reply.redirect(url);
  });

  app.get("/sso/:orgId/callback", async (request, reply) => {
    const { orgId } = request.params as { orgId: string };
    if (!validateOrgId(orgId)) {
      return reply.status(400).send({ error: "Invalid organization ID" });
    }

    const { code, state, error } = request.query as Record<string, string>;

    if (error) {
      return reply.status(400).send({ error: `SSO error: ${error}` });
    }

    if (!code) {
      return reply.status(400).send({ error: "Missing authorization code" });
    }

    // Validate the state parameter against the cookie set at /login and
    // confirm it was issued for this organization.
    const stateCookie = request.cookies?.ovara_sso_state;
    if (!state || !stateCookie || state !== stateCookie || !state.startsWith(`${orgId}:`)) {
      return reply.status(400).send({ error: "Invalid or mismatched SSO state" });
    }

    const provider = getOIDCProvider(orgId);
    if (!provider) {
      return reply.status(400).send({ error: "SSO not configured" });
    }

    try {
      const tokens = await provider.exchangeCode(code);
      const nonce = request.cookies?.ovara_sso_nonce || "";
      const claims = await provider.verifyIdToken(tokens.idToken, nonce);
      const user = await provider.toUser(claims, orgId);

      const jwtToken = await signUserToken(user, jwtSecret);

      reply.header("Set-Cookie", [
        "ovara_sso_state=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0",
        "ovara_sso_nonce=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0",
      ]);

      return reply.send({ user, token: jwtToken });
    } catch (err: any) {
      return reply.status(401).send({ error: `Authentication failed: ${err.message}` });
    }
  });

  app.post("/sso/:orgId/saml/callback", async (request, reply) => {
    const { orgId } = request.params as { orgId: string };
    if (!validateOrgId(orgId)) {
      return reply.status(400).send({ error: "Invalid organization ID" });
    }

    const { SAMLResponse } = request.body as any;
    if (!SAMLResponse) {
      return reply.status(400).send({ error: "Missing SAMLResponse" });
    }

    if (typeof SAMLResponse !== "string" || SAMLResponse.length > 1_000_000) {
      return reply.status(400).send({ error: "Invalid SAMLResponse" });
    }

    const config = oidcConfigs.get(orgId);
    if (!config || !config.x509Cert) {
      return reply.status(400).send({ error: "SAML not configured" });
    }

    try {
      const parsed = samlConfigSchema.safeParse(config);
      if (!parsed.success) {
        return reply.status(400).send({ error: "Invalid SAML configuration" });
      }
      const samlProvider = new SAMLProvider(parsed.data);
      const user = await samlProvider.parseAssertionResponse(SAMLResponse);
      user.organizationId = orgId;
      const token = await signUserToken(user, jwtSecret);
      return reply.send({ user, token });
    } catch (err: any) {
      return reply.status(401).send({ error: `SAML authentication failed: ${err.message}` });
    }
  });

  app.get("/sso/:orgId/config", async (request, reply) => {
    const { orgId } = request.params as { orgId: string };
    if (!validateOrgId(orgId)) {
      return reply.status(400).send({ error: "Invalid organization ID" });
    }

    if (!requireAdmin(request, reply)) return;

    const config = oidcConfigs.get(orgId);
    if (!config) return reply.status(404).send({ error: "No SSO config found" });
    const { clientSecret, ...safe } = config;
    return reply.send(safe);
  });

  app.get("/health", async () => {
    return { status: "ok", service: "ovara-sso", timestamp: new Date().toISOString() };
  });

  return app;
}

async function signUserToken(user: any, jwtSecret: string): Promise<string> {
  const { SignJWT } = await import("jose");
  const secret = new TextEncoder().encode(jwtSecret);
  return new SignJWT({ sub: user.id, email: user.email, org: user.organizationId, groups: user.groups })
    .setProtectedHeader({ alg: "HS256" })
    .setIssuedAt()
    .setExpirationTime("24h")
    .sign(secret);
}

if (require.main === module) {
  buildApp().then((app) => {
    const port = parseInt(process.env.PORT || "3001", 10);
    app.listen({ port, host: "0.0.0.0" }).then(() => {
      console.log(`SSO service listening on port ${port}`);
    });
  });
}
