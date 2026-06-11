import Fastify, { FastifyRequest, FastifyReply } from "fastify";
import cors from "@fastify/cors";
import cookie from "@fastify/cookie";
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

function getOIDCProvider(orgId: string): OIDCProvider | null {
  const config = oidcConfigs.get(orgId);
  if (!config) return null;
  return new OIDCProvider(config);
}

function validateOrgId(orgId: string): boolean {
  return /^[a-zA-Z0-9_-]{1,64}$/.test(orgId);
}

export async function buildApp() {
  await app.register(cors, { origin: true, credentials: true });
  await app.register(cookie, { secret: process.env.COOKIE_SECRET || "ovara-cookie-secret" });

  app.addHook("onRequest", async (request: FastifyRequest, reply: FastifyReply) => {
    const clientIp = request.ip || request.socket.remoteAddress || "unknown";
    const key = `${clientIp}:${request.url}`;
    if (!checkRateLimit(key)) {
      return reply.status(429).send({ error: "Rate limit exceeded" });
    }
  });

  app.post("/sso/:orgId/configure", async (request, reply) => {
    const { orgId } = request.params as { orgId: string };
    if (!validateOrgId(orgId)) {
      return reply.status(400).send({ error: "Invalid organization ID" });
    }

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

    const state = `${orgId}:${Date.now()}`;
    const nonce = `${Date.now()}${Math.random().toString(36).slice(2)}`;

    const provider = getOIDCProvider(orgId);
    if (!provider) {
      return reply.status(400).send({ error: "SSO not configured for this organization" });
    }

    const url = provider.getAuthUrl(state, nonce);
    reply.header("Set-Cookie", `ovara_sso_state=${state}; HttpOnly; Secure; SameSite=Lax; Path=/`);
    reply.header("Set-Cookie", `ovara_sso_nonce=${nonce}; HttpOnly; Secure; SameSite=Lax; Path=/`);
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

    const provider = getOIDCProvider(orgId);
    if (!provider) {
      return reply.status(400).send({ error: "SSO not configured" });
    }

    try {
      const tokens = await provider.exchangeCode(code);
      const nonce = request.cookies?.ovara_sso_nonce || "";
      const claims = await provider.verifyIdToken(tokens.idToken, nonce);
      const user = await provider.toUser(claims);

      const jwtToken = await signUserToken(user);

      reply.header("Set-Cookie", `ovara_sso_state=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0`);
      reply.header("Set-Cookie", `ovara_sso_nonce=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0`);

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

    const { SAMLResponse, RelayState } = request.body as any;
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
      const token = await signUserToken(user);
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

async function signUserToken(user: any): Promise<string> {
  const { SignJWT } = await import("jose");
  const secret = new TextEncoder().encode(process.env.JWT_SECRET || "ovara-dev-secret-change-me");
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
