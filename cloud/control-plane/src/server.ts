import Fastify from "fastify";
import cors from "@fastify/cors";
import helmet from "@fastify/helmet";
import rateLimit from "@fastify/rate-limit";
import { tenantRoutes } from "./routes/tenants";
import { organizationRoutes } from "./routes/organizations";
import { gatewayRoutes } from "./routes/gateways";
import { policyRoutes } from "./routes/policies";
import { revocationRoutes } from "./routes/revocations";
import { apiKeyRoutes } from "./routes/apiKeys";
import { db } from "./db/connection";

const app = Fastify({
  logger: {
    transport: process.env.NODE_ENV !== "production"
      ? { target: "pino-pretty" }
      : undefined,
  },
});

async function start() {
  await app.register(cors, { origin: true, credentials: true });
  await app.register(helmet);
  await app.register(rateLimit, { max: 100, timeWindow: "1 minute" });

  app.get("/health", async () => ({ status: "ok", timestamp: new Date().toISOString() }));

  await app.register(tenantRoutes, { prefix: "/v1/tenants" });
  await app.register(organizationRoutes, { prefix: "/v1/organizations" });
  await app.register(gatewayRoutes, { prefix: "/v1/gateways" });
  await app.register(policyRoutes, { prefix: "/v1/policies" });
  await app.register(revocationRoutes, { prefix: "/v1/revocations" });
  await app.register(apiKeyRoutes, { prefix: "/v1/api-keys" });

  app.setErrorHandler((error, _request, reply) => {
    const err = error as Error & { statusCode?: number };
    if (err.statusCode) {
      return reply.status(err.statusCode).send({
        error: err.message || "Internal server error",
      });
    }
    app.log.error(err);
    return reply.status(500).send({ error: "Internal server error" });
  });

  const port = parseInt(process.env.PORT || "3000", 10);
  await app.listen({ port, host: "0.0.0.0" });
  app.log.info(`Ovara control plane listening on port ${port}`);
}

start().catch((err) => {
  console.error("Fatal startup error:", err);
  process.exit(1);
});

export { app };
