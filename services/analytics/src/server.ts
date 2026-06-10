import Fastify from "fastify";
import cors from "@fastify/cors";
import { AnalyticsEngine } from "./engine";

const engine = new AnalyticsEngine(100000);

export async function buildApp() {
  const app = Fastify({ logger: false });
  await app.register(cors);

  app.post("/v1/analytics/ingest", async (request, reply) => {
    const body = request.body as any;
    if (!body || !body.events || !Array.isArray(body.events)) {
      return reply.status(400).send({ error: "events array required" });
    }
    engine.ingestBatch(body.events);
    return reply.send({
      ingested: body.events.length,
      total: engine.stats().totalEvents,
    });
  });

  app.get("/v1/analytics/summary", async (request, reply) => {
    const query = request.query as Record<string, string>;
    const window = parseInt(query.window || "60", 10);
    return reply.send(engine.computeSummary(window));
  });

  app.get("/v1/analytics/trends", async (request, reply) => {
    const query = request.query as Record<string, string>;
    const hours = parseInt(query.hours || "24", 10);
    return reply.send(engine.computeTrends(hours));
  });

  app.get("/v1/analytics/stats", async (request, reply) => {
    return reply.send(engine.stats());
  });

  app.post("/v1/analytics/clear", async (request, reply) => {
    engine.clear();
    return reply.send({ status: "cleared" });
  });

  return app;
}

if (require.main === module) {
  buildApp().then((app) => {
    app.listen({ port: 8083, host: "0.0.0.0" }).then(() => {
      console.log("Analytics service on port 8083");
    });
  });
}
