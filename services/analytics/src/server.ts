import Fastify from "fastify";

const app = Fastify({ logger: true });

app.get("/v1/analytics/summary", async () => ({
  total_decisions: 0,
  allow_rate: 0,
  avg_latency_ms: 0,
  active_gateways: 0,
}));

app.get("/v1/analytics/trends", async () => ({
  hourly: [],
  daily: [],
}));

app.listen({ port: 8083, host: "0.0.0.0" });
