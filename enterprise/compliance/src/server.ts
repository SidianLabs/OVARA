import Fastify, { FastifyRequest, FastifyReply } from "fastify";
import cors from "@fastify/cors";
import { ComplianceReportGenerator, AuditPipeline } from "./generator";
import { ComplianceReport, AuditExport } from "./types";

const app = Fastify({ logger: true });
const pipeline = new AuditPipeline(50000);
const reportGenerator = new ComplianceReportGenerator();

const rateLimitStore = new Map<string, { count: number; resetAt: number }>();
const RATE_LIMIT_WINDOW_MS = 60_000;
const RATE_LIMIT_MAX = 60;
const MAX_BATCH_SIZE = 10000;

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

function validateOrgId(orgId: string): boolean {
  return /^[a-zA-Z0-9_-]{1,64}$/.test(orgId);
}

export async function buildApp() {
  await app.register(cors, { origin: true, credentials: true });

  app.addHook("onRequest", async (request: FastifyRequest, reply: FastifyReply) => {
    const clientIp = request.ip || request.socket.remoteAddress || "unknown";
    const key = `${clientIp}:${request.url}`;
    if (!checkRateLimit(key)) {
      return reply.status(429).send({ error: "Rate limit exceeded" });
    }
  });

  app.post("/v1/compliance/ingest", async (request, reply) => {
    const { records } = request.body as { records: any[] };
    if (!records || !Array.isArray(records)) {
      return reply.status(400).send({ error: "records array required" });
    }

    if (records.length > MAX_BATCH_SIZE) {
      return reply.status(400).send({ error: `Batch size exceeds maximum of ${MAX_BATCH_SIZE}` });
    }

    let ingested = 0;
    for (const r of records) {
      if (r && typeof r === "object" && r.timestamp && r.organizationId) {
        pipeline.ingest(r);
        ingested++;
      }
    }

    return reply.send({ ingested, total: pipeline.getStats().totalRecords });
  });

  app.post("/v1/compliance/export", async (request, reply) => {
    const params = request.body as AuditExport;

    if (!params.organizationId || !params.startDate || !params.endDate) {
      return reply.status(400).send({ error: "organizationId, startDate, and endDate are required" });
    }

    if (!validateOrgId(params.organizationId)) {
      return reply.status(400).send({ error: "Invalid organization ID" });
    }

    if (!["jsonl", "csv"].includes(params.format)) {
      return reply.status(400).send({ error: "format must be 'jsonl' or 'csv'" });
    }

    const startDate = new Date(params.startDate);
    const endDate = new Date(params.endDate);
    if (isNaN(startDate.getTime()) || isNaN(endDate.getTime())) {
      return reply.status(400).send({ error: "Invalid date format" });
    }
    if (startDate >= endDate) {
      return reply.status(400).send({ error: "startDate must be before endDate" });
    }

    const records = pipeline.query({
      organizationId: params.organizationId,
      startDate,
      endDate,
      limit: Math.min(params.batchSize || 1000, MAX_BATCH_SIZE),
    });

    const result = await reportGenerator.generateExport(params, records);
    return reply.send(result);
  });

  app.post("/v1/compliance/report", async (request, reply) => {
    const params = request.body as ComplianceReport;

    if (!params.organizationId || !params.reportType) {
      return reply.status(400).send({ error: "organizationId and reportType are required" });
    }

    if (!validateOrgId(params.organizationId)) {
      return reply.status(400).send({ error: "Invalid organization ID" });
    }

    if (!["soc2", "gdpr", "audit"].includes(params.reportType)) {
      return reply.status(400).send({ error: "reportType must be 'soc2', 'gdpr', or 'audit'" });
    }

    const records = pipeline.query({
      organizationId: params.organizationId,
      startDate: params.startDate ? new Date(params.startDate) : undefined,
      endDate: params.endDate ? new Date(params.endDate) : undefined,
    });

    let report: Record<string, unknown>;
    switch (params.reportType) {
      case "soc2":
        report = await reportGenerator.generateSOC2Report(records);
        break;
      case "gdpr":
        report = await reportGenerator.generateGDPRReport(records);
        break;
      case "audit":
      default:
        report = await reportGenerator.generateComplianceSummary(records);
    }

    return reply.send({
      id: `rpt_${Date.now()}`,
      generatedAt: new Date().toISOString(),
      ...report,
    });
  });

  app.get("/v1/compliance/stats", async (request, reply) => {
    return reply.send(pipeline.getStats());
  });

  app.get("/health", async () => {
    return { status: "ok", service: "ovara-compliance", timestamp: new Date().toISOString() };
  });

  return app;
}

if (require.main === module) {
  buildApp().then((app) => {
    const port = parseInt(process.env.PORT || "3002", 10);
    app.listen({ port, host: "0.0.0.0" }).then(() => {
      console.log(`Compliance service listening on port ${port}`);
    });
  });
}
