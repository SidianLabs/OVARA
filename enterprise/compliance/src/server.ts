import Fastify, { FastifyRequest, FastifyReply } from "fastify";
import cors from "@fastify/cors";
import { timingSafeEqual } from "crypto";
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

// Periodically evict expired entries so the store cannot grow unboundedly.
setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of rateLimitStore) {
    if (now > entry.resetAt) rateLimitStore.delete(key);
  }
}, RATE_LIMIT_WINDOW_MS).unref();

function safeEqual(a: string, b: string): boolean {
  const ba = Buffer.from(a);
  const bb = Buffer.from(b);
  return ba.length === bb.length && timingSafeEqual(ba, bb);
}

/**
 * Bearer tokens bound to organizations, configured via env:
 *   OVARA_COMPLIANCE_TOKENS="org1:token1,org2:token2"
 * Fails closed: when no tokens are configured every authenticated route
 * returns 503. organizationId is derived from the credential, never from
 * caller-supplied fields.
 */
function loadTokens(): Map<string, string> {
  const tokens = new Map<string, string>();
  const raw = process.env.OVARA_COMPLIANCE_TOKENS || "";
  for (const pair of raw.split(",")) {
    const idx = pair.indexOf(":");
    if (idx > 0) {
      tokens.set(pair.slice(0, idx).trim(), pair.slice(idx + 1).trim());
    }
  }
  return tokens;
}

const orgTokens = loadTokens();

function authenticate(request: FastifyRequest, reply: FastifyReply): string | null {
  if (orgTokens.size === 0) {
    reply.status(503).send({ error: "Compliance API tokens not configured" });
    return null;
  }
  const header = request.headers["authorization"];
  const token = header?.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) {
    reply.status(401).send({ error: "Missing bearer token" });
    return null;
  }
  for (const [orgId, expected] of orgTokens) {
    if (safeEqual(token, expected)) return orgId;
  }
  reply.status(401).send({ error: "Invalid token" });
  return null;
}

export async function buildApp() {
  await app.register(cors, { origin: true, credentials: true });

  app.addHook("onRequest", async (request: FastifyRequest, reply: FastifyReply) => {
    const clientIp = request.ip || request.socket.remoteAddress || "unknown";
    if (!checkRateLimit(clientIp)) {
      return reply.status(429).send({ error: "Rate limit exceeded" });
    }
  });

  app.post("/v1/compliance/ingest", async (request, reply) => {
    const orgId = authenticate(request, reply);
    if (!orgId) return;

    const { records } = request.body as { records: any[] };
    if (!records || !Array.isArray(records)) {
      return reply.status(400).send({ error: "records array required" });
    }

    if (records.length > MAX_BATCH_SIZE) {
      return reply.status(400).send({ error: `Batch size exceeds maximum of ${MAX_BATCH_SIZE}` });
    }

    let ingested = 0;
    for (const r of records) {
      if (r && typeof r === "object" && r.timestamp) {
        // Organization is bound to the authenticated credential; a caller
        // can never write records under another org's ID.
        pipeline.ingest({ ...r, organizationId: orgId });
        ingested++;
      }
    }

    return reply.send({ ingested, total: pipeline.getStats().totalRecords });
  });

  app.post("/v1/compliance/export", async (request, reply) => {
    const orgId = authenticate(request, reply);
    if (!orgId) return;

    const params = request.body as AuditExport;

    if (!params.startDate || !params.endDate) {
      return reply.status(400).send({ error: "startDate and endDate are required" });
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
      organizationId: orgId,
      startDate,
      endDate,
      limit: Math.min(params.batchSize || 1000, MAX_BATCH_SIZE),
    });

    const result = await reportGenerator.generateExport({ ...params, organizationId: orgId }, records);
    return reply.send(result);
  });

  app.post("/v1/compliance/report", async (request, reply) => {
    const orgId = authenticate(request, reply);
    if (!orgId) return;

    const params = request.body as ComplianceReport;

    if (!params.reportType) {
      return reply.status(400).send({ error: "reportType is required" });
    }

    if (!["soc2", "gdpr", "audit"].includes(params.reportType)) {
      return reply.status(400).send({ error: "reportType must be 'soc2', 'gdpr', or 'audit'" });
    }

    const records = pipeline.query({
      organizationId: orgId,
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
    const orgId = authenticate(request, reply);
    if (!orgId) return;

    // Scope stats to the authenticated org — never leak other orgs' IDs.
    const records = pipeline.query({ organizationId: orgId, limit: MAX_BATCH_SIZE });
    const gwSet = new Set<string>();
    for (const r of records) gwSet.add(r.gatewayId);
    return reply.send({
      organizationId: orgId,
      totalRecords: records.length,
      uniqueGatewayIds: [...gwSet],
    });
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
