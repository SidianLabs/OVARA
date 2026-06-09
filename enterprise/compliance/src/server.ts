import Fastify from "fastify";
import cors from "@fastify/cors";
import { ComplianceReportGenerator, AuditPipeline } from "./generator";
import { ComplianceReport, AuditExport } from "./types";

const app = Fastify({ logger: true });
const pipeline = new AuditPipeline(50000);
const reportGenerator = new ComplianceReportGenerator();

export async function buildApp() {
  await app.register(cors, { origin: true, credentials: true });

  app.post("/v1/compliance/ingest", async (request, reply) => {
    const { records } = request.body as { records: any[] };
    if (!records || !Array.isArray(records)) {
      return reply.status(400).send({ error: "records array required" });
    }
    for (const r of records) {
      pipeline.ingest(r);
    }
    return reply.send({ ingested: records.length, total: pipeline.getStats().totalRecords });
  });

  app.post("/v1/compliance/export", async (request, reply) => {
    const params = request.body as AuditExport;

    if (!params.organizationId || !params.startDate || !params.endDate) {
      return reply.status(400).send({ error: "organizationId, startDate, and endDate are required" });
    }

    const records = pipeline.query({
      organizationId: params.organizationId,
      startDate: new Date(params.startDate),
      endDate: new Date(params.endDate),
      limit: params.batchSize || 1000,
    });

    const result = await reportGenerator.generateExport(params, records);
    return reply.send(result);
  });

  app.post("/v1/compliance/report", async (request, reply) => {
    const params = request.body as ComplianceReport;

    if (!params.organizationId || !params.reportType) {
      return reply.status(400).send({ error: "organizationId and reportType are required" });
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
        break;
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
