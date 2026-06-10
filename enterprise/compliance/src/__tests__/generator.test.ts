import { describe, it, expect, beforeEach } from "vitest";
import { ComplianceReportGenerator, AuditPipeline } from "../generator";

describe("ComplianceReportGenerator", () => {
  let generator: ComplianceReportGenerator;

  beforeEach(() => {
    generator = new ComplianceReportGenerator();
  });

  const sampleRecords = [
    { timestamp: "2025-01-01T00:00:00Z", organizationId: "org-1", gatewayId: "gw-a", actor: "agent-1", action: "shell.execute", resource: "sudo", decision: "deny", trustScore: 0.3 },
    { timestamp: "2025-01-02T00:00:00Z", organizationId: "org-1", gatewayId: "gw-a", actor: "agent-1", action: "git.push", resource: "main", decision: "allow", trustScore: 0.9 },
    { timestamp: "2025-01-03T00:00:00Z", organizationId: "org-1", gatewayId: "gw-b", actor: "agent-2", action: "shell.execute", resource: "npm install", decision: "allow", trustScore: 0.85 },
    { timestamp: "2025-01-04T00:00:00Z", organizationId: "org-1", gatewayId: "gw-a", actor: "agent-1", action: "http.request", resource: "api.example.com", decision: "deny", trustScore: 0.1 },
    { timestamp: "2025-01-05T00:00:00Z", organizationId: "org-1", gatewayId: "gw-c", actor: "agent-3", action: "shell.execute", resource: "rm -rf", decision: "deny", trustScore: 0.15 },
  ] as any[];

  it("generates JSONL export", async () => {
    const { data, byteSize } = await generator.generateJSONL(sampleRecords);
    expect(data).toContain("shell.execute");
    expect(data).toContain("org-1");
    expect(byteSize).toBeGreaterThan(100);
    expect(data.split("\n").length).toBe(5);
  });

  it("generates CSV export with headers", async () => {
    const { data, byteSize } = await generator.generateCSV(sampleRecords);
    expect(data).toContain("timestamp,organizationId,gatewayId,actor,action");
    expect(data).toContain("shell.execute");
    expect(data).toContain("agent-1");
    expect(byteSize).toBeGreaterThan(100);
  });

  it("generates compliance summary with correct statistics", async () => {
    const summary = await generator.generateComplianceSummary(sampleRecords);
    expect(summary.totalActions).toBe(5);
    expect(summary.allowedCount).toBe(2);
    expect(summary.deniedCount).toBe(3);
    expect(summary.allowRate).toContain("40");
    expect(summary.denyRate).toContain("60");
    expect(parseFloat(summary.avgTrustScore as string)).toBeLessThan(0.5);
    expect((summary.topActions as any).length).toBeGreaterThan(0);
    expect((summary.topGateways as any).length).toBeGreaterThan(0);
  });

  it("generates SOC2 report", async () => {
    const report = await generator.generateSOC2Report(sampleRecords);
    expect(report.reportType).toBe("soc2");
    expect(report.totalEvents).toBe(5);
    expect(report.policyViolations).toBe(3);
    expect(report.securityAlerts).toBeGreaterThan(0);
  });

  it("generates GDPR report", async () => {
    const report = await generator.generateGDPRReport(sampleRecords);
    expect(report.reportType).toBe("gdpr");
    expect(report.totalAccessEvents).toBeGreaterThanOrEqual(0);
    expect(report.retentionPeriodDays).toBe(90);
  });

  it("handles empty record set", async () => {
    const summary = await generator.generateComplianceSummary([]);
    expect(summary.totalActions).toBe(0);
    expect(summary.allowedCount).toBe(0);
    expect(summary.avgTrustScore).toBe("0.000");
  });

  it("generateExport returns correct format metadata", async () => {
    const result = await generator.generateExport(
      { organizationId: "org-1", startDate: "2025-01-01", endDate: "2025-12-31", format: "jsonl", batchSize: 1000 },
      sampleRecords
    );
    expect(result.id).toMatch(/^export_/);
    expect(result.format).toBe("jsonl");
    expect(result.recordCount).toBe(5);
    expect(result.byteSize).toBeGreaterThan(0);
    expect(result.downloadUrl).toContain("org-1");
  });
});

describe("AuditPipeline", () => {
  const records = [
    { timestamp: "2025-06-01T10:00:00Z", organizationId: "org-x", gatewayId: "gw-1", actor: "a1", action: "shell.execute", resource: "ls", decision: "allow" },
    { timestamp: "2025-06-02T10:00:00Z", organizationId: "org-x", gatewayId: "gw-1", actor: "a1", action: "git.push", resource: "main", decision: "deny", trustScore: 0.4 },
    { timestamp: "2025-06-03T10:00:00Z", organizationId: "org-y", gatewayId: "gw-2", actor: "a2", action: "shell.execute", resource: "rm", decision: "deny" },
  ] as any[];

  it("ingests records", () => {
    const pipeline = new AuditPipeline(100);
    for (const r of records) pipeline.ingest(r);
    expect(pipeline.getStats().totalRecords).toBe(3);
  });

  it("caps at max size", () => {
    const pipeline = new AuditPipeline(2);
    for (const r of records) pipeline.ingest(r);
    expect(pipeline.getStats().totalRecords).toBe(2);
  });

  it("queries by organization", () => {
    const pipeline = new AuditPipeline(100);
    for (const r of records) pipeline.ingest(r);

    const orgX = pipeline.query({ organizationId: "org-x" });
    expect(orgX.length).toBe(2);

    const orgY = pipeline.query({ organizationId: "org-y" });
    expect(orgY.length).toBe(1);
  });

  it("queries by decision", () => {
    const pipeline = new AuditPipeline(100);
    for (const r of records) pipeline.ingest(r);

    const denied = pipeline.query({ decision: "deny" });
    expect(denied.length).toBe(2);
  });

  it("queries by date range", () => {
    const pipeline = new AuditPipeline(100);
    for (const r of records) pipeline.ingest(r);

    const inRange = pipeline.query({
      startDate: new Date("2025-06-02"),
      endDate: new Date("2025-06-02T23:59:59Z"),
    });
    expect(inRange.length).toBe(1);
    expect(inRange[0].action).toBe("git.push");
  });

  it("respects limit", () => {
    const pipeline = new AuditPipeline(100);
    for (const r of records) pipeline.ingest(r);

    const limited = pipeline.query({ limit: 1 });
    expect(limited.length).toBe(1);
  });

  it("getStats returns unique orgs and gateways", () => {
    const pipeline = new AuditPipeline(100);
    for (const r of records) pipeline.ingest(r);

    const stats = pipeline.getStats();
    expect(stats.uniqueOrgIds).toEqual(["org-x", "org-y"]);
    expect(stats.uniqueGatewayIds).toEqual(["gw-1", "gw-2"]);
  });

  it("clear removes all records", () => {
    const pipeline = new AuditPipeline(100);
    for (const r of records) pipeline.ingest(r);
    pipeline.clear();
    expect(pipeline.getStats().totalRecords).toBe(0);
  });
});
