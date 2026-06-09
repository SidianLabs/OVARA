import { randomUUID } from "crypto";
import { stringify } from "csv-stringify/sync";
import { AuditExport, ExportResult, AuditRecord } from "./types";

export class ComplianceReportGenerator {
  constructor() {}

  async generateJSONL(records: AuditRecord[]): Promise<{ data: string; byteSize: number }> {
    const lines = records.map((r) => JSON.stringify(r)).join("\n");
    return { data: lines, byteSize: Buffer.byteLength(lines) };
  }

  async generateCSV(records: AuditRecord[]): Promise<{ data: string; byteSize: number }> {
    const csvData = stringify(records, {
      header: true,
      columns: [
        "timestamp", "organizationId", "gatewayId", "actor", "action",
        "resource", "decision", "receiptId", "policyId", "trustScore",
      ],
      cast: {
        number: (value: any) => String(value ?? ""),
      },
    });
    return { data: csvData, byteSize: Buffer.byteLength(csvData) };
  }

  async generateExport(params: AuditExport, records: AuditRecord[]): Promise<ExportResult> {
    let result: { data: string; byteSize: number };

    switch (params.format) {
      case "jsonl":
        result = await this.generateJSONL(records);
        break;
      case "csv":
        result = await this.generateCSV(records);
        break;
      default:
        result = await this.generateJSONL(records);
    }

    return {
      id: `export_${randomUUID().replace(/-/g, "").slice(0, 16)}`,
      format: params.format,
      recordCount: records.length,
      byteSize: result.byteSize,
      generatedAt: new Date(),
      downloadUrl: `/exports/${params.organizationId}/latest.${params.format}`,
    };
  }

  async generateComplianceSummary(records: AuditRecord[]): Promise<Record<string, unknown>> {
    const totalActions = records.length;
    const allowedCount = records.filter((r) => r.decision === "allow").length;
    const deniedCount = records.filter((r) => r.decision === "deny").length;
    const pendingCount = records.filter((r) => r.decision === "pending").length;

    const actionCounts: Record<string, number> = {};
    const resourceCounts: Record<string, number> = {};
    const gatewayCounts: Record<string, number> = {};
    const actorCounts: Record<string, number> = {};

    for (const r of records) {
      actionCounts[r.action] = (actionCounts[r.action] || 0) + 1;
      resourceCounts[r.resource] = (resourceCounts[r.resource] || 0) + 1;
      gatewayCounts[r.gatewayId] = (gatewayCounts[r.gatewayId] || 0) + 1;
      actorCounts[r.actor] = (actorCounts[r.actor] || 0) + 1;
    }

    const avgTrustScore = records.reduce((sum, r) => sum + (r.trustScore || 0), 0) / (records.length || 1);

    return {
      totalActions,
      allowedCount,
      deniedCount,
      pendingCount,
      allowRate: totalActions > 0 ? (allowedCount / totalActions * 100).toFixed(1) + "%" : "0%",
      denyRate: totalActions > 0 ? (deniedCount / totalActions * 100).toFixed(1) + "%" : "0%",
      avgTrustScore: avgTrustScore.toFixed(3),
      topActions: Object.entries(actionCounts).sort((a, b) => b[1] - a[1]).slice(0, 10),
      topResources: Object.entries(resourceCounts).sort((a, b) => b[1] - a[1]).slice(0, 10),
      topGateways: Object.entries(gatewayCounts).sort((a, b) => b[1] - a[1]).slice(0, 10),
      topActors: Object.entries(actorCounts).sort((a, b) => b[1] - a[1]).slice(0, 10),
    };
  }

  async generateSOC2Report(records: AuditRecord[]): Promise<Record<string, unknown>> {
    const securityEvents = records.filter((r) =>
      r.action.includes("auth.") || r.action.includes("security.") || r.decision === "deny"
    );

    const assetModifications = records.filter((r) =>
      r.action.includes(".execute") || r.action.includes(".push") || r.action.includes(".delete")
    );

    return {
      reportType: "soc2",
      period: {
        start: records[0]?.timestamp,
        end: records[records.length - 1]?.timestamp,
      },
      totalEvents: records.length,
      securityEvents: securityEvents.length,
      assetModifications: assetModifications.length,
      policyViolations: records.filter((r) => r.decision === "deny").length,
      securityAlerts: securityEvents.filter((e) => e.trustScore !== undefined && e.trustScore < 0.5).length,
      summary: await this.generateComplianceSummary(records),
    };
  }

  async generateGDPRReport(records: AuditRecord[], dataSubjectId?: string): Promise<Record<string, unknown>> {
    const personalDataAccess = records.filter((r) =>
      r.action.includes("data.") || r.resource.includes("user") || r.resource.includes("personal")
    );

    return {
      reportType: "gdpr",
      dataSubjectId,
      totalAccessEvents: personalDataAccess.length,
      dataProcessingSummary: await this.generateComplianceSummary(personalDataAccess),
      retentionPeriodDays: 90,
    };
  }
}

export class AuditPipeline {
  private records: AuditRecord[] = [];
  private maxRecords: number;

  constructor(maxRecords = 50000) {
    this.maxRecords = maxRecords;
  }

  ingest(record: AuditRecord) {
    this.records.push(record);
    if (this.records.length > this.maxRecords) {
      this.records = this.records.slice(-this.maxRecords);
    }
  }

  query(filters: {
    organizationId?: string;
    gatewayId?: string;
    action?: string;
    decision?: string;
    startDate?: Date;
    endDate?: Date;
    limit?: number;
  }): AuditRecord[] {
    let result = [...this.records];

    if (filters.organizationId) {
      result = result.filter((r) => r.organizationId === filters.organizationId);
    }
    if (filters.gatewayId) {
      result = result.filter((r) => r.gatewayId === filters.gatewayId);
    }
    if (filters.action) {
      result = result.filter((r) => r.action.includes(filters.action!));
    }
    if (filters.decision) {
      result = result.filter((r) => r.decision === filters.decision);
    }
    if (filters.startDate) {
      result = result.filter((r) => new Date(r.timestamp) >= filters.startDate!);
    }
    if (filters.endDate) {
      result = result.filter((r) => new Date(r.timestamp) <= filters.endDate!);
    }

    const limit = filters.limit || 1000;
    if (result.length > limit) {
      result = result.slice(-limit);
    }

    return result;
  }

  getStats(): { totalRecords: number; uniqueOrgIds: string[]; uniqueGatewayIds: string[] } {
    const orgSet = new Set<string>();
    const gwSet = new Set<string>();
    for (const r of this.records) {
      orgSet.add(r.organizationId);
      gwSet.add(r.gatewayId);
    }
    return {
      totalRecords: this.records.length,
      uniqueOrgIds: [...orgSet],
      uniqueGatewayIds: [...gwSet],
    };
  }

  clear() {
    this.records = [];
  }
}
