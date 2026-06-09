import { z } from "zod";

export const complianceReportSchema = z.object({
  reportType: z.enum(["audit", "soc2", "iso27001", "gdpr", "custom"]),
  organizationId: z.string().uuid(),
  startDate: z.string().datetime(),
  endDate: z.string().datetime(),
  format: z.enum(["json", "csv", "pdf"]).default("json"),
  filters: z.object({
    gatewayIds: z.array(z.string()).optional(),
    eventTypes: z.array(z.string()).optional(),
    actionTypes: z.array(z.string()).optional(),
    minimumTrustScore: z.number().min(0).max(1).optional(),
  }).optional(),
});

export const auditExportSchema = z.object({
  organizationId: z.string().uuid(),
  startDate: z.string().datetime(),
  endDate: z.string().datetime(),
  format: z.enum(["jsonl", "csv", "parquet"]).default("jsonl"),
  batchSize: z.number().int().min(1).max(10000).default(1000),
});

export type ComplianceReport = z.infer<typeof complianceReportSchema>;
export type AuditExport = z.infer<typeof auditExportSchema>;

export interface ExportResult {
  id: string;
  format: string;
  recordCount: number;
  byteSize: number;
  generatedAt: Date;
  downloadUrl: string;
}

export interface AuditRecord {
  timestamp: string;
  organizationId: string;
  gatewayId: string;
  actor: string;
  action: string;
  resource: string;
  decision: string;
  receiptId?: string;
  policyId?: string;
  agentId?: string;
  trustScore?: number;
  details: Record<string, unknown>;
}
