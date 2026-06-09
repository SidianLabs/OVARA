import {
  pgTable,
  varchar,
  text,
  timestamp,
  jsonb,
  uuid,
  boolean,
  integer,
  index,
  uniqueIndex,
} from "drizzle-orm/pg-core";

export const tenants = pgTable("tenants", {
  id: uuid("id").primaryKey().defaultRandom(),
  name: varchar("name", { length: 255 }).notNull().unique(),
  displayName: varchar("display_name", { length: 255 }).notNull(),
  plan: varchar("plan", { length: 50 }).notNull().default("free"),
  status: varchar("status", { length: 20 }).notNull().default("active"),
  metadata: jsonb("metadata").default({}),
  createdAt: timestamp("created_at").defaultNow().notNull(),
  updatedAt: timestamp("updated_at").defaultNow().notNull(),
});

export const organizations = pgTable("organizations", {
  id: uuid("id").primaryKey().defaultRandom(),
  tenantId: uuid("tenant_id").references(() => tenants.id).notNull(),
  name: varchar("name", { length: 255 }).notNull(),
  displayName: varchar("display_name", { length: 255 }).notNull(),
  status: varchar("status", { length: 20 }).notNull().default("active"),
  settings: jsonb("settings").default({}),
  createdAt: timestamp("created_at").defaultNow().notNull(),
  updatedAt: timestamp("updated_at").defaultNow().notNull(),
});

export const gateways = pgTable("gateways", {
  id: uuid("id").primaryKey().defaultRandom(),
  organizationId: uuid("organization_id").references(() => organizations.id).notNull(),
  name: varchar("name", { length: 255 }).notNull(),
  environment: varchar("environment", { length: 50 }).notNull().default("local"),
  region: varchar("region", { length: 50 }).notNull().default("us-east-1"),
  status: varchar("status", { length: 20 }).notNull().default("enrolling"),
  publicKey: text("public_key").notNull(),
  enrollmentToken: text("enrollment_token"),
  enrollmentExpiresAt: timestamp("enrollment_expires_at"),
  lastHeartbeat: timestamp("last_heartbeat"),
  metadata: jsonb("metadata").default({}),
  createdAt: timestamp("created_at").defaultNow().notNull(),
  updatedAt: timestamp("updated_at").defaultNow().notNull(),
}, (table) => ({
  orgIdx: index("gateways_org_idx").on(table.organizationId),
  tokenIdx: uniqueIndex("gateways_token_idx").on(table.enrollmentToken),
}));

export const policies = pgTable("policies", {
  id: uuid("id").primaryKey().defaultRandom(),
  organizationId: uuid("organization_id").references(() => organizations.id).notNull(),
  name: varchar("name", { length: 255 }).notNull(),
  version: integer("version").notNull().default(1),
  rules: jsonb("rules").notNull().default([]),
  status: varchar("status", { length: 20 }).notNull().default("draft"),
  publishedAt: timestamp("published_at"),
  createdAt: timestamp("created_at").defaultNow().notNull(),
  updatedAt: timestamp("updated_at").defaultNow().notNull(),
}, (table) => ({
  orgVersionIdx: uniqueIndex("policies_org_version_idx").on(table.organizationId, table.name, table.version),
}));

export const policyDistributions = pgTable("policy_distributions", {
  id: uuid("id").primaryKey().defaultRandom(),
  policyId: uuid("policy_id").references(() => policies.id).notNull(),
  gatewayId: uuid("gateway_id").references(() => gateways.id).notNull(),
  deliveredAt: timestamp("delivered_at"),
  acknowledgedAt: timestamp("acknowledged_at"),
  status: varchar("status", { length: 20 }).notNull().default("pending"),
  createdAt: timestamp("created_at").defaultNow().notNull(),
}, (table) => ({
  deliveryIdx: index("policy_dist_idx").on(table.policyId, table.gatewayId),
}));

export const revocations = pgTable("revocations", {
  id: uuid("id").primaryKey().defaultRandom(),
  organizationId: uuid("organization_id").references(() => organizations.id).notNull(),
  leaseId: varchar("lease_id", { length: 255 }).notNull(),
  reason: text("reason"),
  status: varchar("status", { length: 20 }).notNull().default("pending"),
  executedAt: timestamp("executed_at"),
  createdAt: timestamp("created_at").defaultNow().notNull(),
}, (table) => ({
  orgLeaseIdx: uniqueIndex("revocations_org_lease_idx").on(table.organizationId, table.leaseId),
}));

export const apiKeys = pgTable("api_keys", {
  id: uuid("id").primaryKey().defaultRandom(),
  organizationId: uuid("organization_id").references(() => organizations.id).notNull(),
  name: varchar("name", { length: 255 }).notNull(),
  keyHash: varchar("key_hash", { length: 255 }).notNull().unique(),
  prefix: varchar("prefix", { length: 8 }).notNull(),
  scopes: jsonb("scopes").default([]),
  expiresAt: timestamp("expires_at"),
  lastUsedAt: timestamp("last_used_at"),
  createdAt: timestamp("created_at").defaultNow().notNull(),
  revokedAt: timestamp("revoked_at"),
}, (table) => ({
  orgIdx: index("apikeys_org_idx").on(table.organizationId),
}));

export const auditLog = pgTable("audit_log", {
  id: uuid("id").primaryKey().defaultRandom(),
  organizationId: uuid("organization_id").references(() => organizations.id).notNull(),
  actor: varchar("actor", { length: 255 }).notNull(),
  action: varchar("action", { length: 255 }).notNull(),
  resource: varchar("resource", { length: 255 }).notNull(),
  resourceId: varchar("resource_id", { length: 255 }),
  details: jsonb("details").default({}),
  ip: varchar("ip", { length: 45 }),
  userAgent: text("user_agent"),
  createdAt: timestamp("created_at").defaultNow().notNull(),
}, (table) => ({
  orgTimeIdx: index("audit_org_time_idx").on(table.organizationId, table.createdAt.desc()),
}));
