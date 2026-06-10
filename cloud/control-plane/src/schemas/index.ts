import { z } from "zod";

const uuid = () => z.string().uuid();
const timestamp = () => z.string().datetime();

export const createTenantSchema = z.object({
  name: z.string().min(3).max(64).regex(/^[a-z0-9-]+$/),
  displayName: z.string().min(1).max(255),
  plan: z.enum(["free", "pro", "enterprise"]).default("free"),
});

export const createOrganizationSchema = z.object({
  tenantId: uuid(),
  name: z.string().min(3).max(255).regex(/^[a-z0-9-]+$/),
  displayName: z.string().min(1).max(255),
});

export const enrollGatewaySchema = z.object({
  organizationId: uuid(),
  name: z.string().min(3).max(255),
  environment: z.string().min(1).max(50).default("local"),
  region: z.string().min(1).max(50).default("us-east-1"),
  publicKey: z.string().min(1),
});

export const createPolicySchema = z.object({
  organizationId: uuid(),
  name: z.string().min(3).max(255),
  rules: z.array(z.object({
    id: z.string(),
    action: z.string(),
    target: z.string(),
    condition: z.string().optional(),
    effect: z.enum(["allow", "deny"]),
    priority: z.number().int().min(0).default(0),
  })).min(1),
});

export const publishPolicySchema = z.object({
  gatewayIds: z.array(uuid()).optional(),
});

export const publishToGatewaysSchema = z.object({
  policyId: uuid(),
  organizationId: uuid(),
});

export const publishToGatewaySchema = z.object({
  policyId: uuid(),
});

export const createApiKeySchema = z.object({
  organizationId: uuid(),
  name: z.string().min(3).max(255),
  scopes: z.array(z.string()).min(1),
  expiresAt: timestamp().optional(),
});

export const createRevocationSchema = z.object({
  organizationId: uuid(),
  leaseId: z.string().min(1),
  reason: z.string().optional(),
});

export const paginationSchema = z.object({
  limit: z.coerce.number().int().min(1).max(100).default(50),
  offset: z.coerce.number().int().min(0).default(0),
});

export type CreateTenant = z.infer<typeof createTenantSchema>;
export type CreateOrganization = z.infer<typeof createOrganizationSchema>;
export type EnrollGateway = z.infer<typeof enrollGatewaySchema>;
export type CreatePolicy = z.infer<typeof createPolicySchema>;
export type PublishPolicy = z.infer<typeof publishPolicySchema>;
export type CreateApiKey = z.infer<typeof createApiKeySchema>;
export type CreateRevocation = z.infer<typeof createRevocationSchema>;
export type PublishToGateways = z.infer<typeof publishToGatewaysSchema>;
export type PublishToGateway = z.infer<typeof publishToGatewaySchema>;
