import { z } from "zod";

export const ssoConfigSchema = z.object({
  provider: z.enum(["oidc", "saml", "google", "github"]),
  clientId: z.string().min(1),
  clientSecret: z.string().min(1),
  issuerUrl: z.string().url().optional(),
  authUrl: z.string().url().optional(),
  tokenUrl: z.string().url().optional(),
  userInfoUrl: z.string().url().optional(),
  jwksUrl: z.string().url().optional(),
  scopes: z.array(z.string()).default(["openid", "email", "profile"]),
  redirectUri: z.string().url(),
  domainWhitelist: z.array(z.string()).optional(),
});

export const samlConfigSchema = z.object({
  provider: z.literal("saml"),
  entityId: z.string().min(1),
  ssoUrl: z.string().url(),
  x509Cert: z.string().min(1),
  assertionConsumerUrl: z.string().url(),
  nameIdFormat: z.string().default("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"),
});

export type SSOConfig = z.infer<typeof ssoConfigSchema>;
export type SAMLConfig = z.infer<typeof samlConfigSchema>;

export interface OIDCTokens {
  accessToken: string;
  idToken: string;
  refreshToken?: string;
  expiresAt: Date;
}

export interface OIDCClaims {
  sub: string;
  email: string;
  emailVerified?: boolean;
  name?: string;
  picture?: string;
  organization?: string;
  groups?: string[];
}

export interface SSOUser {
  id: string;
  email: string;
  name: string;
  provider: string;
  organizationId?: string;
  groups: string[];
  lastLoginAt: Date;
}
