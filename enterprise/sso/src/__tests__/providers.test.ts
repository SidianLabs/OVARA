import { describe, it, expect, vi, beforeEach } from "vitest";
import { OIDCProvider, SAMLProvider } from "../providers";
import { SSOConfig, SAMLConfig } from "../types";

const oidcConfig: SSOConfig = {
  provider: "oidc",
  clientId: "test-client",
  clientSecret: "test-secret",
  issuerUrl: "https://auth.example.com",
  redirectUri: "https://app.example.com/callback",
  scopes: ["openid", "email", "profile"],
};

describe("OIDCProvider", () => {
  let provider: OIDCProvider;

  beforeEach(() => {
    provider = new OIDCProvider(oidcConfig);
  });

  it("generates auth URL with correct parameters", () => {
    const url = provider.getAuthUrl("state123", "nonce456");
    expect(url).toContain("https://auth.example.com/authorize");
    expect(url).toContain("client_id=test-client");
    expect(url).toContain("redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback");
    expect(url).toContain("scope=openid+email+profile");
    expect(url).toContain("state=state123");
    expect(url).toContain("nonce=nonce456");
  });

  it("exchangeCode returns tokens on success", async () => {
    const mockToken = {
      access_token: "access-token-001",
      id_token: "id-token-001",
      refresh_token: "refresh-token-001",
      expires_in: 3600,
    };

    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve(mockToken),
    });

    const tokens = await provider.exchangeCode("auth-code-123");
    expect(tokens.accessToken).toBe("access-token-001");
    expect(tokens.idToken).toBe("id-token-001");
    expect(tokens.refreshToken).toBe("refresh-token-001");
    expect(tokens.expiresAt).toBeInstanceOf(Date);
  });

  it("exchangeCode throws on error response", async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 400,
      text: () => Promise.resolve("invalid_grant"),
    });

    await expect(provider.exchangeCode("bad-code")).rejects.toThrow("Token exchange failed");
  });

  it("toUser maps claims to SSOUser", async () => {
    const claims = {
      sub: "user-123",
      email: "jane@acme.com",
      emailVerified: true,
      name: "Jane Doe",
      groups: ["engineering", "admin"],
    };

    const user = await provider.toUser(claims);
    expect(user.id).toBe("user-123");
    expect(user.email).toBe("jane@acme.com");
    expect(user.name).toBe("Jane Doe");
    expect(user.provider).toBe("oidc");
    expect(user.groups).toEqual(["engineering", "admin"]);
  });

  it("toUser enforces domain whitelist", async () => {
    const restrictedProvider = new OIDCProvider({
      ...oidcConfig,
      domainWhitelist: ["acme.com"],
    });

    const allowed = {
      sub: "u1",
      email: "user@acme.com",
    };
    const user = await restrictedProvider.toUser(allowed);
    expect(user.email).toBe("user@acme.com");

    const blocked = {
      sub: "u2",
      email: "user@evil.com",
    };
    await expect(restrictedProvider.toUser(blocked)).rejects.toThrow("Domain evil.com is not allowed");
  });

  it("toUser maps org by domain callback", async () => {
    const orgMapping = (domain: string) => domain === "partner.com" ? "org-partner-001" : undefined;
    const claims = { sub: "u1", email: "contact@partner.com" };
    const user = await provider.toUser(claims, orgMapping);
    expect(user.organizationId).toBe("org-partner-001");
  });
});

describe("SAMLProvider", () => {
  const samlConfig: SAMLConfig = {
    provider: "saml",
    entityId: "ovara-sp",
    ssoUrl: "https://idp.example.com/sso",
    x509Cert: "MIIC...cert",
    assertionConsumerUrl: "https://app.example.com/saml/callback",
  };

  let samlProvider: SAMLProvider;

  beforeEach(() => {
    samlProvider = new SAMLProvider(samlConfig);
  });

  it("generates SAML auth URL with RelayState", () => {
    const url = samlProvider.getAuthUrl("relay-org-123");
    expect(url).toContain("https://idp.example.com/sso");
    expect(url).toContain("SAMLRequest=");
    expect(url).toContain("RelayState=relay-org-123");
  });

  it("builds valid SAML AuthnRequest XML", () => {
    const url = samlProvider.getAuthUrl("test-relay");
    const samlRequest = new URL(url).searchParams.get("SAMLRequest");
    expect(samlRequest).toBeTruthy();

    const decoded = Buffer.from(samlRequest!, "base64url").toString("utf-8");
    expect(decoded).toContain("<samlp:AuthnRequest");
    expect(decoded).toContain("ovara-sp");
    expect(decoded).toContain("AssertionConsumerServiceURL");
  });

  it("parses SAML assertion response", async () => {
    const samlResponse = Buffer.from(
      `<samlp:Response>
        <saml:Assertion>
          <saml:Subject>
            <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">bob@acme.com</saml:NameID>
          </saml:Subject>
          <saml:AttributeStatement>
            <saml:Attribute Name="email">
              <saml:AttributeValue>bob@acme.com</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="displayName">
              <saml:AttributeValue>Bob Smith</saml:AttributeValue>
            </saml:Attribute>
          </saml:AttributeStatement>
        </saml:Assertion>
      </samlp:Response>`
    ).toString("base64");

    const user = await samlProvider.parseAssertionResponse(samlResponse);
    expect(user.email).toBe("bob@acme.com");
    expect(user.name).toBe("Bob Smith");
    expect(user.provider).toBe("saml");
  });

  it("parses groups from SAML attributes", async () => {
    const samlResponse = Buffer.from(
      `<samlp:Response>
        <saml:Assertion>
          <saml:Subject>
            <saml:NameID>admin@acme.com</saml:NameID>
          </saml:Subject>
          <saml:AttributeStatement>
            <saml:Attribute Name="groups">
              <saml:AttributeValue>engineering</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="groups">
              <saml:AttributeValue>devops</saml:AttributeValue>
            </saml:Attribute>
          </saml:AttributeStatement>
        </saml:Assertion>
      </samlp:Response>`
    ).toString("base64");

    const user = await samlProvider.parseAssertionResponse(samlResponse);
    expect(user.groups).toEqual(["engineering", "devops"]);
  });

  it("throws on missing NameID", async () => {
    const samlResponse = Buffer.from("<samlp:Response></samlp:Response>").toString("base64");
    await expect(samlProvider.parseAssertionResponse(samlResponse)).rejects.toThrow("No NameID found");
  });
});
