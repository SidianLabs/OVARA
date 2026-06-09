import * as jose from "jose";
import { SSOConfig, OIDCTokens, OIDCClaims, SSOUser } from "./types";

type JWKSClient = ReturnType<typeof jose.createRemoteJWKSet>;

export class OIDCProvider {
  private issuerClient: JWKSClient | null = null;

  constructor(private config: SSOConfig) {}

  getAuthUrl(state: string, nonce: string): string {
    const params = new URLSearchParams({
      response_type: "code",
      client_id: this.config.clientId,
      redirect_uri: this.config.redirectUri,
      scope: this.config.scopes.join(" "),
      state,
      nonce,
    });
    const authEndpoint = this.config.authUrl || `${this.config.issuerUrl}/authorize`;
    return `${authEndpoint}?${params.toString()}`;
  }

  async exchangeCode(code: string): Promise<OIDCTokens> {
    const tokenEndpoint = this.config.tokenUrl || `${this.config.issuerUrl}/token`;

    const response = await fetch(tokenEndpoint, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        client_id: this.config.clientId,
        client_secret: this.config.clientSecret,
        redirect_uri: this.config.redirectUri,
      }).toString(),
    });

    if (!response.ok) {
      const err = await response.text();
      throw new Error(`Token exchange failed: ${response.status} — ${err}`);
    }

    const data = await response.json();
    return {
      accessToken: data.access_token,
      idToken: data.id_token,
      refreshToken: data.refresh_token,
      expiresAt: new Date(Date.now() + (data.expires_in || 3600) * 1000),
    };
  }

  async verifyIdToken(idToken: string, nonce: string): Promise<OIDCClaims> {
    const jwks = await this.getJWKS();
    const issuer = this.config.issuerUrl!;

    const { payload } = await jose.jwtVerify(idToken, jwks, {
      issuer,
      audience: this.config.clientId,
    });

    if (payload.nonce !== nonce) {
      throw new Error("ID token nonce mismatch");
    }

    return {
      sub: payload.sub!,
      email: payload.email as string,
      emailVerified: payload.email_verified as boolean,
      name: payload.name as string | undefined,
      picture: payload.picture as string | undefined,
      groups: (payload.groups as string[]) || [],
    };
  }

  async getUserInfo(accessToken: string): Promise<OIDCClaims> {
    const url = this.config.userInfoUrl || `${this.config.issuerUrl}/userinfo`;
    const response = await fetch(url, {
      headers: { Authorization: `Bearer ${accessToken}` },
    });

    if (!response.ok) {
      throw new Error(`UserInfo failed: ${response.status}`);
    }

    const data = await response.json();
    return {
      sub: data.sub,
      email: data.email,
      emailVerified: data.email_verified,
      name: data.name,
      picture: data.picture,
    };
  }

  async toUser(claims: OIDCClaims, orgMapping?: (domain: string) => string | undefined): Promise<SSOUser> {
    const domain = claims.email.split("@")[1] || "";
    const organizationId = orgMapping?.(domain);

    if (this.config.domainWhitelist?.length && !this.config.domainWhitelist.includes(domain)) {
      throw new Error(`Domain ${domain} is not allowed`);
    }

    return {
      id: claims.sub,
      email: claims.email,
      name: claims.name || claims.email,
      provider: this.config.provider,
      organizationId,
      groups: claims.groups || [],
      lastLoginAt: new Date(),
    };
  }

  private async getJWKS(): Promise<JWKSClient> {
    if (this.issuerClient) return this.issuerClient;

    const jwksUrl = this.config.jwksUrl || `${this.config.issuerUrl}/.well-known/jwks.json`;
    const JWKS = jose.createRemoteJWKSet(new URL(jwksUrl));
    this.issuerClient = JWKS;
    return JWKS;
  }
}

export class SAMLProvider {
  constructor(private config: import("./types").SAMLConfig) {}

  getAuthUrl(relayState: string): string {
    const samlRequest = this.buildAuthnRequest();
    const encoded = Buffer.from(samlRequest).toString("base64url");
    const params = new URLSearchParams({
      SAMLRequest: encoded,
      RelayState: relayState,
    });
    return `${this.config.ssoUrl}?${params.toString()}`;
  }

  private buildAuthnRequest(): string {
    const id = `_${Date.now()}${Math.random().toString(36).slice(2)}`;
    return `<?xml version="1.0"?>
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
  ID="${id}" Version="2.0"
  IssueInstant="${new Date().toISOString()}"
  Destination="${this.config.ssoUrl}"
  AssertionConsumerServiceURL="${this.config.assertionConsumerUrl}">
  <saml:Issuer>${this.config.entityId}</saml:Issuer>
  <samlp:NameIDPolicy Format="${this.config.nameIdFormat}" AllowCreate="true"/>
</samlp:AuthnRequest>`;
  }

  async parseAssertionResponse(samlResponse: string): Promise<SSOUser> {
    const decoded = Buffer.from(samlResponse, "base64").toString("utf-8");

    const nameIdMatch = decoded.match(/<saml:NameID[^>]*>(.*?)<\/saml:NameID>/s);
    const email = nameIdMatch?.[1]?.trim();

    if (!email) {
      throw new Error("No NameID found in SAML response");
    }

    const attrEmailMatch = decoded.match(
      /<saml:Attribute Name="email"[^>]*>.*?<saml:AttributeValue[^>]*>(.*?)<\/saml:AttributeValue>/s
    );
    const attrNameMatch = decoded.match(
      /<saml:Attribute Name="displayName"[^>]*>.*?<saml:AttributeValue[^>]*>(.*?)<\/saml:AttributeValue>/s
    );

    return {
      id: email,
      email: attrEmailMatch?.[1]?.trim() || email,
      name: attrNameMatch?.[1]?.trim() || email,
      provider: "saml",
      groups: this.extractGroups(decoded),
      lastLoginAt: new Date(),
    };
  }

  private extractGroups(xml: string): string[] {
    const regex = /<saml:Attribute Name="groups"[^>]*>.*?<saml:AttributeValue[^>]*>(.*?)<\/saml:AttributeValue>/gs;
    const groups: string[] = [];
    let match;
    while ((match = regex.exec(xml)) !== null) {
      groups.push(match[1].trim());
    }
    return groups;
  }
}
