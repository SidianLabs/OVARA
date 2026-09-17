import { createHash, createPublicKey, verify as cryptoVerify } from "crypto";

// verifyEd25519 checks an Ed25519 signature over payload using the caller-
// supplied trusted public key (32 raw bytes, hex-encoded). The key is always
// provided by the caller — never taken from the object being verified.
function verifyEd25519(signatureHex: string, payload: string, publicKeyHex: string): boolean {
  const key = createPublicKey({
    key: {
      kty: "OKP",
      crv: "Ed25519",
      x: Buffer.from(publicKeyHex, "hex").toString("base64url"),
    },
    format: "jwk",
  });
  return cryptoVerify(null, Buffer.from(payload), key, Buffer.from(signatureHex, "hex"));
}

export interface PortableIdentity {
  id: string;
  issuer: string;
  subjectId: string;
  owner: string;
  lifecycle: string;
  publicKey: string;
  signature?: string;
}

export interface PortableLease {
  leaseId: string;
  issuer: string;
  subject: string;
  allowedActions: string[];
  resourceScope: string;
  expiry: number;
  delegationDepth: number;
  issuedAt: number;
  signature: string;
}

export interface PortableReceipt {
  receiptId: string;
  decisionId: string;
  issuingGateway: string;
  issuingOrg: string;
  actionType: string;
  resource: string;
  decision: string;
  agentIdentity: string;
  leaseDigest?: string;
  trustScore: number;
  timestamp: number;
  signature: string;
}

export function verifyAgentIdentity(identity: PortableIdentity, publicKeyHex: string): boolean {
  if (!identity.signature || !publicKeyHex) return false;

  const payload = `${identity.id}|${identity.issuer}|${identity.subjectId}|${identity.owner}|${identity.lifecycle}`;

  try {
    return verifyEd25519(identity.signature, payload, publicKeyHex);
  } catch {
    return false;
  }
}

export function verifyCapabilityLease(lease: PortableLease, publicKeyHex: string): boolean {
  if (!lease.signature || !publicKeyHex) return false;

  const payload = `${lease.leaseId}|${lease.issuer}|${lease.subject}|${JSON.stringify(lease.allowedActions)}|${lease.resourceScope}|${lease.expiry}|${lease.delegationDepth}|${lease.issuedAt}`;

  try {
    return verifyEd25519(lease.signature, payload, publicKeyHex);
  } catch {
    return false;
  }
}

export function verifyReceipt(receipt: PortableReceipt, publicKeyHex: string): boolean {
  if (!receipt.signature || !publicKeyHex) return false;

  const payload = [
    receipt.receiptId, receipt.decisionId, receipt.issuingGateway,
    receipt.issuingOrg, receipt.actionType, receipt.resource,
    receipt.decision, receipt.agentIdentity,
    receipt.trustScore.toFixed(3), receipt.timestamp,
  ].join("|");

  try {
    return verifyEd25519(receipt.signature, payload, publicKeyHex);
  } catch {
    return false;
  }
}

export function computeIdentityDigest(identity: PortableIdentity): string {
  const payload = `${identity.id}|${identity.issuer}|${identity.subjectId}|${identity.owner}|${identity.lifecycle}`;
  return createHash("sha256").update(payload).digest("hex");
}

export function computeReceiptDigest(receipt: PortableReceipt): string {
  const payload = [
    receipt.receiptId, receipt.decisionId, receipt.issuingGateway,
    receipt.issuingOrg, receipt.actionType, receipt.resource,
    receipt.decision, receipt.agentIdentity,
    receipt.trustScore.toFixed(3), receipt.timestamp,
  ].join("|");
  return createHash("sha256").update(payload).digest("hex");
}

export function isLeaseExpired(lease: PortableLease): boolean {
  return Date.now() > lease.expiry * 1000;
}

export function hasAction(lease: PortableLease, action: string): boolean {
  return lease.allowedActions.includes(action) || lease.allowedActions.includes("*");
}

export function scopeCovers(lease: PortableLease, resource: string): boolean {
  return !lease.resourceScope || lease.resourceScope === "*" || lease.resourceScope === resource;
}
