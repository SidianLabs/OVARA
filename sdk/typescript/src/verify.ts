import { createHash, createVerify } from "crypto";

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
  const digest = createHash("sha256").update(payload).digest("hex");

  try {
    const publicKey = Buffer.from(publicKeyHex, "hex");
    const signature = Buffer.from(identity.signature, "hex");
    const verify = createVerify("SHA256");
    verify.update(payload);
    return verify.verify({ key: publicKey, format: "der", type: "spki" }, signature) ||
      verify.verify(publicKey, signature);
  } catch {
    return false;
  }
}

export function verifyCapabilityLease(lease: PortableLease, publicKeyHex: string): boolean {
  if (!lease.signature || !publicKeyHex) return false;

  const payload = `${lease.leaseId}|${lease.issuer}|${lease.subject}|${lease.allowedActions}|${lease.resourceScope}|${lease.expiry}|${lease.delegationDepth}|${lease.issuedAt}`;

  try {
    const publicKey = Buffer.from(publicKeyHex, "hex");
    const signature = Buffer.from(lease.signature, "hex");
    return ed25519Verify(publicKey, Buffer.from(payload), signature);
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
    const publicKey = Buffer.from(publicKeyHex, "hex");
    const signature = Buffer.from(receipt.signature, "hex");
    return ed25519Verify(publicKey, Buffer.from(payload), signature);
  } catch {
    return false;
  }
}

function ed25519Verify(publicKey: Buffer, message: Buffer, signature: Buffer): boolean {
  try {
    const verifyObj = createVerify("SHA256");
    verifyObj.update(message);
    return verifyObj.verify(
      { key: publicKey, format: "der", type: "spki" },
      signature
    );
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
