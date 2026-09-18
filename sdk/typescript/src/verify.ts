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
  /**
   * ed25519 signature over the pipe-joined canonical lease payload.
   * Hex-encoded here. NOTE: on the gateway wire the signature is base64
   * (Go []byte marshals to base64 in JSON) — decode it before calling
   * verifyCapabilityLease, which accepts both hex and base64 input.
   */
  signature: string;
}

/**
 * Receipt as produced by the Ovara egress proxy
 * (proxy/internal/receipts/chain.go). The proxy signs each entry with
 * ed25519 ("sig_v1:<hex>") over the canonical pipe-joined payload, so
 * receipts are verifiable offline with only the proxy's public key.
 *
 * NOTE: gateway-side decision receipts (models.Receipt) are HMAC-SHA256
 * signed — the verify key is the signing key and is never distributed.
 * To check a gateway receipt, fetch GET /v1/receipts/{id} from the
 * gateway that issued it.
 */
export interface PortableReceipt {
  receiptId: string;
  sessionId: string;
  /** RFC3339 / RFC3339Nano timestamp, as serialized by Go time.Time. */
  timestamp: string;
  method: string;
  url: string;
  decision: string;
  status: number;
  /**
   * Links an escalated-then-approved receipt to the approval that
   * authorized it. Present only on such receipts; it is part of the
   * signed canonical payload (appended as "|approval_id").
   */
  approvalId?: string;
  prevHash: string;
  /** "sig_v1:<hex ed25519>" */
  signature: string;
}

// goStringSlice renders a []string the way Go's fmt %v does: "[a b c]".
// The gateway's lease canonical form (internal/identity/validator.go)
// uses %v for allowed_actions, so verifiers must match it exactly.
function goStringSlice(items: string[]): string {
  return "[" + items.join(" ") + "]";
}

// rfc3339ToUnixNano converts an RFC3339/RFC3339Nano timestamp to Unix
// nanoseconds (BigInt), matching Go's time.Time.UnixNano().
function rfc3339ToUnixNano(ts: string): bigint {
  const m = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:?\d{2})?$/.exec(ts);
  if (!m) return 0n;
  const base = Date.parse(m[1] + (m[3] ?? "Z"));
  const frac = (m[2] ?? "").padEnd(9, "0").slice(0, 9);
  return BigInt(base) * 1000000n + BigInt(frac || "0");
}

// receiptCanonical mirrors Receipt.canonical() in the proxy:
// receipt_id|session_id|unixnano|method|url|decision|status|prev_hash
// with "|approval_id" appended when approval_id is non-empty
// (proxy/internal/receipts/chain.go).
function receiptCanonical(r: PortableReceipt): string {
  let c = [
    r.receiptId,
    r.sessionId,
    rfc3339ToUnixNano(r.timestamp).toString(),
    r.method,
    r.url,
    r.decision,
    String(r.status),
    r.prevHash,
  ].join("|");
  if (r.approvalId) {
    c += "|" + r.approvalId;
  }
  return c;
}

// signatureToHex normalizes a signature to hex. The SDK carries
// hex-encoded signatures, but the Go side marshals []byte to base64 on
// the wire — accept that form too.
function signatureToHex(signature: string): string {
  if (/^[0-9a-fA-F]+$/.test(signature) && signature.length % 2 === 0) {
    return signature;
  }
  try {
    return Buffer.from(signature, "base64").toString("hex");
  } catch {
    return signature;
  }
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

  const payload = `${lease.leaseId}|${lease.issuer}|${lease.subject}|${goStringSlice(lease.allowedActions)}|${lease.resourceScope}|${lease.expiry}|${lease.delegationDepth}|${lease.issuedAt}`;

  try {
    return verifyEd25519(signatureToHex(lease.signature), payload, publicKeyHex);
  } catch {
    return false;
  }
}

/**
 * verifyReceipt verifies an Ovara *proxy* receipt (see PortableReceipt):
 * an ed25519 "sig_v1:<hex>" signature over the proxy's canonical
 * pipe-joined payload. The public key is distributed by the proxy
 * (pubkey file written next to the receipt chain).
 */
export function verifyReceipt(receipt: PortableReceipt, publicKeyHex: string): boolean {
  if (!receipt.signature || !publicKeyHex) return false;
  if (!receipt.signature.startsWith("sig_v1:")) return false;

  const payload = receiptCanonical(receipt);

  try {
    return verifyEd25519(receipt.signature.slice(7), payload, publicKeyHex);
  } catch {
    return false;
  }
}

// identityCanonical mirrors AgentIdentity.Digest() in
// identity/internal/crypto/identity.go: compact JSON (Go json.Marshal
// output — no spaces, fields in struct declaration order).
function identityCanonical(identity: PortableIdentity): string {
  return JSON.stringify({
    id: identity.id,
    issuer: identity.issuer,
    subject_id: identity.subjectId,
    owner: identity.owner,
    lifecycle: identity.lifecycle,
  });
}

export function computeIdentityDigest(identity: PortableIdentity): string {
  return createHash("sha256").update(identityCanonical(identity)).digest("hex");
}

export function computeReceiptDigest(receipt: PortableReceipt): string {
  return createHash("sha256").update(receiptCanonical(receipt)).digest("hex");
}

export function isLeaseExpired(lease: PortableLease): boolean {
  return Date.now() > lease.expiry * 1000;
}

export function hasAction(lease: PortableLease, action: string): boolean {
  if (isLeaseExpired(lease)) return false;
  return lease.allowedActions.includes(action) || lease.allowedActions.includes("*");
}

export function scopeCovers(lease: PortableLease, resource: string): boolean {
  // The gateway requires a non-empty resource_scope; an empty scope
  // covers nothing rather than everything.
  if (!lease.resourceScope) return false;
  return lease.resourceScope === "*" || lease.resourceScope === resource;
}
