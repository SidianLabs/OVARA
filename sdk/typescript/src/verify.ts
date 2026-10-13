import { createHash, createPublicKey, verify as cryptoVerify } from "crypto";

// verifyEd25519 checks an Ed25519 signature over payload using the caller-
// supplied trusted public key (32 raw bytes, hex-encoded). The key is always
// provided by the caller — never taken from the object being verified.
function verifyEd25519(signatureHex: string, payload: string | Buffer, publicKeyHex: string): boolean {
  const key = createPublicKey({
    key: {
      kty: "OKP",
      crv: "Ed25519",
      x: Buffer.from(publicKeyHex, "hex").toString("base64url"),
    },
    format: "jwk",
  });
  const msg = typeof payload === "string" ? Buffer.from(payload) : payload;
  return cryptoVerify(null, msg, key, Buffer.from(signatureHex, "hex"));
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
 * ed25519, so receipts are verifiable offline with only the proxy's
 * public key. Two versions exist:
 *
 * - v1: no `v`, "sig_v1:<hex>" over a pipe-joined payload.
 * - v2: `v` === 2, "sig_v2:<hex>" over a domain-separated, length-prefixed
 *   encoding of every field, naming its signing key in `kid`.
 *
 * Build one from a chain line with `portableReceiptFromJSON`.
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
   * authorized it. Signed in both versions.
   */
  approvalId?: string;
  prevHash: string;
  /** "sig_v1:<hex ed25519>" | "sig_v2:<hex ed25519>" */
  signature: string;

  // --- v2 only (absent on v1 receipts) ---
  /** 2 on v2 receipts; absent on v1. */
  v?: number;
  /** "attempt" | "outcome" | absent */
  phase?: string;
  /** "sent" | "not_sent" | absent */
  outcome?: string;
  /** On an outcome receipt: the receipt_id of its attempt. */
  attemptId?: string;
  /** "pt_<sha256[:16]>" of the proxy credential the client presented. */
  agent?: string;
  rule?: string;
  policyHash?: string;
  approver?: string;
  reqBytes?: number | bigint;
  /** -1 when the upstream streamed without a declared length. */
  respBytes?: number | bigint;
  bodySha256?: string;
  reasons?: string[];
  /** Signing key id: first 16 hex digits of sha256(raw public key). */
  kid?: string;
}

const RECEIPT_JSON_KEYS: Record<string, keyof PortableReceipt> = {
  v: "v",
  receipt_id: "receiptId",
  session_id: "sessionId",
  timestamp: "timestamp",
  method: "method",
  url: "url",
  decision: "decision",
  status: "status",
  approval_id: "approvalId",
  phase: "phase",
  outcome: "outcome",
  attempt_id: "attemptId",
  agent: "agent",
  rule: "rule",
  policy_hash: "policyHash",
  approver: "approver",
  req_bytes: "reqBytes",
  resp_bytes: "respBytes",
  body_sha256: "bodySha256",
  reasons: "reasons",
  kid: "kid",
  prev_hash: "prevHash",
  signature: "signature",
};

const RECEIPT_REQUIRED: (keyof PortableReceipt)[] = [
  "receiptId", "sessionId", "timestamp", "method", "url", "decision", "status", "prevHash", "signature",
];

/**
 * portableReceiptFromJSON builds a PortableReceipt from one receipt line
 * (its text or the parsed object, with the proxy's snake_case keys).
 * Unknown keys throw: every byte of a line is meant to be covered by its
 * signature, so a key the verifier does not know is not silently dropped.
 */
export function portableReceiptFromJSON(line: string | Record<string, unknown>): PortableReceipt {
  const obj: unknown = typeof line === "string" ? JSON.parse(line) : line;
  if (typeof obj !== "object" || obj === null || Array.isArray(obj)) {
    throw new Error("receipt must be a JSON object");
  }
  const out: Record<string, unknown> = {};
  for (const [k, val] of Object.entries(obj as Record<string, unknown>)) {
    const name = Object.prototype.hasOwnProperty.call(RECEIPT_JSON_KEYS, k) ? RECEIPT_JSON_KEYS[k] : undefined;
    if (!name) throw new Error(`unknown receipt key: ${k}`);
    out[name] = val;
  }
  for (const k of RECEIPT_REQUIRED) {
    if (!(k in out)) throw new Error(`receipt is missing ${k}`);
  }
  return out as unknown as PortableReceipt;
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

const SIG_V1_PREFIX = "sig_v1:";
const SIG_V2_PREFIX = "sig_v2:";
// Separates v2 receipt signatures from every other use of the key
// (domainV2 in proxy/internal/receipts/chain.go).
const RECEIPT_DOMAIN_V2 = "ovara-proxy-receipt-v2\n";

// receiptCanonicalV1 mirrors Receipt.canonicalV1() in the proxy:
// receipt_id|session_id|unixnano|method|url|decision|status|prev_hash
// with "|approval_id" appended when approval_id is non-empty.
function receiptCanonicalV1(r: PortableReceipt): string {
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

// receiptCanonicalV2 mirrors Receipt.canonicalV2(): the domain separator,
// then each field as a length-prefixed name and a length-prefixed value
// (big-endian uint32 byte counts of the UTF-8 encoding), in a fixed
// order. reasons is its count, then each reason length-prefixed.
function receiptCanonicalV2(r: PortableReceipt): Buffer {
  const parts: Buffer[] = [Buffer.from(RECEIPT_DOMAIN_V2, "utf8")];
  const lp = (s: string) => {
    const b = Buffer.from(s, "utf8");
    const n = Buffer.alloc(4);
    n.writeUInt32BE(b.length, 0);
    parts.push(n, b);
  };
  const field = (name: string, val: string) => {
    lp(name);
    lp(val);
  };
  const reasons = r.reasons ?? [];
  field("v", String(r.v ?? 0));
  field("receipt_id", r.receiptId);
  field("session_id", r.sessionId);
  field("timestamp", rfc3339ToUnixNano(r.timestamp).toString());
  field("method", r.method);
  field("url", r.url);
  field("decision", r.decision);
  field("status", String(r.status));
  field("approval_id", r.approvalId ?? "");
  field("phase", r.phase ?? "");
  field("outcome", r.outcome ?? "");
  field("attempt_id", r.attemptId ?? "");
  field("agent", r.agent ?? "");
  field("rule", r.rule ?? "");
  field("policy_hash", r.policyHash ?? "");
  field("approver", r.approver ?? "");
  field("req_bytes", String(r.reqBytes ?? 0));
  field("resp_bytes", String(r.respBytes ?? 0));
  field("body_sha256", r.bodySha256 ?? "");
  field("reasons", String(reasons.length));
  for (const s of reasons) lp(s);
  field("kid", r.kid ?? "");
  field("prev_hash", r.prevHash);
  return Buffer.concat(parts);
}

// receiptHasV2Fields: any field a v1 signature does not cover is set
// (hasV2Fields in the proxy).
function receiptHasV2Fields(r: PortableReceipt): boolean {
  const nonZero = (n: number | bigint | undefined) => n !== undefined && n !== 0 && n !== 0n;
  return Boolean(
    r.phase || r.outcome || r.attemptId || r.agent || r.rule || r.policyHash || r.approver ||
      nonZero(r.reqBytes) || nonZero(r.respBytes) || r.bodySha256 ||
      (r.reasons !== undefined && r.reasons !== null && r.reasons.length > 0) || r.kid
  );
}

// receiptVersion is the canonical form a receipt claims: 2 when anything
// about it says v2 (the v field, a "sig_v2:" signature, or a field only v2
// signs), 1 otherwise.
function receiptVersion(r: PortableReceipt): 1 | 2 {
  if (r.v === 2 || (r.signature ?? "").startsWith(SIG_V2_PREFIX) || receiptHasV2Fields(r)) return 2;
  return 1;
}

// A lone UTF-16 surrogate has no UTF-8 encoding (Buffer.from would turn it
// into U+FFFD, the same bytes as a real U+FFFD), and no line the proxy
// writes decodes to one.
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

// receiptTypesOk checks the JSON types the proxy writes.
function receiptTypesOk(r: PortableReceipt): boolean {
  const isStr = (x: unknown) => typeof x === "string" && !LONE_SURROGATE.test(x);
  const optStr = (x: unknown) => x === undefined || isStr(x);
  const isInt = (x: unknown) => (typeof x === "number" && Number.isSafeInteger(x)) || typeof x === "bigint";
  const optInt = (x: unknown) => x === undefined || isInt(x);
  return (
    [r.receiptId, r.sessionId, r.timestamp, r.method, r.url, r.decision, r.prevHash, r.signature].every(isStr) &&
    [r.approvalId, r.phase, r.outcome, r.attemptId, r.agent, r.rule, r.policyHash, r.approver, r.bodySha256, r.kid].every(
      optStr
    ) &&
    isInt(r.status) &&
    [r.v, r.reqBytes, r.respBytes].every(optInt) &&
    (r.reasons === undefined || (Array.isArray(r.reasons) && r.reasons.every(isStr)))
  );
}

/**
 * receiptKeyId is the id a v2 receipt names its signing key by (`kid`):
 * the first 16 hex digits of the SHA-256 of the raw public key (KeyID in
 * proxy/internal/receipts/keys.go).
 */
export function receiptKeyId(publicKeyHex: string): string {
  return createHash("sha256").update(Buffer.from(publicKeyHex, "hex")).digest("hex").slice(0, 16);
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
 * verifyReceipt verifies one Ovara *proxy* receipt (see PortableReceipt)
 * against the proxy's public key (the pubkey file written next to the
 * receipt chain). The version is chosen by the signature prefix and the
 * `v` field, and they must agree:
 *
 * - "sig_v2:" requires `v` === 2 and `kid` naming the public key; the
 *   signature covers the v2 length-prefixed encoding of every field.
 * - "sig_v1:" requires no `v` and no v2-only field (a v1 signature does
 *   not cover them, so a receipt carrying them is refused rather than
 *   verified on the fields it happens to sign).
 *
 * This checks a single receipt. Chain properties (prev_hash links, v1
 * never following v2, outcomes naming an earlier attempt, key validity
 * windows) are checked by `ovara log --verify-only`.
 */
export function verifyReceipt(receipt: PortableReceipt, publicKeyHex: string): boolean {
  if (!receipt.signature || !publicKeyHex) return false;
  if (!receiptTypesOk(receipt)) return false;
  const sig = receipt.signature;
  if (!/^sig_v[12]:[0-9a-fA-F]{128}$/.test(sig)) return false;

  try {
    if (sig.startsWith(SIG_V2_PREFIX)) {
      if (receipt.v !== 2) return false;
      if (receipt.kid !== receiptKeyId(publicKeyHex)) return false;
      return verifyEd25519(sig.slice(SIG_V2_PREFIX.length), receiptCanonicalV2(receipt), publicKeyHex);
    }
    if (sig.startsWith(SIG_V1_PREFIX)) {
      if (receipt.v !== undefined || receiptHasV2Fields(receipt)) return false;
      return verifyEd25519(sig.slice(SIG_V1_PREFIX.length), receiptCanonicalV1(receipt), publicKeyHex);
    }
  } catch {
    return false;
  }
  return false;
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

/**
 * computeReceiptDigest is the SHA-256 (hex) of the receipt's canonical
 * signing payload, v1 or v2 as the receipt claims (see verifyReceipt).
 */
export function computeReceiptDigest(receipt: PortableReceipt): string {
  const payload = receiptVersion(receipt) === 2 ? receiptCanonicalV2(receipt) : receiptCanonicalV1(receipt);
  return createHash("sha256").update(payload).digest("hex");
}

/** @internal Canonical-form helpers, exposed for the SDK's own test vectors. */
export const __receiptInternals = { receiptCanonicalV1, receiptCanonicalV2, receiptVersion, rfc3339ToUnixNano };

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
