import { describe, it, expect } from "vitest";
import { generateKeyPairSync, sign as cryptoSign } from "crypto";
import {
  verifyAgentIdentity,
  verifyCapabilityLease,
  verifyReceipt,
  computeIdentityDigest,
  computeReceiptDigest,
  isLeaseExpired,
  hasAction,
  scopeCovers,
} from "../verify";
import type { PortableIdentity, PortableLease, PortableReceipt } from "../verify";

describe("Verification functions", () => {
  const testIdentity: PortableIdentity = {
    id: "agt_abc123",
    issuer: "ovara",
    subjectId: "agent-007",
    owner: "acme-corp",
    lifecycle: "active",
    publicKey: "deadbeef",
    signature: "sig_placeholder",
  };

  it("computeIdentityDigest produces deterministic hash", () => {
    const d1 = computeIdentityDigest(testIdentity);
    const d2 = computeIdentityDigest(testIdentity);
    expect(d1).toBe(d2);
    expect(d1).toHaveLength(64);
  });

  const testReceipt: PortableReceipt = {
    receiptId: "rcpt_abc123",
    sessionId: "sess1",
    timestamp: "2025-09-14T12:34:56.123456789Z",
    method: "POST",
    url: "https://api.example.com/v1",
    decision: "allow",
    status: 200,
    prevHash: "",
    signature: "sig_v1:00",
  };

  it("computeReceiptDigest works", () => {
    const d1 = computeReceiptDigest(testReceipt);
    expect(d1).toHaveLength(64);
  });

  it("verifyAgentIdentity returns false without signature", () => {
    const result = verifyAgentIdentity({ ...testIdentity, signature: undefined }, testIdentity.publicKey);
    expect(result).toBe(false);
  });

  it("verifyAgentIdentity returns false without public key", () => {
    const result = verifyAgentIdentity(testIdentity, "");
    expect(result).toBe(false);
  });

  it("verifyAgentIdentity verifies a real Ed25519 signature", () => {
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    const publicKeyHex = Buffer.from(
      (publicKey.export({ format: "jwk" }) as { x: string }).x,
      "base64url"
    ).toString("hex");

    const identity: PortableIdentity = {
      id: "agt_real",
      issuer: "ovara",
      subjectId: "agent-007",
      owner: "acme-corp",
      lifecycle: "active",
      publicKey: "embedded-not-used",
    };
    const payload = `${identity.id}|${identity.issuer}|${identity.subjectId}|${identity.owner}|${identity.lifecycle}`;
    identity.signature = cryptoSign(null, Buffer.from(payload), privateKey).toString("hex");

    expect(verifyAgentIdentity(identity, publicKeyHex)).toBe(true);

    const otherKey = generateKeyPairSync("ed25519").publicKey;
    const otherHex = Buffer.from(
      (otherKey.export({ format: "jwk" }) as { x: string }).x,
      "base64url"
    ).toString("hex");
    expect(verifyAgentIdentity(identity, otherHex)).toBe(false);
  });

  it("verifyCapabilityLease returns false without signature", () => {
    const lease: PortableLease = {
      leaseId: "l1", issuer: "i1", subject: "s1",
      allowedActions: ["shell.execute"], resourceScope: "*",
      expiry: 2_000_000_000, delegationDepth: 2, issuedAt: 1_750_000_000,
      signature: "",
    };
    expect(verifyCapabilityLease(lease, "abc")).toBe(false);
  });

  it("verifyReceipt returns false without signature", () => {
    expect(verifyReceipt({ ...testReceipt, signature: "" }, "abc")).toBe(false);
  });

  it("verifyReceipt verifies a real proxy sig_v1 signature", () => {
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    const publicKeyHex = Buffer.from(
      (publicKey.export({ format: "jwk" }) as { x: string }).x,
      "base64url"
    ).toString("hex");

    // Canonical payload: receipt_id|session_id|unixnano|method|url|decision|status|prev_hash
    // timestamp "2025-09-14T12:34:56.123456789Z" -> 1757853296123456789
    const payload = "rcpt_abc123|sess1|1757853296123456789|POST|https://api.example.com/v1|allow|200|";
    const sig = "sig_v1:" + cryptoSign(null, Buffer.from(payload), privateKey).toString("hex");

    expect(verifyReceipt({ ...testReceipt, signature: sig }, publicKeyHex)).toBe(true);
    expect(verifyReceipt({ ...testReceipt, signature: sig, decision: "deny" }, publicKeyHex)).toBe(false);
  });

  it("isLeaseExpired detects expired lease", () => {
    const past: PortableLease = {
      leaseId: "l1", issuer: "i1", subject: "s1",
      allowedActions: [], resourceScope: "*",
      expiry: 1, delegationDepth: 0, issuedAt: 0,
      signature: "sig",
    };
    const future: PortableLease = { ...past, expiry: 4_000_000_000 };
    expect(isLeaseExpired(past)).toBe(true);
    expect(isLeaseExpired(future)).toBe(false);
  });

  it("hasAction matches exact and wildcard", () => {
    const lease: PortableLease = {
      leaseId: "l1", issuer: "i1", subject: "s1",
      allowedActions: ["shell.execute", "git.push", "*"],
      resourceScope: "*",
      expiry: 4_000_000_000, delegationDepth: 0, issuedAt: 0,
      signature: "sig",
    };
    expect(hasAction(lease, "shell.execute")).toBe(true);
    expect(hasAction(lease, "git.clone")).toBe(true);
    expect(hasAction(lease, "unsupported.action")).toBe(true);
  });

  it("scopeCovers works", () => {
    const lease: PortableLease = {
      leaseId: "l1", issuer: "i1", subject: "s1",
      allowedActions: [], resourceScope: "repo/my-app",
      expiry: 4_000_000_000, delegationDepth: 0, issuedAt: 0,
      signature: "sig",
    };
    expect(scopeCovers(lease, "repo/my-app")).toBe(true);
    expect(scopeCovers(lease, "other-repo")).toBe(false);

    const wildcardLease: PortableLease = { ...lease, resourceScope: "*" };
    expect(scopeCovers(wildcardLease, "anything")).toBe(true);

    // Gateway requires a non-empty resource_scope: empty covers nothing.
    const emptyLease: PortableLease = { ...lease, resourceScope: "" };
    expect(scopeCovers(emptyLease, "anything")).toBe(false);
  });

  it("hasAction returns false for expired lease", () => {
    const expired: PortableLease = {
      leaseId: "l1", issuer: "i1", subject: "s1",
      allowedActions: ["shell.execute", "*"],
      resourceScope: "*",
      expiry: 1, delegationDepth: 0, issuedAt: 0,
      signature: "sig",
    };
    expect(hasAction(expired, "shell.execute")).toBe(false);
  });
});
