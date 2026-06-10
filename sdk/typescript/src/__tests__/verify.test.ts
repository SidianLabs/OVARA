import { describe, it, expect } from "vitest";
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

  it("computeReceiptDigest works", () => {
    const receipt: PortableReceipt = {
      receiptId: "r1",
      decisionId: "d1",
      issuingGateway: "gw1",
      issuingOrg: "acme",
      actionType: "shell.execute",
      resource: "npm",
      decision: "allow",
      agentIdentity: "agt1",
      trustScore: 0.95,
      timestamp: 1_750_000_000,
      signature: "sig",
    };
    const d1 = computeReceiptDigest(receipt);
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
    const receipt: PortableReceipt = {
      receiptId: "r1", decisionId: "d1", issuingGateway: "g1",
      issuingOrg: "org1", actionType: "shell", resource: "ls",
      decision: "allow", agentIdentity: "a1", trustScore: 0.9,
      timestamp: 1_750_000_000, signature: "",
    };
    expect(verifyReceipt(receipt, "abc")).toBe(false);
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

    const emptyLease: PortableLease = { ...lease, resourceScope: "" };
    expect(scopeCovers(emptyLease, "anything")).toBe(true);
  });
});
