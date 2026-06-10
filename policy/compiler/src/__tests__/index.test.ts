import { describe, it, expect } from "vitest";
import { compilePolicy, simulateDecision, diffPolicies, PolicyDocument } from "../index";

const validDoc: PolicyDocument = {
  name: "test-policy",
  version: 1,
  defaultEffect: "deny",
  rules: [
    { id: "r1", action: "shell.execute", target: "sudo", effect: "deny", priority: 100 },
    { id: "r2", action: "shell.execute", target: "*", effect: "allow", priority: 0 },
    { id: "r3", action: "git.push", target: "main", effect: "deny", priority: 50 },
  ],
};

describe("compilePolicy", () => {
  it("compiles a valid policy document", () => {
    const result = compilePolicy(validDoc);
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
    expect(result.compiled).toBeDefined();
    const compiled = result.compiled as any;
    expect(compiled.name).toBe("test-policy");
    expect(compiled.rules).toHaveLength(3);
    expect(compiled.rules[0].id).toBe("r1");
  });

  it("sorts rules by priority descending", () => {
    const result = compilePolicy(validDoc);
    const rules = (result.compiled as any).rules;
    expect(rules[0].priority).toBe(100);
    expect(rules[1].priority).toBe(50);
    expect(rules[2].priority).toBe(0);
  });

  it("rejects policy with duplicate rule IDs", () => {
    const dupDoc: PolicyDocument = {
      name: "dup",
      version: 1,
      rules: [
        { id: "r1", action: "a", target: "x", effect: "allow", priority: 0 },
        { id: "r1", action: "a", target: "y", effect: "deny", priority: 10 },
      ],
    };
    const result = compilePolicy(dupDoc);
    expect(result.valid).toBe(false);
    expect(result.errors[0]).toContain("duplicate rule id");
  });

  it("rejects empty rules array", () => {
    const result = compilePolicy({
      name: "empty",
      version: 1,
      rules: [],
    });
    expect(result.valid).toBe(false);
  });

  it("rejects missing required fields", () => {
    const result = compilePolicy({
      name: "",
      version: 1,
      rules: [{ id: "", action: "", target: "", effect: "allow" as const, priority: 0 }],
    });
    expect(result.valid).toBe(false);
    expect(result.errors.length).toBeGreaterThan(0);
  });

  it("defaults version to 1 when not provided", () => {
    const result = compilePolicy({
      name: "test",
      rules: [{ id: "r1", action: "a", target: "x", effect: "allow", priority: 0 }],
    } as any);
    const compiled = result.compiled as any;
    expect(compiled.version).toBe(1);
  });
});

describe("simulateDecision", () => {
  it("allows a matching rule", () => {
    const result = simulateDecision(validDoc, "shell.execute", "ls");
    expect(result.decision).toBe("allow");
    expect(result.matchedRule).toBe("r2");
  });

  it("denies a blocked action", () => {
    const result = simulateDecision(validDoc, "shell.execute", "sudo");
    expect(result.decision).toBe("deny");
    expect(result.matchedRule).toBe("r1");
  });

  it("returns default effect when no rule matches", () => {
    const result = simulateDecision(validDoc, "http.get", "https://example.com");
    expect(result.decision).toBe("deny");
    expect(result.matchedRule).toBeUndefined();
  });

  it("wildcard action matches any action", () => {
    const wildcardDoc: PolicyDocument = {
      name: "wildcard",
      version: 1,
      rules: [{ id: "r1", action: "*", target: "*", effect: "deny", priority: 0 }],
    };
    const result = simulateDecision(wildcardDoc, "anything.here", "any-resource");
    expect(result.decision).toBe("deny");
    expect(result.matchedRule).toBe("r1");
  });

  it("higher priority rule wins", () => {
    const result = simulateDecision(validDoc, "git.push", "main");
    expect(result.decision).toBe("deny");
    expect(result.matchedRule).toBe("r3");
  });
});

describe("diffPolicies", () => {
  it("detects added rules", () => {
    const oldDoc: PolicyDocument = {
      name: "p", version: 1,
      rules: [{ id: "r1", action: "a", target: "x", effect: "allow", priority: 0 }],
    };
    const newDoc: PolicyDocument = {
      name: "p", version: 2,
      rules: [
        { id: "r1", action: "a", target: "x", effect: "allow", priority: 0 },
        { id: "r2", action: "b", target: "y", effect: "deny", priority: 10 },
      ],
    };

    const diff = diffPolicies(oldDoc, newDoc);
    expect((diff.added as any[]).length).toBe(1);
    expect((diff.added as any[])[0].id).toBe("r2");
  });

  it("detects removed rules", () => {
    const oldDoc: PolicyDocument = {
      name: "p", version: 1,
      rules: [
        { id: "r1", action: "a", target: "x", effect: "allow", priority: 0 },
        { id: "r2", action: "b", target: "y", effect: "deny", priority: 10 },
      ],
    };
    const newDoc: PolicyDocument = {
      name: "p", version: 2,
      rules: [{ id: "r1", action: "a", target: "x", effect: "allow", priority: 0 }],
    };

    const diff = diffPolicies(oldDoc, newDoc);
    expect((diff.removed as any[]).length).toBe(1);
    expect((diff.removed as any[])[0].id).toBe("r2");
  });

  it("detects modified rules", () => {
    const oldDoc: PolicyDocument = {
      name: "p", version: 1,
      rules: [{ id: "r1", action: "a", target: "x", effect: "allow", priority: 0 }],
    };
    const newDoc: PolicyDocument = {
      name: "p", version: 2,
      rules: [{ id: "r1", action: "a", target: "x", effect: "deny", priority: 100 }],
    };

    const diff = diffPolicies(oldDoc, newDoc);
    expect((diff.modified as any[]).length).toBe(1);
    expect((diff.modified as any[])[0].effect).toBe("deny");
  });

  it("tracks version change", () => {
    const diff = diffPolicies(validDoc, { ...validDoc, version: 3 });
    expect((diff.version as any).from).toBe(1);
    expect((diff.version as any).to).toBe(3);
  });
});
