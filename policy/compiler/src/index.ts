import { z } from "zod";

export const PolicyRule = z.object({
  id: z.string().min(1),
  action: z.string().min(1),
  target: z.string().min(1),
  condition: z.string().optional(),
  effect: z.enum(["allow", "deny"]),
  priority: z.number().int().min(0).default(0),
});

export const PolicyDocument = z.object({
  id: z.string().optional(),
  name: z.string().min(1),
  version: z.number().int().min(1).default(1),
  rules: z.array(PolicyRule).min(1),
  defaultEffect: z.enum(["allow", "deny"]).default("deny"),
});

export type PolicyRule = z.infer<typeof PolicyRule>;
export type PolicyDocument = z.infer<typeof PolicyDocument>;

export function compilePolicy(doc: PolicyDocument): { valid: boolean; errors: string[]; compiled?: unknown } {
  const result = PolicyDocument.safeParse(doc);
  if (!result.success) {
    return { valid: false, errors: result.error.issues.map(i => `${i.path.join(".")}: ${i.message}`) };
  }

  const validated = result.data;
  const sorted = [...validated.rules].sort((a, b) => b.priority - a.priority);

  const ids = new Set<string>();
  for (const rule of sorted) {
    if (ids.has(rule.id)) {
      return { valid: false, errors: [`duplicate rule id: ${rule.id}`] };
    }
    ids.add(rule.id);
  }

  return {
    valid: true,
    errors: [],
    compiled: {
      name: validated.name,
      version: validated.version,
      rules: sorted,
      default_effect: validated.defaultEffect,
      rule_count: sorted.length,
      compiled_at: new Date().toISOString(),
    },
  };
}

export function simulateDecision(doc: PolicyDocument, action: string, resource: string): { decision: string; matchedRule?: string } {
  const compiled = compilePolicy(doc);
  if (!compiled.valid || !compiled.compiled) return { decision: doc.defaultEffect || "deny" };

  const rules = (compiled.compiled as any).rules as PolicyRule[];
  for (const rule of rules) {
    const actionMatch = rule.action === action || rule.action === "*";
    const resourceMatch = rule.target === resource || rule.target === "*";

    if (actionMatch && resourceMatch) {
      return { decision: rule.effect, matchedRule: rule.id };
    }
  }

  return { decision: doc.defaultEffect || "deny" };
}

export function diffPolicies(oldDoc: PolicyDocument, newDoc: PolicyDocument): Record<string, unknown> {
  const oldIds = new Set(oldDoc.rules.map(r => r.id));
  const newIds = new Set(newDoc.rules.map(r => r.id));

  return {
    added: newDoc.rules.filter(r => !oldIds.has(r.id)),
    removed: oldDoc.rules.filter(r => !newIds.has(r.id)),
    modified: newDoc.rules.filter(r => {
      const old = oldDoc.rules.find(o => o.id === r.id);
      return old && JSON.stringify(old) !== JSON.stringify(r);
    }),
    version: { from: oldDoc.version, to: newDoc.version },
  };
}
