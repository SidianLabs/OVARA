import { describe, it, expect } from 'vitest';
import { translateCedar, translateCedarJSON, parseCedar, type OvaraPolicy } from './index';

describe('Cedar adapter', () => {
  it('translates a single permit statement', () => {
    const cedar = `
      permit (
        principal == Agent::"agt-001",
        action == Action::"git.pull",
        resource == Repo::"*"
      );
    `;
    const result = translateCedar(cedar);
    expect(result.version).toBe('v1-from-cedar');
    expect(result.rules).toHaveLength(1);
    expect(result.rules[0].action_type).toBe('git.pull');
    expect(result.rules[0].allow).toBe(true);
  });

  it('translates a forbid statement', () => {
    const cedar = `
      forbid (
        principal,
        action == Action::"shell",
        resource == Repo::"acme/api"
      );
    `;
    const result = translateCedar(cedar);
    const denyRule = result.rules.find(r => r.deny);
    expect(denyRule).toBeDefined();
    expect(denyRule!.action_type).toBe('shell');
    expect(denyRule!.environment).toBe('acme/api');
  });

  it('combines permit and forbid (no catch-all because permit exists)', () => {
    const cedar = `
      permit (
        principal == Agent::"agt-001",
        action == Action::"git.pull"
      );

      forbid (
        principal,
        action == Action::"shell",
        resource == Repo::"production"
      );
    `;
    const result = translateCedar(cedar);
    expect(result.rules).toHaveLength(2);
    expect(result.rules.some(r => r.allow)).toBe(true);
    expect(result.rules.some(r => r.deny)).toBe(true);
  });

  it('adds catch-all escalate when policy has only forbid', () => {
    const cedar = `
      forbid (
        principal,
        action == Action::"shell",
        resource == Repo::"production"
      );
    `;
    const result = translateCedar(cedar);
    expect(result.rules).toHaveLength(2);
    expect(result.rules.some(r => r.escalate && r.action_type === '*')).toBe(true);
  });

  it('extracts principal into conditions', () => {
    const cedar = `
      permit (
        principal == Agent::"agt-001",
        action == Action::"shell"
      );
    `;
    const result = translateCedar(cedar);
    const rule = result.rules[0];
    expect(rule.conditions?.principal_id).toBe('agt-001');
  });

  it('parses when conditions into rule.conditions', () => {
    const cedar = `
      permit (
        principal,
        action == Action::"shell"
      ) when { principal.trust_score < 0.5, principal.role == "admin" };
    `;
    const result = translateCedar(cedar);
    const rule = result.rules[0];
    expect(rule.conditions?.principal_trust_score_lt).toBe(0.5);
    expect(rule.conditions?.principal_role_eq).toBe('admin');
  });

  it('parses Cedar source into statements', () => {
    const cedar = `permit (action == Action::"shell"); forbid (action == Action::"exec");`;
    const parsed = parseCedar(cedar);
    expect(parsed.statements).toHaveLength(2);
    expect(parsed.statements[0].effect).toBe('permit');
    expect(parsed.statements[1].effect).toBe('forbid');
  });

  it('rejects empty policy', () => {
    expect(() => translateCedar('')).toThrow(/empty policy/);
  });

  it('rejects policy with no statements', () => {
    expect(() => translateCedar('// just a comment')).toThrow(/no statements/);
  });

  it('produces valid JSON', () => {
    const cedar = `permit (action == Action::"git.pull");`;
    const json = translateCedarJSON(cedar);
    const parsed: OvaraPolicy = JSON.parse(json);
    expect(parsed.rules).toHaveLength(1);
  });

  it('preserves line numbers in descriptions', () => {
    const cedar = `// comment
permit (action == Action::"shell");`;
    const result = translateCedar(cedar);
    expect(result.rules[0].description).toMatch(/line 2/);
  });

  it('handles wildcard action and resource', () => {
    const cedar = `
      permit (
        principal,
        action,
        resource
      );
    `;
    const result = translateCedar(cedar);
    expect(result.rules[0].action_type).toBe('*');
    expect(result.rules[0].environment).toBe('*');
  });
});
