import { describe, it, expect } from 'vitest';
import { translateRego, translateRegoJSON, type OvaraPolicy } from './index';

describe('OPA (Rego) adapter', () => {
  it('translates a single allow rule (with default-deny catch-all)', () => {
    const rego = `
      package ovara.runtime

      default allow = false

      allow {
        input.action_type == "git.pull"
      }
    `;
    const result = translateRego(rego);
    expect(result.version).toBe('v1-from-opa');
    expect(result.rules).toHaveLength(2);
    expect(result.rules[0].action_type).toBe('git.pull');
    expect(result.rules[0].allow).toBe(true);
    expect(result.rules[1].action_type).toBe('*');
    expect(result.rules[1].escalate).toBe(true);
  });

  it('translates a deny rule (with default-deny catch-all)', () => {
    const rego = `
      package ovara.runtime

      deny {
        input.environment == "production"
        input.action_type == "shell"
      }
    `;
    const result = translateRego(rego);
    expect(result.rules.length).toBeGreaterThanOrEqual(1);
    const denyRule = result.rules.find(r => r.deny);
    expect(denyRule).toBeDefined();
    expect(denyRule!.action_type).toBe('shell');
    expect(denyRule!.environment).toBe('production');
  });

  it('combines multiple rules and adds catch-all when default-deny', () => {
    const rego = `
      package ovara.runtime

      default allow = false

      allow {
        input.action_type == "git.pull"
      }

      allow {
        input.environment == "local"
        input.action_type == "shell"
      }

      deny {
        input.environment == "production"
      }
    `;
    const result = translateRego(rego);
    const actions = result.rules.map(r => r.action_type);
    expect(actions).toContain('git.pull');
    expect(actions).toContain('shell');
    expect(actions).toContain('*'); // catch-all
  });

  it('skips catch-all escalate when package default-allows', () => {
    const rego = `
      package ovara.runtime

      default allow = true

      allow {
        input.action_type == "git.pull"
      }
    `;
    const result = translateRego(rego);
    // No catch-all escalate when default=allow
    const catchAll = result.rules.find(r => r.action_type === '*' && r.escalate);
    expect(catchAll).toBeUndefined();
  });

  it('preserves extra conditions as JSON', () => {
    const rego = `
      package ovara.runtime

      allow {
        input.action_type == "shell"
        input.environment == "dev"
        input.agent_id == "agt-001"
      }
    `;
    const result = translateRego(rego);
    const rule = result.rules.find(r => r.action_type === 'shell');
    expect(rule).toBeDefined();
    expect(rule!.conditions).toBeDefined();
    expect(rule!.conditions!.agent_id).toBe('agt-001');
  });

  it('rejects packages outside the ovara namespace', () => {
    const rego = `
      package kubernetes.admission

      allow {
        input.action_type == "shell"
      }
    `;
    expect(() => translateRego(rego)).toThrow(/package must start with 'ovara'/);
  });

  it('rejects missing package declaration', () => {
    const rego = `
      allow {
        input.action_type == "shell"
      }
    `;
    expect(() => translateRego(rego)).toThrow(/missing 'package'/);
  });

  it('rejects empty policy', () => {
    expect(() => translateRego('')).toThrow(/empty policy/);
  });

  it('produces valid JSON', () => {
    const rego = `
      package ovara.runtime

      allow {
        input.action_type == "git.pull"
      }
    `;
    const json = translateRegoJSON(rego);
    const parsed: OvaraPolicy = JSON.parse(json);
    expect(parsed.rules.length).toBeGreaterThan(0);
  });

  it('preserves line numbers in descriptions', () => {
    const rego = `package ovara.runtime
default allow = false
allow {
  input.action_type == "git.pull"
}`;
    const result = translateRego(rego);
    const allowRule = result.rules.find(r => r.allow);
    expect(allowRule).toBeDefined();
    // 'allow {' is on line 3 (1-indexed)
    expect(allowRule!.description).toMatch(/line 3/);
  });

  it('translates Rego v1 syntax: import, default :=, allow if', () => {
    const rego = `
      package ovara.runtime

      import rego.v1

      default allow := false

      allow if {
        input.action_type == "git.pull"
      }

      allow if input.environment == "local"

      deny if {
        input.environment == "production"  # never allow shells in prod
        input.action_type == "shell"
      }
    `;
    const result = translateRego(rego);
    const allowRule = result.rules.find(r => r.allow && r.action_type === 'git.pull');
    expect(allowRule).toBeDefined();
    const localRule = result.rules.find(r => r.allow && r.environment === 'local');
    expect(localRule).toBeDefined();
    const denyRule = result.rules.find(r => r.deny);
    expect(denyRule).toBeDefined();
    expect(denyRule!.environment).toBe('production');
  });

  it('splits body expressions joined by semicolons', () => {
    const rego = `package ovara.runtime
allow if { input.action_type == "shell"; input.environment == "dev" }`;
    const result = translateRego(rego);
    const rule = result.rules.find(r => r.allow);
    expect(rule).toBeDefined();
    expect(rule!.action_type).toBe('shell');
    expect(rule!.environment).toBe('dev');
  });

  it('substitutes := bindings and accepts some declarations', () => {
    const rego = `package ovara.runtime
allow if {
  some env
  env := "dev"
  input.environment == env
  input.action_type == "shell"
}`;
    const result = translateRego(rego);
    const rule = result.rules.find(r => r.allow);
    expect(rule).toBeDefined();
    expect(rule!.environment).toBe('dev');
  });

  it('maps startswith to a glob condition', () => {
    const rego = `package ovara.runtime
allow if {
  startswith(input.action_type, "git.")
}`;
    const result = translateRego(rego);
    const rule = result.rules.find(r => r.allow);
    expect(rule).toBeDefined();
    expect(rule!.action_type).toBe('git.*');
  });

  it('maps != and > comparisons into conditions', () => {
    const rego = `package ovara.runtime
deny if {
  input.environment != "dev"
  input.risk > 5
}`;
    const result = translateRego(rego);
    const rule = result.rules.find(r => r.deny);
    expect(rule).toBeDefined();
    expect(rule!.environment).toBe('!=dev');
    expect(rule!.conditions!.risk).toBe('>5');
  });

  it('still rejects untranslatable expressions fail-closed', () => {
    const rego = `package ovara.runtime
allow if {
  crypto.verify(input.token)
}`;
    expect(() => translateRego(rego)).toThrow(/unhandled body expression/);
  });

  it('rejects else after allow (would broaden allow)', () => {
    const rego = `package ovara.runtime
allow if {
  input.environment == "dev"
} else {
  input.environment == "local"
}`;
    expect(() => translateRego(rego)).toThrow(/else/i);
  });

  it('emits wildcard rule when there are no explicit allow/deny', () => {
    const rego = `
      package ovara.runtime

      default allow = false
    `;
    const result = translateRego(rego);
    expect(result.rules).toHaveLength(1);
    expect(result.rules[0].action_type).toBe('*');
    expect(result.rules[0].escalate).toBe(true);
  });
});
