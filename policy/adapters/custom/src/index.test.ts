import { describe, it, expect } from 'vitest';
import { translateCustom, translateCustomJSON, type OvaraPolicy } from './index';

describe('Custom JSON adapter', () => {
  it('translates template rules without sources', () => {
    const config = {
      version: 'v1',
      mappings: [
        {
          name: 'acme-policies',
          source: 'acme',
          match: { action: '$.operation', resource: '$.target', effect: '$.outcome' },
          rules: [
            { action: 'shell', resource: 'local', effect: 'allow' as const },
            { action: 'git.push', effect: 'escalate' as const },
          ],
        },
      ],
    };
    const result = translateCustom(config);
    expect(result.rules).toHaveLength(2);
    expect(result.rules[0].action_type).toBe('shell');
    expect(result.rules[0].environment).toBe('local');
    expect(result.rules[0].allow).toBe(true);
  });

  it('resolves JSONPath from source objects', () => {
    const config = {
      version: 'v1',
      mappings: [
        {
          name: 'acme',
          source: 'acme',
          match: { action: '$.operation', resource: '$.target', effect: '$.outcome' },
          rules: [{ action: '*', effect: 'allow' as const }],
        },
      ],
    };
    const sources = [
      { operation: 'shell:ls', target: 'shell:ls', outcome: 'allow' },
      { operation: 'git.push', target: 'repo:main', outcome: 'escalate' },
    ];
    const result = translateCustom(config, sources);
    expect(result.rules).toHaveLength(2);
    expect(result.rules[0].action_type).toBe('shell:ls');
    expect(result.rules[0].allow).toBe(true);
    expect(result.rules[1].action_type).toBe('git.push');
    // Without template rules, effect comes from $.outcome
    // The first source's outcome was 'allow' so this would be 'allow' too
  });

  it('rejects missing version', () => {
    expect(() =>
      translateCustom({ version: '', mappings: [] })
    ).toThrow(/missing version/);
  });

  it('rejects empty mappings', () => {
    expect(() =>
      translateCustom({ version: 'v1', mappings: [] })
    ).toThrow(/no mappings/);
  });

  it('rejects mappings without name', () => {
    expect(() =>
      translateCustom({
        version: 'v1',
        mappings: [{ name: '', source: 'x', match: { action: '$.a', resource: '$.r', effect: '$.e' }, rules: [] }],
      })
    ).toThrow(/mapping missing name/);
  });

  it('produces valid JSON', () => {
    const config = {
      version: 'v1',
      mappings: [
        {
          name: 'test',
          source: 'test',
          match: { action: '$.a', resource: '$.r', effect: '$.e' },
          rules: [{ action: 'shell', effect: 'allow' as const }],
        },
      ],
    };
    const json = translateCustomJSON(config);
    const parsed: OvaraPolicy = JSON.parse(json);
    expect(parsed.rules).toHaveLength(1);
  });

  it('preserves deny effect', () => {
    const config = {
      version: 'v1',
      mappings: [
        {
          name: 'strict',
          source: 'org',
          match: { action: '$.a', resource: '$.r', effect: '$.e' },
          rules: [{ action: 'exec', effect: 'deny' as const }],
        },
      ],
    };
    const result = translateCustom(config);
    expect(result.rules[0].deny).toBe(true);
  });

  it('preserves conditions passthrough', () => {
    const config = {
      version: 'v1',
      mappings: [
        {
          name: 'test',
          source: 't',
          match: { action: '$.a', resource: '$.r', effect: '$.e' },
          rules: [{
            action: 'shell',
            effect: 'escalate' as const,
            conditions: { agent_id: 'agt-001' },
          }],
        },
      ],
    };
    const result = translateCustom(config);
    expect(result.rules[0].conditions).toEqual({ agent_id: 'agt-001' });
  });
});
