import { describe, it, expect, vi, beforeEach } from 'vitest';
import { ovaraGuard, handleOvaraToolCall } from '../guard';

vi.mock('@ovara/sdk', () => ({
  createClient: vi.fn(() => ({
    check: vi.fn().mockResolvedValue({
      decision: 'allow',
      request_id: 'req-001',
      trust_score: 0.95,
      reason: 'local policy',
    }),
  })),
}));

describe('ovaraGuard', () => {
  it('returns a function tool definition', () => {
    const guard = ovaraGuard();
    expect(guard).toHaveProperty('type', 'function');
    expect(guard).toHaveProperty('function');
    const fn = guard.function as { name: string; description: string; parameters: object };
    expect(fn.name).toBe('ovara_check');
    expect(fn.description).toContain('Ovara runtime trust policy');
  });

  it('function has correct parameters schema', () => {
    const guard = ovaraGuard();
    const fn = guard.function as { parameters: { type: string; properties: object; required: string[] } };
    expect(fn.parameters.type).toBe('object');
    expect(fn.parameters.properties).toHaveProperty('action');
    expect(fn.parameters.properties).toHaveProperty('resource');
    expect(fn.parameters.properties).toHaveProperty('environment');
    expect(fn.parameters.required).toContain('action');
    expect(fn.parameters.required).toContain('resource');
  });

  it('environment is limited to local, staging, production', () => {
    const guard = ovaraGuard();
    const fn = guard.function as { parameters: { properties: { environment: { enum: string[] } } } };
    expect(fn.parameters.properties.environment.enum).toEqual(['local', 'staging', 'production']);
  });
});

describe('handleOvaraToolCall', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('returns decision result as JSON string', async () => {
    const result = await handleOvaraToolCall({
      action: 'shell',
      resource: 'shell:ls',
      environment: 'local',
    });
    const parsed = JSON.parse(result);
    expect(parsed.decision).toBe('allow');
  });

  it('uses local as default environment', async () => {
    const result = await handleOvaraToolCall({
      action: 'shell',
      resource: 'shell:echo hello',
    });
    const parsed = JSON.parse(result);
    expect(parsed.decision).toBe('allow');
  });

  it('passes action and resource correctly', async () => {
    const result = await handleOvaraToolCall({
      action: 'git.push',
      resource: 'git:origin/main',
      environment: 'staging',
    });
    const parsed = JSON.parse(result);
    expect(parsed.decision).toBe('allow');
  });

  it('returns valid JSON string', async () => {
    const result = await handleOvaraToolCall({
      action: 'exec',
      resource: 'exec:ls',
    });
    expect(() => JSON.parse(result)).not.toThrow();
  });
});