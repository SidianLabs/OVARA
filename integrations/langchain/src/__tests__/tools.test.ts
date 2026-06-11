import { describe, it, expect, beforeEach, vi } from 'vitest';
import { OvaraCheckTool, OvaraStatusTool, OvaraReceiptsTool } from '../tools';

globalThis.fetch = vi.fn() as unknown as typeof fetch;

function mockFetch(json: unknown, ok = true) {
  return (globalThis.fetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
    ok,
    status: ok ? 200 : 500,
    json: () => Promise.resolve(json),
  });
}

describe('OvaraCheckTool', () => {
  beforeEach(() => {
    (globalThis.fetch as ReturnType<typeof vi.fn>).mockClear();
  });

  it('has correct name and description', () => {
    expect(OvaraCheckTool.name).toBe('ovara_check_action');
    expect(OvaraCheckTool.description).toContain('Ovara runtime trust policy');
  });

  it('has schema with action and resource fields', () => {
    const schema = OvaraCheckTool.schema as { properties: { action: object; resource: object; environment: object } };
    expect(schema.properties).toHaveProperty('action');
    expect(schema.properties).toHaveProperty('resource');
    expect(schema.properties).toHaveProperty('environment');
  });

  it('calls gateway with correct path and body', async () => {
    mockFetch({ decision: 'allow', request_id: 'req-001' });

    await OvaraCheckTool._call({ action: 'shell', resource: 'shell:ls', environment: 'local' });

    const call = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(call[0]).toBe('http://localhost:8080/v1/runtime/check');
    const body = JSON.parse(call[1].body as string);
    expect(body.action_type).toBe('shell');
    expect(body.resource).toBe('shell:ls');
    expect(body.environment).toBe('local');
  });

  it('defaults environment to local', async () => {
    mockFetch({ decision: 'allow' });

    await OvaraCheckTool._call({ action: 'shell', resource: 'shell:ls' });

    const call = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[0];
    const body = JSON.parse(call[1].body as string);
    expect(body.environment).toBe('local');
  });

  it('returns JSON string result', async () => {
    mockFetch({ decision: 'allow', trust_score: 0.95 });

    const result = await OvaraCheckTool._call({ action: 'shell', resource: 'shell:ls' });

    expect(() => JSON.parse(result)).not.toThrow();
    const parsed = JSON.parse(result);
    expect(parsed.decision).toBe('allow');
  });
});

describe('OvaraStatusTool', () => {
  beforeEach(() => {
    (globalThis.fetch as ReturnType<typeof vi.fn>).mockClear();
  });

  it('has correct name and description', () => {
    expect(OvaraStatusTool.name).toBe('ovara_gateway_status');
    expect(OvaraStatusTool.description).toContain('health and status');
  });

  it('has empty schema', () => {
    const schema = OvaraStatusTool.schema as { type: string; properties: object };
    expect(schema.type).toBe('object');
    expect(schema.properties).toEqual({});
  });

  it('calls gateway status endpoint', async () => {
    mockFetch({ gateway_id: 'gw-001', status: 'healthy' });

    await OvaraStatusTool._call({});

    const call = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(call[0]).toBe('http://localhost:8080/v1/runtime/status');
    expect(call[1].method).toBe('GET');
  });

  it('returns JSON string', async () => {
    mockFetch({ gateway_id: 'gw-001', status: 'healthy' });

    const result = await OvaraStatusTool._call({});

    const parsed = JSON.parse(result);
    expect(parsed.gateway_id).toBe('gw-001');
  });
});

describe('OvaraReceiptsTool', () => {
  beforeEach(() => {
    (globalThis.fetch as ReturnType<typeof vi.fn>).mockClear();
  });

  it('has correct name and description', () => {
    expect(OvaraReceiptsTool.name).toBe('ovara_list_receipts');
    expect(OvaraReceiptsTool.description).toContain('execution receipts');
  });

  it('has schema with limit and offset', () => {
    const schema = OvaraReceiptsTool.schema as { properties: { limit: object; offset: object } };
    expect(schema.properties).toHaveProperty('limit');
    expect(schema.properties).toHaveProperty('offset');
  });

  it('calls receipts endpoint with default pagination', async () => {
    mockFetch([]);

    await OvaraReceiptsTool._call({});

    const call = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(call[0]).toContain('/v1/runtime/receipts?limit=20&offset=0');
  });

  it('uses custom limit and offset', async () => {
    mockFetch([]);

    await OvaraReceiptsTool._call({ limit: 50, offset: 10 });

    const call = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(call[0]).toContain('limit=50');
    expect(call[0]).toContain('offset=10');
  });

  it('returns JSON string', async () => {
    mockFetch([{ receipt_id: 'rcpt-001', decision: 'allow' }]);

    const result = await OvaraReceiptsTool._call({ limit: 10 });

    const parsed = JSON.parse(result);
    expect(parsed).toHaveLength(1);
  });
});

describe('ToolResult interface compliance', () => {
  it('all tools have name, description, schema, and _call', () => {
    const tools = [OvaraCheckTool, OvaraStatusTool, OvaraReceiptsTool];
    for (const tool of tools) {
      expect(typeof tool.name).toBe('string');
      expect(typeof tool.description).toBe('string');
      expect(typeof tool.schema).toBe('object');
      expect(typeof tool._call).toBe('function');
    }
  });

  it('all tools return JSON-serializable strings', async () => {
    mockFetch({ decision: 'allow' });
    const result1 = await OvaraCheckTool._call({ action: 'shell', resource: 'shell:ls' });
    expect(() => JSON.parse(result1)).not.toThrow();

    mockFetch({ status: 'ok' });
    const result2 = await OvaraStatusTool._call({});
    expect(() => JSON.parse(result2)).not.toThrow();

    mockFetch([]);
    const result3 = await OvaraReceiptsTool._call({});
    expect(() => JSON.parse(result3)).not.toThrow();
  });
});