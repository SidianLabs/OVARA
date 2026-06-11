import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { OvaraClient } from '../api-client';

global.fetch = vi.fn() as unknown as typeof fetch;

function mockFetch(response: unknown, ok = true) {
  return (global.fetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
    ok,
    status: ok ? 200 : 500,
    statusText: ok ? 'OK' : 'Internal Server Error',
    json: () => Promise.resolve(response),
  });
}

describe('OvaraClient', () => {
  let client: OvaraClient;

  beforeEach(() => {
    client = new OvaraClient('http://localhost:9090/v1', 'test-key');
    (global.fetch as ReturnType<typeof vi.fn>).mockClear();
  });

  afterEach(() => {
    (global.fetch as ReturnType<typeof vi.fn>).mockReset();
  });

  describe('constructor', () => {
    it('uses provided baseUrl', () => {
      const c = new OvaraClient('http://custom:9000/api');
      expect((c as unknown as { baseUrl: string }).baseUrl).toBe('http://custom:9000/api');
    });

    it('uses default baseUrl when not provided', () => {
      const c = new OvaraClient();
      expect((c as unknown as { baseUrl: string }).baseUrl).toBe('http://localhost:9090/v1');
    });

    it('stores apiKey', () => {
      const c = new OvaraClient('http://localhost:9090', 'my-secret');
      expect((c as unknown as { apiKey: string | undefined }).apiKey).toBe('my-secret');
    });

    it('apiKey is undefined when not provided', () => {
      const c = new OvaraClient('http://localhost:9090');
      expect((c as unknown as { apiKey: string | undefined }).apiKey).toBeUndefined();
    });
  });

  describe('health', () => {
    it('calls correct endpoint', async () => {
      mockFetch({ status: 'healthy', version: '0.8.0' });

      const result = await client.health();

      expect(global.fetch).toHaveBeenCalledWith(
        'http://localhost:9090/v1/runtime/health',
        expect.any(Object)
      );
      expect(result.status).toBe('healthy');
    });

    it('includes authorization header', async () => {
      mockFetch({ status: 'ok', version: '0.8.0' });

      await client.health();

      const call = (global.fetch as ReturnType<typeof vi.fn>).mock.calls[0];
      const headers = call[1].headers as Record<string, string>;
      expect(headers['Authorization']).toBe('Bearer test-key');
    });

    it('throws on non-ok response', async () => {
      (global.fetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
        ok: false,
        status: 401,
        statusText: 'Unauthorized',
        json: () => Promise.resolve({}),
      });

      await expect(client.health()).rejects.toThrow('API error: 401 Unauthorized');
    });
  });

  describe('listGateways', () => {
    it('returns gateway list', async () => {
      const gateways = [
        { id: 'gw-001', region: 'us-east', status: 'healthy', version: '0.8.0', decisions: 150, lastHeartbeat: '2026-06-11T10:00:00Z' },
        { id: 'gw-002', region: 'eu-west', status: 'degraded', version: '0.8.0', decisions: 42, lastHeartbeat: '2026-06-11T09:55:00Z' },
      ];
      mockFetch(gateways);

      const result = await client.listGateways();

      expect(result).toHaveLength(2);
      expect(result[0].id).toBe('gw-001');
      expect(result[1].status).toBe('degraded');
    });
  });

  describe('getGateway', () => {
    it('builds correct path with id', async () => {
      mockFetch({ id: 'gw-abc', region: 'us-east', status: 'healthy', version: '0.8.0', decisions: 100, lastHeartbeat: '2026-06-11T10:00:00Z' });

      await client.getGateway('gw-abc');

      expect(global.fetch).toHaveBeenCalledWith(
        'http://localhost:9090/v1/runtime/gateways/gw-abc',
        expect.any(Object)
      );
    });
  });

  describe('listPolicies', () => {
    it('returns policy list', async () => {
      const policies = [
        { id: 'pol-001', name: 'strict-local', rules: 12, status: 'active', lastModified: '2026-06-01T00:00:00Z' },
      ];
      mockFetch(policies);

      const result = await client.listPolicies();

      expect(result).toHaveLength(1);
      expect(result[0].name).toBe('strict-local');
    });
  });

  describe('queryAuditLog', () => {
    it('builds query string with all params', async () => {
      mockFetch([]);

      await client.queryAuditLog({ action: 'shell', decision: 'allow', limit: 50 });

      const call = (global.fetch as ReturnType<typeof vi.fn>).mock.calls[0];
      const url = call[0];
      expect(url).toContain('/v1/audit?action=shell&decision=allow&limit=50');
    });

    it('handles no params', async () => {
      mockFetch([]);

      await client.queryAuditLog();

      const call = (global.fetch as ReturnType<typeof vi.fn>).mock.calls[0];
      const url = call[0];
      expect(url).toBe('http://localhost:9090/v1/audit');
    });

    it('handles partial params', async () => {
      mockFetch([]);

      await client.queryAuditLog({ action: 'git.push' });

      const call = (global.fetch as ReturnType<typeof vi.fn>).mock.calls[0];
      const url = call[0];
      expect(url).toContain('action=git.push');
      expect(url).not.toContain('decision=');
    });
  });

  describe('listOrganizations', () => {
    it('calls correct endpoint', async () => {
      mockFetch([]);

      await client.listOrganizations();

      expect(global.fetch).toHaveBeenCalledWith(
        'http://localhost:9090/v1/organizations',
        expect.any(Object)
      );
    });
  });

  describe('getMetrics', () => {
    it('returns dashboard metrics', async () => {
      const metrics = {
        decisionsPerSec: 12.5,
        avgLatencyMs: 45,
        errorRate: 0.02,
        activeGateways: 3,
        trustScores: [0.95, 0.88, 0.72],
      };
      mockFetch(metrics);

      const result = await client.getMetrics();

      expect(result.decisionsPerSec).toBe(12.5);
      expect(result.trustScores).toHaveLength(3);
    });
  });

  describe('simulateDecision', () => {
    it('posts correct payload', async () => {
      mockFetch({ decision: 'allow', reasons: ['local policy'], trustScore: 0.95 });

      const result = await client.simulateDecision('shell', 'shell:ls', 'agent-001');

      const call = (global.fetch as ReturnType<typeof vi.fn>).mock.calls[0];
      const body = JSON.parse(call[1].body as string);
      expect(body.action).toBe('shell');
      expect(body.resource).toBe('shell:ls');
      expect(body.agent_identity).toBe('agent-001');
      expect(result.decision).toBe('allow');
    });
  });

  describe('apiKey passthrough', () => {
    it('no auth header when apiKey is not set', async () => {
      const c = new OvaraClient('http://localhost:9090');
      mockFetch({ status: 'ok', version: '0.8.0' });

      await c.health();

      const call = (global.fetch as ReturnType<typeof vi.fn>).mock.calls[0];
      const headers = call[1].headers as Record<string, string>;
      expect(headers['Authorization']).toBeUndefined();
    });

    it('bearer token sent with apiKey', async () => {
      mockFetch({ status: 'ok', version: '0.8.0' });

      await client.health();

      const call = (global.fetch as ReturnType<typeof vi.fn>).mock.calls[0];
      const headers = call[1].headers as Record<string, string>;
      expect(headers['Authorization']).toBe('Bearer test-key');
    });
  });
});