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
      expect((c as unknown as { baseUrl: string }).baseUrl).toBe('http://localhost:3000/v1');
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
    it('calls control-plane /health without /v1 prefix', async () => {
      mockFetch({ status: 'ok', timestamp: '2026-06-11T10:00:00Z' });

      const result = await client.health();

      expect(global.fetch).toHaveBeenCalledWith('http://localhost:9090/health');
      expect(result.status).toBe('ok');
    });

    it('throws on non-ok response', async () => {
      (global.fetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
        ok: false,
        status: 503,
        statusText: 'Service Unavailable',
        json: () => Promise.resolve({}),
      });

      await expect(client.health()).rejects.toThrow('API error: 503');
    });
  });

  describe('listGateways', () => {
    it('maps control-plane gateway rows to view models', async () => {
      const now = Date.now();
      mockFetch([
        { id: 'uuid-1', name: 'gw-prod-01', region: 'us-east-1', status: 'online',
          lastHeartbeat: new Date(now - 10_000).toISOString(), metadata: { version: 'v1.0.0', decisions: 150 } },
        { id: 'uuid-2', name: 'gw-stage-01', region: 'eu-west-1', status: 'enrolling',
          lastHeartbeat: null, metadata: {} },
        { id: 'uuid-3', name: 'gw-dead-01', region: 'us-west-2', status: 'offline',
          lastHeartbeat: new Date(now - 3600_000).toISOString(), metadata: null },
      ]);

      const result = await client.listGateways();

      expect(result).toHaveLength(3);
      expect(result[0]).toMatchObject({ name: 'gw-prod-01', status: 'healthy', version: 'v1.0.0', decisions: 150 });
      expect(result[1].status).toBe('degraded');
      expect(result[1].lastHeartbeat).toBe('—');
      expect(result[2].status).toBe('unhealthy');
      expect(result[2].decisions).toBeNull();
    });
  });

  describe('listPolicies', () => {
    it('maps rules array to count and formats updatedAt', async () => {
      mockFetch([
        { id: 'pol-001', name: 'strict-local', rules: [{ a: 1 }, { a: 2 }], status: 'published', updatedAt: new Date().toISOString() },
      ]);

      const result = await client.listPolicies();

      expect(result).toHaveLength(1);
      expect(result[0].name).toBe('strict-local');
      expect(result[0].rules).toBe(2);
      expect(result[0].lastModified).toContain('ago');
    });
  });

  describe('queryAuditLog', () => {
    it('builds limit query and maps rows', async () => {
      mockFetch([
        { id: 'a1', actor: 'apikey:k1', action: 'policy.publish', resource: 'policy', resourceId: 'pol-1', createdAt: '2026-06-11T10:00:00Z' },
      ]);

      const result = await client.queryAuditLog(50);

      const call = (global.fetch as ReturnType<typeof vi.fn>).mock.calls[0];
      expect(call[0]).toBe('http://localhost:9090/v1/audit?limit=50');
      expect(result[0]).toMatchObject({ actor: 'apikey:k1', action: 'policy.publish', resourceId: 'pol-1' });
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

  describe('listApprovals', () => {
    it('flattens per-gateway approvals and collects gateway errors', async () => {
      mockFetch({
        gateways: [
          {
            gatewayId: 'gw-1',
            gatewayName: 'prod-01',
            approvals: [
              {
                approval_id: 'ap_1',
                decision_id: 'dec_1',
                action_type: 'shell.exec',
                resource: 'shell:x',
                environment: 'production',
                status: 'pending',
                created_at: '2026-01-01T00:00:00Z',
                agent_id: 'agent-a',
                trust_score: 0.4,
                anomaly_codes: ['new_resource'],
              },
            ],
            error: null,
          },
          { gatewayId: 'gw-2', gatewayName: 'staging-01', approvals: [], error: 'unreachable' },
        ],
      });

      const res = await client.listApprovals();

      expect(res.approvals).toHaveLength(1);
      expect(res.approvals[0]).toMatchObject({
        approvalId: 'ap_1', actionType: 'shell.exec', status: 'pending',
        gatewayId: 'gw-1', gatewayName: 'prod-01', trustScore: 0.4,
      });
      expect(res.gatewayErrors).toEqual([{ gatewayName: 'staging-01', error: 'unreachable' }]);
    });
  });

  describe('resolveApproval', () => {
    it('posts to the per-gateway resolution path', async () => {
      mockFetch({ status: 'approved' });

      await client.resolveApproval('gw-1', 'ap_1', 'approve');

      expect(global.fetch).toHaveBeenCalledWith(
        'http://localhost:9090/v1/approvals/gw-1/ap_1/approve',
        expect.objectContaining({ method: 'POST' })
      );
    });
  });

  describe('apiKey passthrough', () => {
    it('no auth header when apiKey is not set', async () => {
      const c = new OvaraClient('http://localhost:9090/v1');
      mockFetch([]);

      await c.listGateways();

      const call = (global.fetch as ReturnType<typeof vi.fn>).mock.calls[0];
      const headers = call[1].headers as Record<string, string>;
      expect(headers['Authorization']).toBeUndefined();
    });

    it('bearer token sent with apiKey', async () => {
      mockFetch([]);

      await client.listGateways();

      const call = (global.fetch as ReturnType<typeof vi.fn>).mock.calls[0];
      const headers = call[1].headers as Record<string, string>;
      expect(headers['Authorization']).toBe('Bearer test-key');
    });
  });
});
